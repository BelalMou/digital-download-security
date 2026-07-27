import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleStripeWebhook, type WebhookDeps } from "../src/webhook";

const SESSION_ID = "cs_test_a1b2c3";
const SECRET = "whsec_test";

const req = (opts: { signed?: boolean; body?: string } = {}) =>
  new Request("https://example.com/api/webhooks/stripe", {
    method: "POST",
    headers: opts.signed === false ? {} : { "stripe-signature": "t=1,v1=deadbeef" },
    body: opts.body ?? JSON.stringify({ id: "evt_1" }),
  });

const completed = (object: Record<string, unknown> = {}) => ({
  type: "checkout.session.completed",
  data: {
    object: {
      id: SESSION_ID,
      amount_total: 4900,
      payment_intent: "pi_123",
      metadata: { assetId: "asset-1", buyerId: "buyer-1" },
      ...object,
    },
  },
});

let deps: WebhookDeps;
let constructEvent: ReturnType<typeof vi.fn>;
let findPurchaseBySessionId: ReturnType<typeof vi.fn>;
let createPurchase: ReturnType<typeof vi.fn>;
let revokeByPaymentIntent: ReturnType<typeof vi.fn>;

beforeEach(() => {
  constructEvent = vi.fn();
  findPurchaseBySessionId = vi.fn().mockResolvedValue(null);
  createPurchase = vi.fn().mockResolvedValue({});
  revokeByPaymentIntent = vi.fn().mockResolvedValue(1);
  deps = {
    constructEvent,
    secret: SECRET,
    db: { findPurchaseBySessionId, createPurchase, revokeByPaymentIntent },
  } as unknown as WebhookDeps;
});

describe("leak #2 — the signature you forgot to verify", () => {
  it("rejects a payload with no signature, without calling Stripe", async () => {
    const res = await handleStripeWebhook(req({ signed: false }), deps);
    expect(res.status).toBe(400);
    expect(constructEvent).not.toHaveBeenCalled();
    expect(createPurchase).not.toHaveBeenCalled();
  });

  it("rejects a forged payload and grants nothing", async () => {
    constructEvent.mockImplementation(() => {
      throw new Error("No signatures found matching the expected signature");
    });
    const res = await handleStripeWebhook(req(), deps);
    expect(res.status).toBe(400);
    expect(createPurchase).not.toHaveBeenCalled();
  });

  it("verifies against the raw body, not a re-serialised object", async () => {
    const body = '{"id":"evt_1","spacing":  "preserved"}';
    constructEvent.mockReturnValue(completed());
    await handleStripeWebhook(req({ body }), deps);

    const [rawBody, signature, secret] = constructEvent.mock.calls[0];
    expect(rawBody).toBe(body); // byte-for-byte, whitespace included
    expect(signature).toBe("t=1,v1=deadbeef");
    expect(secret).toBe(SECRET);
  });
});

describe("leak #1 — the webhook that grants two purchases", () => {
  it("grants once on first delivery", async () => {
    constructEvent.mockReturnValue(completed());
    const res = await handleStripeWebhook(req(), deps);

    expect(res.status).toBe(200);
    expect(createPurchase).toHaveBeenCalledTimes(1);
    expect(createPurchase.mock.calls[0][0]).toMatchObject({
      stripePaymentId: SESSION_ID,
      stripePaymentIntentId: "pi_123",
      amount: 49,
    });
  });

  it("does not double-grant when Stripe redelivers", async () => {
    constructEvent.mockReturnValue(completed());
    await handleStripeWebhook(req(), deps);

    findPurchaseBySessionId.mockResolvedValue({ id: "p1" }); // now exists
    const second = await handleStripeWebhook(req(), deps);

    expect(second.status).toBe(200); // ack, so Stripe stops retrying
    expect(createPurchase).toHaveBeenCalledTimes(1); // still one grant
  });

  it("does not let a failing side effect fail the webhook", async () => {
    constructEvent.mockReturnValue(completed());
    const onFulfilled = vi.fn().mockRejectedValue(new Error("SMTP down"));
    const res = await handleStripeWebhook(req(), { ...deps, onFulfilled });

    expect(res.status).toBe(200); // a retry would re-deliver an already-fulfilled sale
    expect(createPurchase).toHaveBeenCalledTimes(1);
  });

  it("refuses to fulfil without attribution metadata", async () => {
    constructEvent.mockReturnValue(completed({ metadata: {} }));
    const res = await handleStripeWebhook(req(), deps);
    expect(res.status).toBe(400);
    expect(createPurchase).not.toHaveBeenCalled();
  });

  it("ignores unrelated event types", async () => {
    constructEvent.mockReturnValue({
      type: "payment_intent.created",
      data: { object: { id: "pi_1" } },
    });
    const res = await handleStripeWebhook(req(), deps);
    expect(res.status).toBe(200);
    expect(createPurchase).not.toHaveBeenCalled();
  });
});

describe("bonus — the price you took from the browser", () => {
  it("takes the amount from Stripe even when metadata says otherwise", async () => {
    constructEvent.mockReturnValue(
      completed({
        amount_total: 4900,
        metadata: { assetId: "asset-1", buyerId: "buyer-1", amount: "0.01", price: "0.01" },
      })
    );
    await handleStripeWebhook(req(), deps);
    expect(createPurchase.mock.calls[0][0].amount).toBe(49);
  });
});

describe("leak #4 — the refund that doesn't revoke", () => {
  const charge = (over: Record<string, unknown> = {}) => ({
    type: "charge.refunded",
    data: {
      object: { id: "ch_1", payment_intent: "pi_123", amount: 4900, amount_refunded: 4900, ...over },
    },
  });

  it("revokes on a full refund", async () => {
    constructEvent.mockReturnValue(charge());
    const res = await handleStripeWebhook(req(), deps);
    expect(res.status).toBe(200);
    expect(revokeByPaymentIntent).toHaveBeenCalledWith("pi_123");
  });

  it("does NOT revoke on a partial refund", async () => {
    constructEvent.mockReturnValue(charge({ amount_refunded: 1000 }));
    await handleStripeWebhook(req(), deps);
    expect(revokeByPaymentIntent).not.toHaveBeenCalled();
  });

  it("revokes on a dispute regardless of amount", async () => {
    constructEvent.mockReturnValue({
      type: "charge.dispute.created",
      data: { object: { id: "dp_1", payment_intent: "pi_123" } },
    });
    await handleStripeWebhook(req(), deps);
    expect(revokeByPaymentIntent).toHaveBeenCalledWith("pi_123");
  });

  it("handles an expanded payment_intent object as well as an id string", async () => {
    constructEvent.mockReturnValue(charge({ payment_intent: { id: "pi_123" } }));
    await handleStripeWebhook(req(), deps);
    expect(revokeByPaymentIntent).toHaveBeenCalledWith("pi_123");
  });

  it("acks without retrying when there is no payment intent to act on", async () => {
    constructEvent.mockReturnValue(charge({ payment_intent: null }));
    const res = await handleStripeWebhook(req(), deps);
    expect(res.status).toBe(200);
    expect(revokeByPaymentIntent).not.toHaveBeenCalled();
  });
});
