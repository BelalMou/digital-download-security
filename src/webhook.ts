/**
 * Reference Stripe webhook handler for a digital-download store.
 *
 * Framework-agnostic on purpose: it takes a standard `Request` and its
 * dependencies, so it drops into Next.js route handlers, Remix, Hono, Express
 * (with a raw-body parser), or a test — unchanged.
 *
 * The two properties worth copying:
 *   1. Signature verification against the RAW body, failing closed.
 *   2. Fulfilment that is idempotent, because Stripe delivers at least once.
 */

export type PurchaseRecord = {
  stripePaymentId: string;
  stripePaymentIntentId: string | null;
  amount: number;
  assetId: string;
  buyerId: string;
};

export interface WebhookDeps {
  /** Usually `stripe.webhooks.constructEvent`. Must throw on a bad signature. */
  constructEvent: (rawBody: string, signature: string, secret: string) => StripeEventish;
  secret: string;
  db: {
    findPurchaseBySessionId: (sessionId: string) => Promise<unknown | null>;
    createPurchase: (data: PurchaseRecord) => Promise<unknown>;
    /** Returns how many rows were revoked. */
    revokeByPaymentIntent: (paymentIntentId: string) => Promise<number>;
  };
  /** Optional side effects; failures here must never fail the webhook. */
  onFulfilled?: (purchase: PurchaseRecord) => Promise<void>;
}

type StripeEventish = {
  type: string;
  data: { object: Record<string, unknown> };
};

const ok = () => new Response("OK", { status: 200 });
const bad = () => new Response("Bad request", { status: 400 });

/** Stripe sometimes gives an id string, sometimes an expanded object. */
function idOf(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (value && typeof value === "object" && "id" in value) {
    const id = (value as { id?: unknown }).id;
    return typeof id === "string" ? id : null;
  }
  return null;
}

export async function handleStripeWebhook(
  request: Request,
  deps: WebhookDeps
): Promise<Response> {
  // Read the body as TEXT. Parsing and re-serialising changes the bytes, the
  // signature stops matching, and people then "fix" it by skipping verification.
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");
  if (!signature) return bad();

  let event: StripeEventish;
  try {
    event = deps.constructEvent(rawBody, signature, deps.secret);
  } catch {
    // Fail closed. This endpoint grants entitlements; an unverified caller gets nothing.
    return bad();
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const sessionId = String(session.id);
      const metadata = (session.metadata ?? {}) as Record<string, string>;
      const { assetId, buyerId } = metadata;

      // No metadata means we cannot attribute the sale. Refusing beats guessing.
      if (!assetId || !buyerId) return bad();

      // Fast path. The unique index on stripePaymentId is what actually makes this
      // safe under a race — two simultaneous deliveries both pass this check, and
      // the database refuses the second insert.
      const existing = await deps.db.findPurchaseBySessionId(sessionId);
      if (!existing) {
        const purchase: PurchaseRecord = {
          stripePaymentId: sessionId,
          // Refund and dispute events reference the PaymentIntent, never the
          // session. Without this column a refund cannot be mapped to a purchase.
          stripePaymentIntentId: idOf(session.payment_intent),
          // The amount comes from Stripe, never from client-controlled metadata.
          amount: (Number(session.amount_total) || 0) / 100,
          assetId,
          buyerId,
        };
        await deps.db.createPurchase(purchase);
        // Email and analytics must not be able to fail the webhook: a thrown error
        // here would make Stripe retry a delivery we already fulfilled.
        deps.onFulfilled?.(purchase).catch(() => {});
      }
    }

    // Money going back out. Revoke access but keep the row — it is the financial
    // record the refund refers to.
    if (event.type === "charge.refunded" || event.type === "charge.dispute.created") {
      const object = event.data.object;
      const paymentIntentId = idOf(object.payment_intent);
      if (!paymentIntentId) return ok(); // nothing actionable; don't make Stripe retry

      // A partial refund leaves the buyer having paid for part of it, so it does not
      // revoke. A dispute always does.
      const isDispute = event.type === "charge.dispute.created";
      const fullyRefunded =
        Number(object.amount_refunded ?? 0) >= Number(object.amount ?? 0);

      if (isDispute || fullyRefunded) {
        await deps.db.revokeByPaymentIntent(paymentIntentId);
      }
    }
  } catch {
    // A real failure: 500 so Stripe retries, and idempotency makes the retry safe.
    return new Response("Internal server error", { status: 500 });
  }

  return ok();
}
