#!/usr/bin/env node
/**
 * stripe-sig — verify, sign and send Stripe webhook events from the terminal.
 *
 * Deliberately offline: no Stripe login, no tunnel, no account. Useful when you
 * want a specific payload (a partial refund, a redelivery, hostile metadata)
 * rather than whatever `stripe trigger` happens to emit.
 *
 *   npx github:BelalMou/digital-download-security verify --secret whsec_... --file body.json --sig 't=..,v1=..'
 *   npx github:BelalMou/digital-download-security sign   --secret whsec_... --event checkout.session.completed
 *   npx github:BelalMou/digital-download-security send   --secret whsec_... --event charge.refunded --url http://localhost:3000/api/webhooks/stripe
 */
import crypto from "node:crypto";
import fs from "node:fs";

const TOLERANCE = 300; // Stripe's default replay window, in seconds

// ── event fixtures ──────────────────────────────────────────────────────────
const rid = (p) => p + Math.random().toString(36).slice(2, 12);
const now = () => Math.floor(Date.now() / 1000);

const EVENTS = {
  "checkout.session.completed": (o = {}) => ({
    id: rid("evt_test_"), object: "event", type: "checkout.session.completed", created: now(),
    data: { object: {
      id: rid("cs_test_"), object: "checkout.session", amount_total: 3900, currency: "usd",
      payment_intent: rid("pi_test_"), payment_status: "paid", status: "complete",
      customer_details: { email: "buyer@example.com" },
      metadata: { assetId: "asset_123", buyerId: "user_456" }, ...o,
    }},
  }),
  "charge.refunded": (o = {}) => ({
    id: rid("evt_test_"), object: "event", type: "charge.refunded", created: now(),
    data: { object: {
      id: rid("ch_test_"), object: "charge", amount: 3900, amount_refunded: 3900,
      currency: "usd", payment_intent: rid("pi_test_"), refunded: true, paid: true, ...o,
    }},
  }),
  "charge.dispute.created": (o = {}) => ({
    id: rid("evt_test_"), object: "event", type: "charge.dispute.created", created: now(),
    data: { object: {
      id: rid("dp_test_"), object: "dispute", amount: 3900, currency: "usd",
      charge: rid("ch_test_"), payment_intent: rid("pi_test_"),
      reason: "fraudulent", status: "warning_needs_response", ...o,
    }},
  }),
  "payment_intent.succeeded": (o = {}) => ({
    id: rid("evt_test_"), object: "event", type: "payment_intent.succeeded", created: now(),
    data: { object: {
      id: rid("pi_test_"), object: "payment_intent", amount: 3900,
      amount_received: 3900, currency: "usd", status: "succeeded", ...o,
    }},
  }),
  "invoice.payment_failed": (o = {}) => ({
    id: rid("evt_test_"), object: "event", type: "invoice.payment_failed", created: now(),
    data: { object: {
      id: rid("in_test_"), object: "invoice", amount_due: 3900, currency: "usd",
      attempt_count: 2, status: "open", customer_email: "buyer@example.com", ...o,
    }},
  }),
};

// ── core ────────────────────────────────────────────────────────────────────
export function hmac(secret, timestamp, payload) {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
}

export function parseSigHeader(header) {
  const out = { t: null, v1: [] };
  for (const part of String(header).trim().split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim(), v = part.slice(i + 1).trim();
    if (k === "t") out.t = v;
    else if (k === "v1") out.v1.push(v);
  }
  return out;
}

/** Returns { ok, reason, expected, age }. Never throws on bad input. */
export function verify(payload, header, secret) {
  const { t, v1 } = parseSigHeader(header);
  if (!t) return { ok: false, reason: "no t= timestamp in the signature header" };
  if (!v1.length) return { ok: false, reason: "no v1= signature in the header" };

  const expected = hmac(secret, t, payload);
  // Constant-time compare, since this is the same check a server would do.
  const match = v1.some((sig) => {
    const a = Buffer.from(sig), b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
  const age = now() - Number(t);

  if (!match) {
    return { ok: false, expected, age,
      reason: "signature does not match — most often the body is not byte-identical " +
              "(re-serialised JSON), or the secret belongs to a different endpoint" };
  }
  if (Math.abs(age) > TOLERANCE) {
    return { ok: false, expected, age,
      reason: `signature is valid but the timestamp is ${age}s old, outside Stripe's ` +
              `${TOLERANCE}s replay window — constructEvent would still reject it` };
  }
  return { ok: true, expected, age };
}

export function sign(payload, secret, timestamp = now()) {
  return { header: `t=${timestamp},v1=${hmac(secret, timestamp, payload)}`, timestamp };
}

// ── cli ─────────────────────────────────────────────────────────────────────
function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) out[a.slice(2)] = argv[i + 1]?.startsWith("--") ? true : argv[++i];
    else out._.push(a);
  }
  return out;
}

const USAGE = `stripe-sig — verify, sign and send Stripe webhook events offline

  verify  --secret whsec_...  --sig 't=..,v1=..'  [--file body.json | --body '{...}']
  sign    --secret whsec_...  [--event <type> | --file body.json | --body '{...}']
  send    --secret whsec_...  --url <endpoint>    [--event <type> | --file body.json]
          [--times N]   send the SAME signed request N times, to test idempotency

  events: ${Object.keys(EVENTS).join(", ")}

Nothing is uploaded anywhere. The signing secret never leaves this process.
More: https://belalmou.github.io/digital-download-security/`;

function body(a) {
  if (a.file) return fs.readFileSync(a.file, "utf8").trim();
  if (a.body) return a.body;
  const type = a.event || "checkout.session.completed";
  const make = EVENTS[type];
  if (!make) { console.error(`unknown event: ${type}\nknown: ${Object.keys(EVENTS).join(", ")}`); process.exit(2); }
  // Minified on purpose: the bytes we sign must be the bytes we send.
  return JSON.stringify(make());
}

function needSecret(a) {
  if (!a.secret) { console.error("missing --secret (the whsec_... signing secret)"); process.exit(2); }
  if (/^(sk|rk)_/.test(a.secret)) {
    console.error("that looks like an API key, not a signing secret — signing secrets start with whsec_");
    process.exit(2);
  }
  return a.secret;
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const a = args(argv.slice(1));

  if (!cmd || cmd === "help" || a.help) { console.log(USAGE); return; }

  if (cmd === "verify") {
    const secret = needSecret(a);
    if (!a.sig) { console.error("missing --sig (the Stripe-Signature header value)"); process.exit(2); }
    const r = verify(body(a), a.sig, secret);
    if (r.ok) { console.log(`✓ signature valid (timestamp ${r.age}s old)`); return; }
    console.error(`✗ ${r.reason}`);
    if (r.expected) console.error(`  expected v1=${r.expected}`);
    process.exit(1);
  }

  if (cmd === "sign") {
    const secret = needSecret(a);
    const raw = body(a);
    const { header } = sign(raw, secret);
    console.log(header);
    if (!a.quiet) console.error(`\n# body (${raw.length} bytes) — sign and send these exact bytes\n${raw}`);
    return;
  }

  if (cmd === "send") {
    const secret = needSecret(a);
    if (!a.url) { console.error("missing --url (your webhook endpoint)"); process.exit(2); }
    const raw = body(a);
    const times = Math.max(1, Number(a.times) || 1);
    // The same signed request each time: that is what a Stripe redelivery is.
    const { header } = sign(raw, secret);
    for (let i = 1; i <= times; i++) {
      try {
        const res = await fetch(a.url, {
          method: "POST",
          headers: { "content-type": "application/json", "stripe-signature": header },
          body: raw,
        });
        const text = (await res.text()).slice(0, 120).replace(/\s+/g, " ");
        console.log(`${i}/${times}  ${res.status} ${res.statusText}  ${text}`);
      } catch (e) {
        console.error(`${i}/${times}  request failed: ${e.message}`);
        process.exit(1);
      }
    }
    if (times > 1) {
      console.error(`\n# sent the identical event ${times}×. A correct handler grants once and ` +
                    `returns 200 every time.\n# https://belalmou.github.io/digital-download-security/stripe-webhook-fired-twice.html`);
    }
    return;
  }

  console.error(`unknown command: ${cmd}\n\n${USAGE}`);
  process.exit(2);
}

// Only run the CLI when executed directly, so the functions stay importable in tests.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}
