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
import path from "node:path";
import { fileURLToPath } from "node:url";

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


// ── providers ───────────────────────────────────────────────────────────────
/**
 * Every one of these is HMAC-SHA256, and every one differs in what gets signed
 * and how it's encoded. Getting that wrong is the single most common cause of
 * "signature verification failed" across all of them.
 */
export const PROVIDERS = {
  stripe: {
    header: "Stripe-Signature",
    // t=<unix>,v1=<hex> over "<t>.<body>"
    signed: (body, { t }) => `${t}.${body}`,
    encoding: "hex",
    format: (sig, { t }) => `t=${t},v1=${sig}`,
    extract: (h) => {
      const t = /(?:^|,)\s*t=(\d+)/.exec(h)?.[1];
      const sigs = [...String(h).matchAll(/v1=([a-f0-9]+)/g)].map((m) => m[1]);
      return { t, sigs };
    },
    tolerance: 300,
  },
  github: {
    header: "X-Hub-Signature-256",
    // sha256=<hex> over the raw body only — no timestamp
    signed: (body) => body,
    encoding: "hex",
    format: (sig) => `sha256=${sig}`,
    extract: (h) => ({ t: null, sigs: [String(h).replace(/^sha256=/, "").trim()] }),
    tolerance: null,
  },
  shopify: {
    header: "X-Shopify-Hmac-Sha256",
    // base64 of the raw body — no prefix, no timestamp
    signed: (body) => body,
    encoding: "base64",
    format: (sig) => sig,
    extract: (h) => ({ t: null, sigs: [String(h).trim()] }),
    tolerance: null,
  },
  slack: {
    header: "X-Slack-Signature",
    // v0=<hex> over "v0:<timestamp>:<body>", timestamp in X-Slack-Request-Timestamp
    signed: (body, { t }) => `v0:${t}:${body}`,
    encoding: "hex",
    format: (sig) => `v0=${sig}`,
    extract: (h) => ({ t: null, sigs: [String(h).replace(/^v0=/, "").trim()] }),
    tolerance: 300,
    needsTimestampHeader: "X-Slack-Request-Timestamp",
  },
};

function digest(secret, message, encoding) {
  return crypto.createHmac("sha256", secret).update(message).digest(encoding);
}

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


/** Provider-aware signing. Returns { header, value, timestamp }. */
export function signFor(provider, payload, secret, timestamp = now()) {
  const p = PROVIDERS[provider];
  if (!p) throw new Error(`unknown provider: ${provider}`);
  const sig = digest(secret, p.signed(payload, { t: timestamp }), p.encoding);
  return { header: p.header, value: p.format(sig, { t: timestamp }), timestamp };
}

/** Provider-aware verification. Returns { ok, reason, expected, age }. */
export function verifyFor(provider, payload, headerValue, secret, timestamp) {
  const p = PROVIDERS[provider];
  if (!p) return { ok: false, reason: `unknown provider: ${provider}` };
  const { t: parsedT, sigs } = p.extract(headerValue);
  const t = timestamp ?? parsedT;

  if (p.tolerance && !t) {
    return { ok: false, reason: `${provider} signatures cover a timestamp; supply it` +
      (p.needsTimestampHeader ? ` (the ${p.needsTimestampHeader} header)` : "") };
  }
  if (!sigs.length || !sigs[0]) return { ok: false, reason: "no signature found in the header" };

  const expected = digest(secret, p.signed(payload, { t }), p.encoding);
  const match = sigs.some((sig) => {
    const a = Buffer.from(sig), b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
  const age = t ? now() - Number(t) : 0;

  if (!match) {
    return { ok: false, expected, age,
      reason: "signature does not match — most often the body is not byte-identical " +
              "(re-serialised JSON), or the secret belongs to a different endpoint" };
  }
  if (p.tolerance && Math.abs(age) > p.tolerance) {
    return { ok: false, expected, age,
      reason: `signature is valid but the timestamp is ${age}s old, outside the ` +
              `${p.tolerance}s replay window` };
  }
  return { ok: true, expected, age };
}

export function sign(payload, secret, timestamp = now()) {
  return { header: `t=${timestamp},v1=${hmac(secret, timestamp, payload)}`, timestamp };
}


// ── audit ───────────────────────────────────────────────────────────────────
/**
 * Runs the adversarial cases against YOUR OWN endpoint and reports what it does.
 *
 * Every request is an ordinary webhook POST — nothing here is an attack, and it
 * needs your signing secret to be meaningful. Point it at an endpoint you control
 * (localhost or your own staging), not at somebody else's service.
 */
async function post(url, raw, header) {
  const headers = { "content-type": "application/json" };
  if (header) headers["stripe-signature"] = header;
  try {
    const res = await fetch(url, { method: "POST", headers, body: raw });
    return { status: res.status, body: (await res.text()).slice(0, 80).replace(/\s+/g, " ") };
  } catch (e) {
    return { status: 0, body: e.message };
  }
}

async function auditEndpoint(url, secret) {
  const raw = JSON.stringify(EVENTS["checkout.session.completed"]());
  const results = [];
  // status 0 means the request never landed. That is an unreachable endpoint, not a
  // security verdict — reporting it as "rejected" would be a dangerously flattering lie.
  const rejects = (s) => s >= 400 && s < 500;
  const unreachable = (s) => s === 0;

  const probe = await post(url, raw, sign(raw, secret).header);
  if (unreachable(probe.status)) {
    return [{ name: "Endpoint reachable", pass: false, fatal: true,
      detail: probe.body,
      why: "Nothing could be sent, so no check below would mean anything. " +
           "Is the server running and the URL right?" }];
  }

  // 1. no signature at all
  let r = await post(url, raw, null);
  results.push({ name: "Rejects a request with no signature header",
    pass: rejects(r.status), detail: `HTTP ${r.status}`,
    why: "Without this, anyone who finds the URL can grant themselves purchases." });

  // 2. forged signature
  r = await post(url, raw, `t=${now()},v1=${"0".repeat(64)}`);
  results.push({ name: "Rejects a forged signature",
    pass: rejects(r.status), detail: `HTTP ${r.status}`,
    why: "A wrong v1 must never fulfil. If this passes, verification is not happening." });

  // 3. valid signature, but body altered after signing
  const { header: goodHdr } = sign(raw, secret);
  r = await post(url, raw + " ", goodHdr);
  results.push({ name: "Rejects a body that changed after signing",
    pass: rejects(r.status), detail: `HTTP ${r.status}`,
    why: "Proves the signature is checked against the raw bytes received." });

  // 4. valid signature but stale timestamp
  const stale = sign(raw, secret, now() - 3600).header;
  r = await post(url, raw, stale);
  results.push({ name: "Rejects a replayed (stale) timestamp",
    pass: rejects(r.status), detail: `HTTP ${r.status}`,
    why: `Stripe enforces a ${TOLERANCE}s window. Accepting old events allows replay.`,
    soft: true });

  // 5. a genuine event should be accepted
  const fresh = sign(raw, secret).header;
  r = await post(url, raw, fresh);
  const accepted = r.status >= 200 && r.status < 300;
  results.push({ name: "Accepts a correctly signed event",
    pass: accepted, detail: `HTTP ${r.status} ${r.body}`,
    why: "If this fails, the secret or the raw-body handling is wrong." });

  // 6. redelivery — identical request twice
  if (accepted) {
    const again = await post(url, raw, fresh);
    results.push({ name: "Survives a redelivery (same event twice)",
      pass: again.status >= 200 && again.status < 300, detail: `HTTP ${again.status} ${again.body}`,
      why: "Stripe delivers at least once. A 500 here means Stripe will retry forever. " +
           "This cannot see your database — check that only ONE purchase was granted." });
  }

  return results;
}

// ── cli ─────────────────────────────────────────────────────────────────────
function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const next = argv[i + 1];
      // A trailing flag has no next arg. Without this check `--quiet` at the end of
      // the line parsed as undefined (falsy), so the flag silently did nothing.
      out[a.slice(2)] = next === undefined || next.startsWith("--") ? true : argv[++i];
    }
    else out._.push(a);
  }
  return out;
}

const USAGE = `stripe-sig — verify, sign and send Stripe webhook events offline

  verify  --secret whsec_...  --sig 't=..,v1=..'  [--file body.json | --body '{...}']
  sign    --secret whsec_...  [--event <type> | --file body.json | --body '{...}']
  send    --secret whsec_...  --url <endpoint>    [--event <type> | --file body.json]
          [--times N]   send the SAME signed request N times, to test idempotency
  audit   --secret whsec_...  --url <endpoint>
          run the adversarial cases against your OWN endpoint and score it

  events:    ${Object.keys(EVENTS).join(", ")}
  providers: ${Object.keys(PROVIDERS).join(", ")}   (--provider, default stripe)

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

function needSecret(a, provider) {
  if (!a.secret) { console.error("missing --secret (the signing secret)"); process.exit(2); }
  // Only Stripe uses whsec_/sk_ prefixes; don't nag GitHub or Shopify users.
  if ((!provider || provider === "stripe") && /^(sk|rk)_/.test(a.secret)) {
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
    const secret = needSecret(a, a.provider);
    if (!a.sig) { console.error("missing --sig (the signature header value)"); process.exit(2); }
    const prov = a.provider || "stripe";
    if (!PROVIDERS[prov]) { console.error(`unknown provider: ${prov}\nknown: ${Object.keys(PROVIDERS).join(", ")}`); process.exit(2); }
    const r = verifyFor(prov, body(a), a.sig, secret, a.timestamp);
    if (r.ok) { console.log(`✓ signature valid (timestamp ${r.age}s old)`); return; }
    console.error(`✗ ${r.reason}`);
    if (r.expected) console.error(`  expected signature: ${r.expected}`);
    process.exit(1);
  }

  if (cmd === "sign") {
    const secret = needSecret(a, a.provider);
    const prov = a.provider || "stripe";
    if (!PROVIDERS[prov]) { console.error(`unknown provider: ${prov}\nknown: ${Object.keys(PROVIDERS).join(", ")}`); process.exit(2); }
    const raw = body(a);
    const r = signFor(prov, raw, secret);
    const header = prov === "stripe" ? r.value : `${r.header}: ${r.value}`;
    console.log(header);
    if (PROVIDERS[prov].needsTimestampHeader && !a.quiet)
      console.error(`# also send ${PROVIDERS[prov].needsTimestampHeader}: ${r.timestamp}`);
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

  if (cmd === "audit") {
    const secret = needSecret(a);
    if (!a.url) { console.error("missing --url (the endpoint you want to audit)"); process.exit(2); }
    console.error(`auditing ${a.url}\n(only run this against an endpoint you control)\n`);
    const results = await auditEndpoint(a.url, secret);
    let hard = 0;
    for (const r of results) {
      const mark = r.pass ? "PASS" : (r.fatal ? "STOP" : r.soft ? "WARN" : "FAIL");
      if (!r.pass && !r.soft) hard++;
      console.log(`  [${mark}] ${r.name}  (${r.detail})`);
      if (!r.pass) console.log(`         ${r.why}`);
    }
    const passed = results.filter((r) => r.pass).length;
    console.log(`\n  ${passed}/${results.length} checks passed`);
    if (hard) {
      console.log(`  ${hard} of them matter: https://belalmou.github.io/digital-download-security/`);
      process.exit(1);
    }
    return;
  }

  console.error(`unknown command: ${cmd}\n\n${USAGE}`);
  process.exit(2);
}

// Run the CLI only when this file is the entrypoint, so the exports stay importable
// in tests. Resolve both sides through realpath: npx and npm invoke a bin through a
// SYMLINK, so a naive `import.meta.url === file://${process.argv[1]}` comparison is
// false and the CLI silently does nothing.
function isEntrypoint() {
  const invoked = process.argv[1];
  if (!invoked) return false;
  try {
    return fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(path.resolve(invoked));
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}
