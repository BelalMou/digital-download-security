import { describe, it, expect } from "vitest";
// @ts-expect-error - plain ESM module, no types needed for these assertions
import { hmac, parseSigHeader, verify, sign } from "../cli.mjs";

const SECRET = "whsec_cli_test_secret";
const BODY = '{"id":"evt_1","type":"checkout.session.completed"}';

describe("stripe-sig core", () => {
  it("signs and verifies its own output", () => {
    const { header } = sign(BODY, SECRET);
    expect(verify(BODY, header, SECRET).ok).toBe(true);
  });

  it("matches a signature computed independently", () => {
    const t = 1785200000;
    // Reference value: HMAC-SHA256 over "<t>.<body>" — the same thing Stripe does.
    expect(hmac(SECRET, t, BODY)).toBe(sign(BODY, SECRET, t).header.split("v1=")[1]);
  });

  it("rejects a body that changed by one byte", () => {
    const { header } = sign(BODY, SECRET);
    const r = verify(BODY + " ", header, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/byte-identical/);
  });

  it("rejects the wrong secret", () => {
    const { header } = sign(BODY, SECRET);
    expect(verify(BODY, header, "whsec_a_different_secret").ok).toBe(false);
  });

  it("rejects a stale timestamp even when the hmac is correct", () => {
    const old = Math.floor(Date.now() / 1000) - 600; // outside the 300s window
    const { header } = sign(BODY, SECRET, old);
    const r = verify(BODY, header, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/replay window/);
  });

  it("handles a malformed header without throwing", () => {
    expect(verify(BODY, "nonsense", SECRET).ok).toBe(false);
    expect(verify(BODY, "", SECRET).ok).toBe(false);
  });

  it("accepts a header carrying several v1 signatures", () => {
    const { header, timestamp } = sign(BODY, SECRET);
    const withExtra = `${header},v1=${"0".repeat(64)}`;
    expect(verify(BODY, withExtra, SECRET).ok).toBe(true);
    expect(parseSigHeader(withExtra).v1).toHaveLength(2);
    expect(parseSigHeader(withExtra).t).toBe(String(timestamp));
  });
});

// @ts-expect-error - plain ESM module
import { signFor, verifyFor, PROVIDERS } from "../cli.mjs";

describe("multi-provider signatures", () => {
  const body = '{"hello":"world"}';
  const secret = "shhh_secret";

  // Reference values computed independently (Python hmac/hashlib), so a refactor
  // that quietly changes what gets signed will fail here.
  const REFERENCE: Record<string, string> = {
    stripe: "t=1785200000,v1=79bf35a829cd00eec4452a7bf10477082580ed89ee60fc769cfd7ced90b8e7ef",
    github: "sha256=9c44816487012df8d61dd06c06a28f70ff0f9f69311cf1ebd60d45d4679fc8dd",
    shopify: "nESBZIcBLfjWHdBsBqKPcP8Pn2kxHPHr1g1F1GefyN0=",
    slack: "v0=c0cc0262427825a80c884205a83f894bd89740a841c32bdafa7622c5202704cd",
  };

  for (const provider of Object.keys(REFERENCE)) {
    it(`${provider}: matches an independently computed signature`, () => {
      expect(signFor(provider, body, secret, 1785200000).value).toBe(REFERENCE[provider]);
    });

    it(`${provider}: rejects a tampered body`, () => {
      const now = Math.floor(Date.now() / 1000);
      const { value } = signFor(provider, body, secret, now);
      expect(verifyFor(provider, body + " ", value, secret, now).ok).toBe(false);
    });

    it(`${provider}: rejects the wrong secret`, () => {
      const now = Math.floor(Date.now() / 1000);
      const { value } = signFor(provider, body, secret, now);
      expect(verifyFor(provider, body, value, "not_the_secret", now).ok).toBe(false);
    });

    it(`${provider}: round-trips with a fresh timestamp`, () => {
      const now = Math.floor(Date.now() / 1000);
      const { value } = signFor(provider, body, secret, now);
      expect(verifyFor(provider, body, value, secret, now).ok).toBe(true);
    });
  }

  it("enforces a replay window only where the provider has one", () => {
    const stale = Math.floor(Date.now() / 1000) - 100000;
    for (const p of Object.keys(PROVIDERS)) {
      const { value } = signFor(p, body, secret, stale);
      const r = verifyFor(p, body, value, secret, stale);
      // Stripe and Slack sign the timestamp; GitHub and Shopify do not.
      expect(r.ok).toBe(PROVIDERS[p].tolerance === null);
    }
  });

  it("refuses an unknown provider instead of guessing", () => {
    expect(verifyFor("paypal", body, "x", secret).ok).toBe(false);
  });
});
