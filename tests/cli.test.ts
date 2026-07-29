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
