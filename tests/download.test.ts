import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleDownload, type Purchase, type DownloadDeps } from "../src/download";

const OWNER = "user-owner";
const ID_A = "clx0000000000000000000aaa";
const ID_B = "clx0000000000000000000bbb";

const purchase = (over: Partial<Purchase> = {}): Purchase => ({
  id: ID_A,
  buyerId: OWNER,
  refundedAt: null,
  fileKey: "owner/asset.zip",
  ...over,
});

let deps: DownloadDeps;
let createSignedUrl: ReturnType<typeof vi.fn>;
let findPurchase: ReturnType<typeof vi.fn>;
let getUserId: ReturnType<typeof vi.fn>;

beforeEach(() => {
  createSignedUrl = vi.fn().mockResolvedValue("https://storage.example/signed?t=abc");
  findPurchase = vi.fn();
  getUserId = vi.fn().mockResolvedValue(OWNER);
  deps = { getUserId, findPurchase, createSignedUrl } as unknown as DownloadDeps;
});

describe("leak #3 — the download URL that gets shared", () => {
  it("refuses an anonymous caller before touching the database", async () => {
    getUserId.mockResolvedValue(null);
    const res = await handleDownload(ID_A, deps);
    expect(res.status).toBe(401);
    expect(findPurchase).not.toHaveBeenCalled();
  });

  it("does not let a signed-in user download someone else's purchase", async () => {
    findPurchase.mockResolvedValue(purchase({ buyerId: "user-victim" }));
    const res = await handleDownload(ID_A, deps);
    expect(res.status).toBe(404);
    // The critical assertion: no signed URL is ever minted for a non-owner.
    expect(createSignedUrl).not.toHaveBeenCalled();
  });

  it("does not leak which purchase ids exist", async () => {
    findPurchase.mockResolvedValueOnce(purchase({ buyerId: "user-victim" }));
    const foreign = await handleDownload(ID_A, deps);

    findPurchase.mockResolvedValueOnce(null);
    const missing = await handleDownload(ID_B, deps);

    expect(foreign.status).toBe(missing.status);
    expect(await foreign.text()).toBe(await missing.text());
  });

  it("gives the owner a URL that expires", async () => {
    findPurchase.mockResolvedValue(purchase());
    const res = await handleDownload(ID_A, deps);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://storage.example/signed?t=abc");
    const [key, ttl] = createSignedUrl.mock.calls[0];
    expect(key).toBe("owner/asset.zip");
    expect(ttl).toBe(3600);
  });

  it("rejects a malformed id before querying", async () => {
    const res = await handleDownload("../../etc/passwd", deps);
    expect(res.status).toBe(404);
    expect(findPurchase).not.toHaveBeenCalled();
  });

  it("sheds load before authenticating", async () => {
    const res = await handleDownload(ID_A, { ...deps, rateLimit: () => false });
    expect(res.status).toBe(429);
    expect(getUserId).not.toHaveBeenCalled();
  });
});

describe("leak #4 — the refund that doesn't revoke", () => {
  it("refuses a refunded purchase and mints no URL", async () => {
    findPurchase.mockResolvedValue(purchase({ refundedAt: new Date("2026-07-01") }));
    const res = await handleDownload(ID_A, deps);
    expect(res.status).toBe(410);
    expect(createSignedUrl).not.toHaveBeenCalled();
  });

  it("still serves a purchase that was never refunded", async () => {
    findPurchase.mockResolvedValue(purchase({ refundedAt: null }));
    const res = await handleDownload(ID_A, deps);
    expect(res.status).toBe(302);
  });
});
