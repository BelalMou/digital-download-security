/**
 * Reference download handler for a digital-download store.
 *
 * The rule: a purchased file is reachable only by the person who bought it, only
 * while that purchase stands, and only through a URL that expires.
 */

export type Purchase = {
  id: string;
  buyerId: string;
  refundedAt: Date | null;
  fileKey: string;
};

export interface DownloadDeps {
  /** Returns the signed-in user's id, or null. */
  getUserId: () => Promise<string | null>;
  findPurchase: (purchaseId: string) => Promise<Purchase | null>;
  /** Should return a URL that expires. `expiresInSeconds` is not optional for a reason. */
  createSignedUrl: (fileKey: string, expiresInSeconds: number) => Promise<string | null>;
  /** Return false to shed the request. */
  rateLimit?: (key: string) => boolean;
  clientKey?: string;
}

export const SIGNED_URL_TTL_SECONDS = 3600;

/**
 * Identical response for "does not exist" and "exists but isn't yours".
 *
 * Distinguishing them (403 vs 404) turns the endpoint into an oracle that
 * confirms which purchase ids are real. Same status, same body, both cases.
 */
const notFound = () => new Response("Not found", { status: 404 });

export async function handleDownload(
  purchaseId: string,
  deps: DownloadDeps
): Promise<Response> {
  // Shed load before doing any auth or database work.
  if (deps.rateLimit && !deps.rateLimit(deps.clientKey ?? "anonymous")) {
    return new Response("Too many requests", { status: 429 });
  }

  // Reject junk before it reaches the database.
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(purchaseId)) return notFound();

  const userId = await deps.getUserId();
  if (!userId) return new Response("Unauthorized", { status: 401 });

  const purchase = await deps.findPurchase(purchaseId);

  // Ownership is checked here, server-side, against the session — not by a query
  // parameter, and not by hiding the link in the UI.
  if (!purchase || purchase.buyerId !== userId) return notFound();

  // Refunded or disputed: the money went back, so the file goes away too.
  if (purchase.refundedAt) {
    return new Response("This purchase was refunded and is no longer available.", {
      status: 410,
    });
  }

  const url = await deps.createSignedUrl(purchase.fileKey, SIGNED_URL_TTL_SECONDS);
  if (!url) return new Response("Something went wrong", { status: 500 });

  // 302 to a short-lived signed URL. The file itself is never public.
  return new Response(null, { status: 302, headers: { Location: url } });
}
