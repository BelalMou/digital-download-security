# Four ways a digital-download store leaks money

[![licence: MIT](https://img.shields.io/badge/licence-MIT-0E7A55)](LICENSE)

**Read it as a write-up:** <https://belalmou.github.io/digital-download-security/>

Selling files is the "easy" e-commerce case: no stock, no shipping, no returns
logistics. That reputation is why the security gets skipped, and the same four
holes turn up in tutorial after tutorial.

Each one below comes with a **runnable test that fails against the naive
implementation and passes against the fixed one**. Clone it, run `npm test`, and
check your own store against the same cases.

```bash
npm install
npm test          # 22 tests, ~200ms, no database or network required
```

Everything is mocked, so the suite runs anywhere and finishes instantly. There is
nothing to configure.

---

## 1. The webhook that grants two purchases

Stripe delivers webhooks **at least once**. Retries happen on timeouts, on 500s,
and sometimes for no reason you'll ever discover. The naive handler is:

```ts
// wrong
const session = event.data.object;
await prisma.purchase.create({ data: { ... } });   // runs twice on redelivery
```

Two rows, one payment. Now your revenue reporting is wrong, the buyer may get two
confirmation emails, and any per-purchase entitlement is doubled.

The fix isn't "check if it exists first" on its own — that's a race. It's a
**unique constraint on the Stripe id** so the database refuses the second write,
with the check as the fast path:

```ts
const existing = await prisma.purchase.findFirst({
  where: { stripePaymentId: session.id },
});
if (!existing) {
  await prisma.purchase.create({
    data: { stripePaymentId: session.id, ... },   // unique index catches the race
  });
}
```

> `tests/stripe-webhook.test.ts` → *"does not double-grant when Stripe redelivers
> the same event"* — asserts the second delivery still returns 200 (so Stripe stops
> retrying) while `create` was called exactly once.

## 2. The signature you forgot to verify

Your webhook endpoint is a public URL that grants entitlements. If it doesn't
verify the signature, **anyone who guesses it can mint themselves purchases** by
POSTing a plausible JSON body.

```ts
const event = stripe.webhooks.constructEvent(
  await request.text(),        // RAW body — see below
  request.headers.get("stripe-signature"),
  process.env.STRIPE_WEBHOOK_SECRET
);
```

Two traps here:

- **The raw body matters.** If your framework parsed the JSON and you re-serialise
  it, key order and whitespace change, the computed signature won't match, and the
  usual "fix" people reach for is to skip verification. Read the body as text.
- **Fail closed.** A verification error is a `400`, not a `try/catch` that shrugs
  and continues.

> Tests cover a missing signature header, a forged payload, and that verification
> receives the raw body rather than a re-serialised object.

## 3. The download URL that gets shared

If a purchased file lives at a guessable or permanent URL, it will end up in a
Discord server. Two things have to be true:

- **Ownership is checked server-side, against the session** — not by a query
  parameter, and not by hiding the link in the UI.
- **The URL expires.** Serve a signed URL with a short TTL rather than a public
  object.

```ts
if (!purchase || purchase.buyerId !== session.user.id) {
  return new Response("Not found", { status: 404 });
}
const { data } = await supabase.storage
  .from("assets")
  .createSignedUrl(purchase.asset.fileUrl, 3600);
```

Note the `404`. Returning `403` for "exists but isn't yours" and `404` for
"doesn't exist" **tells an attacker which purchase ids are real**. Return the same
thing for both.

> `tests/download-authorization.test.ts` asserts a non-owner gets 404, that **no
> signed URL is ever minted** for them, and that the foreign-purchase response is
> byte-identical to the missing-purchase response.

## 4. The refund that doesn't revoke anything

This one is nearly universal, because refunding happens in the Stripe dashboard
and never touches your app. The customer gets their money back **and keeps the
file**.

Handle `charge.refunded` and `charge.dispute.created`:

```ts
await prisma.purchase.updateMany({
  where: { stripePaymentIntentId: intentId, refundedAt: null },
  data: { refundedAt: new Date() },
});
```

Three details worth stealing:

- **Refund events reference the PaymentIntent, not the Checkout Session.** If you
  only stored the session id, you cannot map a refund back to a purchase at all.
  Store both at fulfilment.
- **Partial refunds shouldn't revoke** — the buyer still paid for part of it.
  Compare `amount_refunded` against `amount`.
- **Don't delete the purchase row.** It's the financial record the refund refers
  to. Add a `refundedAt` column and check it at download time.

---

## Bonus: the price you took from the browser

Not in the four because it's better known, but still worth stating: never accept
an amount from the client.

```ts
const asset = await prisma.asset.findUnique({ where: { id } });
unit_amount: Math.round(asset.price * 100)   // from your DB, always
```

> Tested with hostile `amount` and `price` values planted in the checkout session's
> metadata; the recorded amount still comes from Stripe's `amount_total`.

---

## What this is and isn't

This is a **reference for the security-critical paths**, not a store. It is
deliberately small so the tests are the point.

If you want the whole thing built — storefront, auth, admin moderation, seller
dashboards, EN/PL i18n, transactional email, and these four fixes already wired —
that's the [Digital Storefront Starter](#), a paid kit. It's the same code these
tests were extracted from. No pressure: everything above is MIT and complete
enough to fix your own store without buying anything.

## Licence

MIT.
