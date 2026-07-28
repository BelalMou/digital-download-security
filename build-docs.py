#!/usr/bin/env python3
"""Generate the GitHub Pages site from article.html.

article.html is written for the Artifact renderer, which supplies its own <head>.
GitHub Pages serves the file raw, so it needs a real document with the metadata a
search engine and a link preview actually read.
"""
import re, os, datetime

BASE = os.path.dirname(os.path.abspath(__file__))
SITE = "https://belalmou.github.io/digital-download-security/"
REPO = "https://github.com/BelalMou/digital-download-security"

TITLE = "Four ways a digital-download store leaks money"
DESC = ("Stripe webhooks fire more than once, download URLs get shared, and refunds "
        "don't revoke access. Four failure modes in digital-download stores, each with "
        "a runnable test. MIT licensed.")

src = open(os.path.join(BASE, "article.html"), encoding="utf-8").read()
style = re.search(r"<style>.*?</style>", src, re.S).group(0)
body = src.split("</style>", 1)[1].strip()

# The GitHub link belongs in the page, not only in the footer.
if "Source and tests on GitHub" not in body:
    body = body.replace(
        "<footer>",
        f'<p style="margin-top:34px"><a href="{REPO}" '
        'style="font-family:var(--mono);font-size:14px;display:inline-flex;align-items:center;'
        'gap:9px;text-decoration:none;border:1px solid var(--rule-2);border-radius:999px;'
        'padding:11px 20px;color:var(--ink)">Source and tests on GitHub &rarr;</a></p>\n<footer>',
    )

ld = f"""{{
  "@context":"https://schema.org",
  "@type":"TechArticle",
  "headline":"{TITLE}",
  "description":"{DESC}",
  "author":{{"@type":"Person","name":"Belal Moussa","url":"https://github.com/BelalMou"}},
  "datePublished":"2026-07-27",
  "dateModified":"{datetime.date.today().isoformat()}",
  "license":"https://opensource.org/licenses/MIT",
  "mainEntityOfPage":{{"@type":"WebPage","@id":"{SITE}"}},
  "keywords":"stripe webhook idempotency, webhook fired twice, signed download url, refund revoke access, payment security"
}}"""

doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TITLE}</title>
<meta name="description" content="{DESC}">
<link rel="canonical" href="{SITE}">
<meta name="author" content="Belal Moussa">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">

<meta property="og:type" content="article">
<meta property="og:title" content="{TITLE}">
<meta property="og:description" content="{DESC}">
<meta property="og:url" content="{SITE}">
<meta property="og:site_name" content="digital-download-security">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{TITLE}">
<meta name="twitter:description" content="{DESC}">

<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><text y='26' font-size='26'>&#128274;</text></svg>">
<script type="application/ld+json">{ld}</script>
{style}
</head>
<body>
{body}
</body>
</html>
"""

with open(os.path.join(BASE, "docs", "index.html"), "w", encoding="utf-8") as f:
    f.write(doc)

with open(os.path.join(BASE, "docs", "robots.txt"), "w", encoding="utf-8") as f:
    f.write(f"User-agent: *\nAllow: /\n\nSitemap: {SITE}sitemap.xml\n")

with open(os.path.join(BASE, "docs", "sitemap.xml"), "w", encoding="utf-8") as f:
    f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{SITE}</loc>
    <lastmod>{datetime.date.today().isoformat()}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>{SITE}test-stripe-webhook-locally.html</loc>
    <lastmod>{datetime.date.today().isoformat()}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>{SITE}stripe-webhook-fired-twice.html</loc>
    <lastmod>{datetime.date.today().isoformat()}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>{SITE}stripe-signature-debugger.html</loc>
    <lastmod>{datetime.date.today().isoformat()}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
</urlset>
""")

# Stops Jekyll from touching the files.
open(os.path.join(BASE, "docs", ".nojekyll"), "w").close()

print(f"built docs/index.html ({len(doc):,} bytes) + robots.txt + sitemap.xml + .nojekyll")
