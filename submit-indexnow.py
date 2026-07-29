#!/usr/bin/env python3
"""Push our URLs into the IndexNow-participating search engines (Bing, Yandex, Seznam).

No account and no verification flow: ownership is proved by hosting a file whose
name and contents are both the key. Run after deploying a change.

    python3 submit-indexnow.py
"""
import json, urllib.request, urllib.error, re, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
HOST = "belalmou.github.io"
SITE = f"https://{HOST}/digital-download-security/"
ENDPOINT = "https://api.indexnow.org/indexnow"


def key_from_build():
    src = open(os.path.join(BASE, "build-docs.py"), encoding="utf-8").read()
    m = re.search(r'INDEXNOW_KEY\s*=\s*"([0-9a-f]+)"', src)
    if not m:
        sys.exit("no INDEXNOW_KEY found in build-docs.py")
    return m.group(1)


def urls_from_sitemap():
    xml = open(os.path.join(BASE, "docs", "sitemap.xml"), encoding="utf-8").read()
    return re.findall(r"<loc>([^<]+)</loc>", xml)


def check(url, expect=None):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            body = r.read().decode("utf-8", "replace").strip()
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


def main():
    key = key_from_build()
    key_url = f"{SITE}{key}.txt"

    # Submitting before the key file is live gets the whole batch rejected, so verify first.
    status, body = check(key_url)
    print(f"key file {key_url} -> HTTP {status}")
    if status != 200 or body != key:
        sys.exit(f"key file is not live and correct yet (got {status!r}, body {body[:40]!r}). "
                 "Deploy first, then re-run.")
    print("  contents match the key ✓")

    urls = urls_from_sitemap()
    print(f"submitting {len(urls)} URLs from the sitemap")
    for u in urls:
        print("  ", u)

    payload = json.dumps({
        "host": HOST,
        "key": key,
        "keyLocation": key_url,
        "urlList": urls,
    }).encode()

    req = urllib.request.Request(ENDPOINT, data=payload,
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"\nIndexNow -> HTTP {r.status} {r.reason}")
            # 200 accepted, 202 accepted-pending-key-validation. Both are success.
            if r.status in (200, 202):
                print("accepted. Bing/Yandex/Seznam will crawl these; it is not instant.")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        print(f"\nIndexNow -> HTTP {e.code}: {detail}")
        sys.exit(1)


if __name__ == "__main__":
    main()
