#!/usr/bin/env python3
"""URL-reputation safety check — pluggable threat-intel providers (see specs/safety-vetting.md).

Aggregate verdict over ≥2 providers:
  - any provider says `listed`  -> "flagged"  (block/label)
  - ≥2 providers say `clean`     -> "clean"    (the two-source bar)
  - otherwise                    -> "unknown"  (allow, mark unknown — never block on a provider outage)

Providers are key-gated (keys via env / GitHub secrets); a provider with no key is skipped.
Stdlib only, so it runs anywhere (CI, local). Fail-open: any provider error -> "unknown".
"""
from __future__ import annotations
import json
import os
import socket
import urllib.parse
import urllib.request
from urllib.parse import urlsplit


def _host(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").split("@")[-1].split(":")[0].lower()
    except Exception:
        return ""


def urlhaus(url: str, key: str | None):
    if not key:
        return None
    try:
        data = urllib.parse.urlencode({"url": url}).encode()
        req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=data,
                                     headers={"Auth-Key": key})
        with urllib.request.urlopen(req, timeout=12) as r:
            j = json.loads(r.read().decode())
        qs = j.get("query_status")
        if qs == "ok" and j.get("url_status") in ("online", "known"):
            return ("urlhaus", "listed")
        if qs == "no_results":
            return ("urlhaus", "clean")
        return ("urlhaus", "unknown")
    except Exception:
        return ("urlhaus", "unknown")


def safebrowsing(url: str, key: str | None):
    if not key:
        return None
    try:
        body = {
            "client": {"clientId": "osintresourceshub", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        req = urllib.request.Request(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as r:
            j = json.loads(r.read().decode())
        return ("safebrowsing", "listed" if j.get("matches") else "clean")
    except Exception:
        return ("safebrowsing", "unknown")


def spamhaus_dbl(url: str, key=None):
    host = _host(url)
    if not host:
        return None
    try:
        res = socket.gethostbyname(f"{host}.dbl.spamhaus.org")
        if res.startswith("127.0.1."):          # 127.0.1.x = listed
            return ("spamhaus", "listed")
        return ("spamhaus", "unknown")           # 127.255.255.x = query refused/rate-limited
    except socket.gaierror:
        return ("spamhaus", "clean")             # NXDOMAIN = not listed
    except Exception:
        return ("spamhaus", "unknown")


# provider -> callable(url, key). Add PhishTank etc. here later.
PROVIDERS = [
    ("urlhaus", urlhaus, "URLHAUS_KEY"),
    ("safebrowsing", safebrowsing, "SAFEBROWSING_KEY"),
    ("spamhaus", spamhaus_dbl, None),            # DNS, no key
]


def check_url(url: str) -> dict:
    results = []
    for _name, fn, env in PROVIDERS:
        r = fn(url, os.environ.get(env) if env else None)
        if r:
            results.append(r)
    verdicts = [v for _, v in results]
    clean = verdicts.count("clean")
    if "listed" in verdicts:
        status = "flagged"
    elif clean >= 2:                              # the two-source bar for a "clean" badge
        status = "clean"
    else:
        status = "unknown"
    return {
        "status": status,
        "sources": [s for s, _ in results],
        "flagged_by": [s for s, v in results if v == "listed"],
    }


def safebrowsing_batch(urls: list[str], key: str | None) -> set:
    """Return the set of URLs Safe Browsing flags. Batches of 500 (its API limit). Fail-open."""
    flagged: set = set()
    if not key or not urls:
        return flagged
    for i in range(0, len(urls), 500):
        chunk = urls[i:i + 500]
        try:
            body = {
                "client": {"clientId": "osintresourceshub", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in chunk],
                },
            }
            req = urllib.request.Request(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                j = json.loads(r.read().decode())
            for m in j.get("matches", []):
                u = (m.get("threat") or {}).get("url")
                if u:
                    flagged.add(u)
        except Exception:
            pass  # fail-open: a batch error doesn't flag anyone
    return flagged


def check_catalog(urls: list[str], rate: float = 2.0) -> dict:
    """Recurring whole-catalog check (specs/safety-vetting.md): URLhaus per-URL (data-minimal — no
    bulk feed held) + Safe Browsing batched. No Spamhaus (DNS rate-limited for bulk). Two providers
    → the ≥2-clean bar means both keys are needed for a `clean` verdict. Fail-open throughout."""
    import time
    uh_key = os.environ.get("URLHAUS_KEY")
    sb_key = os.environ.get("SAFEBROWSING_KEY")
    sb_flagged = safebrowsing_batch(urls, sb_key)
    interval = 1.0 / rate if rate > 0 else 0.0
    out = {}
    for u in urls:
        res = []
        r = urlhaus(u, uh_key)
        if r:
            res.append(r)
        if sb_key:
            res.append(("safebrowsing", "listed" if u in sb_flagged else "clean"))
        verdicts = [v for _, v in res]
        if "listed" in verdicts:
            status = "flagged"
        elif verdicts.count("clean") >= 2:
            status = "clean"
        else:
            status = "unknown"
        out[u] = {"status": status, "sources": [s for s, _ in res],
                  "flagged_by": [s for s, v in res if v == "listed"]}
        if uh_key and interval:
            time.sleep(interval)          # be polite to URLhaus
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(check_url(sys.argv[1] if len(sys.argv) > 1 else "https://example.com"), indent=2))
