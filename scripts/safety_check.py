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


if __name__ == "__main__":
    import sys
    print(json.dumps(check_url(sys.argv[1] if len(sys.argv) > 1 else "https://example.com"), indent=2))
