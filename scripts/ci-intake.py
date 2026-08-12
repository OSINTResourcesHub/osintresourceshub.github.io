#!/usr/bin/env python3
"""CI intake — runs the Hub's logic on a `suggest-tool` issue (decision D17-C).

Parses the issue form, dedup-checks against the live union (tools.json ∪ additions.jsonl),
categorizes with the engine taxonomy, does a best-effort reachability probe, and — if the tool
is new — appends it to `data/additions.jsonl`. Writes `intake-comment.md` (posted back on the
issue) and step outputs (`result`, `branch`, `title`) for the workflow.

Runs in CI with `rotbaseline` pip-installed (>= v0.2.0 for the 2-level taxonomy). It can't import
the private `tools/` helpers, so the union read + normalization are inlined here.
"""
from __future__ import annotations
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from rotbaseline import adapters
from rotbaseline.taxonomy import classify as categorize
from safety_check import check_url          # URL-reputation vetting (specs/safety-vetting.md)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ADD = DATA / "additions.jsonl"
COMMENT = ROOT / "intake-comment.md"


def norm(url: str) -> str:
    k = adapters.normalize_url(url) or url
    return k[4:] if k.startswith("www.") else k


# Browser-extension detection from store URLs. MUST stay in sync with the same set in
# tools/export_catalog.py (this script runs in CI and can't import the private tools/ helpers,
# so the store regexes are duplicated by hand — update both if you touch either).
_STORES = [("chrome", re.compile(r"chromewebstore\.google\.com|chrome\.google\.com/webstore")),
           ("firefox", re.compile(r"addons\.mozilla\.org")),
           ("edge", re.compile(r"microsoftedge\.microsoft\.com/addons")),
           ("opera", re.compile(r"addons\.opera\.com"))]


def ext_src(u: str) -> list[str]:
    u = (u or "").lower()
    return [n for n, rx in _STORES if rx.search(u)]


def parse_issue(body: str) -> dict:
    """GitHub issue-form body renders as '### Label\\n\\nvalue' blocks."""
    fields = {}
    for m in re.finditer(r"^###\s+(.+?)\s*\n+(.*?)(?=\n###\s|\Z)", body or "", re.S | re.M):
        val = m.group(2).strip()
        fields[m.group(1).strip().lower()] = "" if val == "_No response_" else val
    return fields


def load_union() -> list[dict]:
    tools = json.loads((DATA / "tools.json").read_text(encoding="utf-8")).get("tools", [])
    seen = {t["url"] for t in tools}
    if ADD.exists():
        for line in ADD.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    a = json.loads(line)
                    if a.get("url") and a["url"] not in seen:
                        tools.append(a); seen.add(a["url"])
                except json.JSONDecodeError:
                    pass
    return tools


def probe(url: str):
    try:
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": "OSINTResourcesHub-Intake/0.1 (+https://osintresourceshub.com)"})
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status
    except Exception:
        return None


def out(**kv):
    p = os.environ.get("GITHUB_OUTPUT")
    if p:
        with open(p, "a", encoding="utf-8") as f:
            for k, v in kv.items():
                f.write(f"{k}={v}\n")


def main() -> int:
    f = parse_issue(os.environ.get("ISSUE_BODY", ""))
    num = os.environ.get("ISSUE_NUMBER", "")
    user = re.sub(r"[^A-Za-z0-9-]", "", os.environ.get("ISSUE_USER", "someone")) or "someone"

    raw = (f.get("url") or "").strip()
    url = raw.split()[0] if raw else ""
    # tool name = the issue title (minus any legacy "[tool] " prefix); fall back to the old Name field
    title = re.sub(r"^\[tool\]\s*", "", os.environ.get("ISSUE_TITLE", ""), flags=re.I)
    name = re.sub(r"\s+", " ", f.get("name", "")).strip() or re.sub(r"\s+", " ", title).strip()
    what = re.sub(r"\s+", " ", f.get("what it does", "")).strip()
    lic = re.sub(r"\s+", " ", f.get("access", "")).strip()   # cost/access model → stored as `cost`

    if not url.lower().startswith("http"):
        COMMENT.write_text("Couldn't find a valid **URL** in the submission — please edit the "
                           "issue with a full `https://…` URL and I'll re-check.", encoding="utf-8")
        out(result="invalid")
        return 0

    key = norm(url)
    idx = {norm(t["url"]): t for t in load_union()}
    if key in idx:
        t = idx[key]
        COMMENT.write_text(f"**Already in the catalog** as *{t['name']}* — category "
                           f"**{t.get('category','?')}**. No change needed.", encoding="utf-8")
        out(result="known")
        return 0

    # Safety check BEFORE anything else touches the URL — protects the curator who will click it.
    safety = check_url(url)
    if safety["status"] == "flagged":
        COMMENT.write_text(
            f"⚠️ **Not added — flagged by a URL-reputation check** ({', '.join(safety['flagged_by'])}). "
            "This URL is on a threat-intel blocklist (malware/phishing). If you believe this is a false "
            "positive, say so here and a maintainer will review.", encoding="utf-8")
        out(result="flagged")
        return 0
    safe_line = ("✓ safety-checked, clean" if safety["status"] == "clean"
                 else "safety: not fully checked (reputation providers unconfigured or unavailable)")

    cat = categorize(f"{name} {what}") or "Unsorted"
    exts = ext_src(url)                                   # [] unless it's a known extension-store URL
    status = probe(url)
    health = (f"reachable (HTTP {status})" if status and status < 400
              else ("no response" if status is None else f"HTTP {status}"))

    row = {
        "url": url, "name": name or url, "category": cat,
        **({"ext": True, "ext_src": exts} if exts else {}),   # browser extension (auto, from store URL)
        "payload_type": "link",
        **({"cost": lic} if lic and lic != "Unknown" else {}),
        "safety": safety["status"],
        **({"safety_sources": safety["sources"]} if safety["sources"] else {}),
        "source": f"community:@{user}", "sources": [f"community:@{user}"], "source_count": 1,
        "submitted_by": f"@{user}",
        "submitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": what[:280],
    }
    with ADD.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    ext_note = f" · detected as a **{'/'.join(exts)}** browser extension" if exts else ""
    COMMENT.write_text(
        f"Queued **{name or url}** → suggested category **{cat}**{ext_note} · {safe_line} · reachability: {health}.\n\n"
        "A pull request was opened to add it (Community tier); a curator reviews and merges to "
        "publish. Authoritative health appears after the next daily check.", encoding="utf-8")
    title = re.sub(r"\s+", " ", f"Add tool: {name or url}")[:80]
    out(result="new", branch=f"intake/issue-{num}", title=title)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
