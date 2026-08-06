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

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ADD = DATA / "additions.jsonl"
COMMENT = ROOT / "intake-comment.md"


def norm(url: str) -> str:
    k = adapters.normalize_url(url) or url
    return k[4:] if k.startswith("www.") else k


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
    name = re.sub(r"\s+", " ", f.get("name", "")).strip()
    what = re.sub(r"\s+", " ", f.get("what it does", "")).strip()

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

    cat = categorize(f"{name} {what}") or "Unsorted"
    status = probe(url)
    health = (f"reachable (HTTP {status})" if status and status < 400
              else ("no response" if status is None else f"HTTP {status}"))

    row = {
        "url": url, "name": name or url, "category": cat, "payload_type": "link",
        "source": f"community:@{user}", "sources": [f"community:@{user}"], "source_count": 1,
        "submitted_by": f"@{user}",
        "submitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": what[:280],
    }
    with ADD.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    COMMENT.write_text(
        f"Queued **{name or url}** → suggested category **{cat}** · preliminary check: {health}.\n\n"
        "A pull request was opened to add it (Community tier); a curator reviews and merges to "
        "publish. Authoritative health appears after the next daily check.", encoding="utf-8")
    title = re.sub(r"\s+", " ", f"Add tool: {name or url}")[:80]
    out(result="new", branch=f"intake/issue-{num}", title=title)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
