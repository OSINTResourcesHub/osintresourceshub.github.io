#!/usr/bin/env python3
"""Refresh link-health for the catalog.

Pipeline (run by .github/workflows/freshness.yml):

    data/tools.json  --(adapt)-->  corpus.jsonl
    corpus.jsonl     --(rotbaseline verify + report)-->  verification_log.jsonl + report.json
    those            --(adapt)-->  data/status.json   <-- what the site reads

`rotbaseline` is the link-health engine, installed as a dependency by the
workflow (it is NOT vendored into this repo). See the OSINT-Research engine repo.

tools.json shape (minimal):
    {
      "generated_at": "2026-07-11T00:00:00Z",
      "tools": [
        {"url": "https://example.com", "name": "Example", "source": "cipher387",
         "category": "Domains & IPs", "payload_type": "link"},
        ...
      ]
    }

Only entries with payload_type "link" (the default) are HTTP-checked; bookmarklets,
query-forms, etc. stay `unverified`, by design.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
WORK = Path(__file__).resolve().parent / "out"

TOOLS_JSON = DATA / "tools.json"
ADDITIONS = DATA / "additions.jsonl"        # CI/curator layer (D17-C) — health-checked too
STATUS_JSON = DATA / "status.json"
CORPUS = WORK / "corpus.jsonl"

# Rate: polite by default. Override in CI via env if needed.
RATE = "5"


def union_tools() -> list[dict]:
    """The live catalog: base tools.json ∪ additions.jsonl (D17-C)."""
    tools = json.loads(TOOLS_JSON.read_text(encoding="utf-8")).get("tools", [])
    seen = {(t.get("url") or "").strip() for t in tools}
    if ADDITIONS.exists():
        for line in ADDITIONS.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = (a.get("url") or "").strip()
            if url and url not in seen:
                tools.append(a)
                seen.add(url)
    return tools


def build_corpus(tools: list[dict], exclude: set = frozenset()) -> int:
    """tools -> corpus.jsonl in the shape rotbaseline expects. `exclude` = URLs we must NOT fetch
    (safety-flagged) — we never HTTP-request a known-malicious link."""
    WORK.mkdir(parents=True, exist_ok=True)
    n = 0
    with CORPUS.open("w", encoding="utf-8") as f:
        for t in tools:
            url = (t.get("url") or "").strip()
            if not url or url in exclude:
                continue
            row = {
                "entry": url,
                "title": t.get("name", ""),
                "source": t.get("source", ""),
                "category": t.get("category"),
                "payload_type": t.get("payload_type", "link"),
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def load_latest_states() -> dict[str, dict]:
    """Latest verdict per URL from the append-only verification log."""
    log = WORK / "verification_log.jsonl"
    latest: dict[str, dict] = {}
    if not log.exists():
        return latest
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        latest[r["entry_url"]] = {
            "state": r.get("state"),
            "final_status": r.get("final_status"),
            "checked_at": r.get("checked_at"),
        }
    return latest


def main() -> int:
    if not TOOLS_JSON.exists():
        print(f"no {TOOLS_JSON} yet — nothing to check", file=sys.stderr)
        return 0

    tools = union_tools()
    urls = [u for u in ((t.get("url") or "").strip() for t in tools) if u]

    prior_flagged = set()
    if STATUS_JSON.exists():
        try:
            prior_flagged = set(json.loads(STATUS_JSON.read_text(encoding="utf-8")).get("flagged", []))
        except Exception:
            pass

    # ---- SAFETY FIRST: URL-reputation before we fetch anything (specs/safety-vetting.md) ----
    from safety_check import check_catalog
    safety = check_catalog(urls)
    flagged = {u for u, v in safety.items() if v["status"] == "flagged"}
    newly = sorted(flagged - prior_flagged)
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "newly_flagged.txt").write_text("\n".join(newly), encoding="utf-8")
    if flagged:
        print(f"safety: {len(flagged)} flagged ({len(newly)} newly) — not fetching those", flush=True)

    # ---- health-check the rest (never fetch a flagged URL) ----
    total = build_corpus(tools, exclude=flagged)
    if total:
        run(["rotbaseline", "verify", "--corpus", str(CORPUS), "--out", str(WORK), "--rate", RATE])
        run(["rotbaseline", "report", "--in", str(WORK), "--corpus", str(CORPUS),
             "--out", str(WORK), "--domain", "OSINT"])
    report = json.loads((WORK / "report.json").read_text(encoding="utf-8")) if (WORK / "report.json").exists() else {}
    links = load_latest_states()

    # ---- overlay safety onto every union URL (health only where we fetched) ----
    for u in urls:
        e = links.get(u, {})
        sv = safety.get(u, {})
        e["safety"] = sv.get("status", "unknown")
        if sv.get("sources"):
            e["safety_sources"] = sv["sources"]
        links[u] = e

    by_state: dict[str, int] = {}
    safety_by: dict[str, int] = {}
    for v in links.values():
        if v.get("state"):
            by_state[v["state"]] = by_state.get(v["state"], 0) + 1
        s = v.get("safety", "unknown")
        safety_by[s] = safety_by.get(s, 0) + 1

    status = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_total": len(urls),
        "checked": report.get("rot", {}).get("checked_http", sum(1 for v in links.values() if v.get("state"))),
        "rot_pct": report.get("rot", {}).get("rot_pct_of_checked", 0.0),
        "rot_definition": "dead + suspected_dead + blocked_unknown as % of checked links",
        "by_state": by_state,
        "safety_by_state": safety_by,
        "flagged": sorted(flagged),
        "links": links,
    }
    DATA.mkdir(parents=True, exist_ok=True)
    STATUS_JSON.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {STATUS_JSON}: {status['checked']} checked, rot {status['rot_pct']}%, safety {safety_by}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
