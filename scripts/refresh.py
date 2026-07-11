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
STATUS_JSON = DATA / "status.json"
CORPUS = WORK / "corpus.jsonl"

# Rate: polite by default. Override in CI via env if needed.
RATE = "5"


def build_corpus() -> int:
    """tools.json -> corpus.jsonl in the shape rotbaseline.adapters.load_corpus expects."""
    tools = json.loads(TOOLS_JSON.read_text(encoding="utf-8")).get("tools", [])
    WORK.mkdir(parents=True, exist_ok=True)
    n = 0
    with CORPUS.open("w", encoding="utf-8") as f:
        for t in tools:
            url = (t.get("url") or "").strip()
            if not url:
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

    total = build_corpus()
    if total == 0:
        print("corpus empty — nothing to check", file=sys.stderr)
        return 0

    # Tier-1 HTTP check + report. (Tier-2 headless is optional and heavier; enable
    # in the workflow by installing Playwright browsers and adding a verify-tier2 step.)
    run(["rotbaseline", "verify", "--corpus", str(CORPUS), "--out", str(WORK), "--rate", RATE])
    run(["rotbaseline", "report", "--in", str(WORK), "--corpus", str(CORPUS),
         "--out", str(WORK), "--domain", "OSINT"])

    report = json.loads((WORK / "report.json").read_text(encoding="utf-8"))
    links = load_latest_states()

    by_state: dict[str, int] = {}
    for v in links.values():
        by_state[v["state"]] = by_state.get(v["state"], 0) + 1

    status = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_total": total,
        "checked": report.get("rot", {}).get("checked_http", len(links)),
        "rot_pct": report.get("rot", {}).get("rot_pct_of_checked", 0.0),
        "rot_definition": "dead + suspected_dead + blocked_unknown as % of checked links",
        "by_state": by_state,
        "links": links,
    }
    DATA.mkdir(parents=True, exist_ok=True)
    STATUS_JSON.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {STATUS_JSON}: {status['checked']} checked, rot {status['rot_pct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
