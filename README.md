# OSINT Resources Hub

**A vetted directory of OSINT tools, organized by _how you actually investigate_ — not by what shape the software ships in.**

Extensions, GitHub tools, and the web platforms & data sources most collections skip — curated for threat intel, corporate investigations, fin-crime, and geopolitical research. Every entry is vetted, attributed, and health-checked, so dead links don't rot in the list.

Live at **https://osintresourceshub.com** · built in public.

---

## What this repo is

This is the **public site repo** for OSINT Resources Hub. It contains only what's meant to be public:

| Path | What |
|---|---|
| `index.html` | The site (currently the "launching soon" page; later the full app) |
| `data/tools.json` | The catalog — URLs + **our** canonical taxonomy + source attribution |
| `data/status.json` | Link-health snapshot, refreshed automatically (see below) |
| `scripts/refresh.py` | Adapts `tools.json` → the checker → `status.json` |
| `.github/workflows/freshness.yml` | Scheduled job that runs the health check and commits `status.json` |
| `SOURCES.md` | Attribution — every collection we drew from, credited |
| `LICENSE` / `DATA-LICENSE` | Code licence (MIT) and data licence (CC BY-SA 4.0) |

The engine that measures link rot (`rotbaseline`) lives in a **separate repo** and is installed as a dependency by the workflow — this repo carries no raw third-party corpora.

## How the catalog is built (provenance, not scraping)

We keep the **free facts** — a tool's URL — and attach **our own** taxonomy and health data. We never republish a source's own grouping or card structure. Overlap between sources is a *feature*: a tool listed in several independent collections scores higher and earns a "listed in N collections" badge. Full method and every source: [`SOURCES.md`](SOURCES.md).

## Link health, refreshed automatically

A scheduled GitHub Action runs the `rotbaseline` checker against every URL and writes `data/status.json` (per-URL state + an overall rot %). States: `alive`, `dead`, `suspected_dead`, `blocked_unknown`, `login_walled`, `unverified`. A link is only marked `dead` after two failing observations ≥24 h apart, so a transient blip doesn't kill an entry. See [`scripts/refresh.py`](scripts/refresh.py) and [`.github/workflows/freshness.yml`](.github/workflows/freshness.yml).

## Provenance & takedown

Every entry credits its source(s). If you maintain a listed resource and want an attribution corrected or an entry removed, open an issue with the `takedown` label or email `info@osintresourceshub.com`. We aim to action requests promptly.

## Contributing

Suggestions for new tools, corrections, and dead-link reports are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please don't paste large exports of someone else's collection; link to the source and we'll assess it through our compliance process.

## Credits

Created and maintained by [OSINT-Research](https://osint-research.com).
