# Contributing

Thanks for helping keep OSINT Resources Hub useful and accurate. There are three
easy ways to contribute — none require you to write code.

## 1. Suggest a tool

Open an issue with the `suggest-tool` label and include:

- **URL** of the tool or resource
- **What it does** in one line
- **Who it's for** (e.g. threat intel, corporate investigations, fin-crime, geopolitics)
- Whether it's free, freemium, or commercial

We'll assess it — including a licence/terms check on any *source* it came from —
before it's added. (See "Sourcing rules" below.)

## 2. Report a dead or wrong link

Open an issue with the `dead-link` label and paste the URL. Our automated checker
catches most rot, but a human report is faster for soft-404s (pages that return
"200 OK" but show nothing useful).

## 3. Correct attribution or request removal

If you maintain a resource we list and want the credit corrected, or the entry
removed, open an issue with the `takedown` label or email
`info@osintresourceshub.com`.

## Sourcing rules (important)

We build the catalog by keeping **tool URLs** (which are facts) and attaching
**our own** taxonomy and health data. We do **not** copy another collection's
card structure, groupings, or descriptions.

So please:

- **Do** point us at a source (a link, a GitHub repo, a directory) and we'll
  evaluate it.
- **Don't** paste a large export of someone else's collection into an issue or
  PR — we can't ingest that, and it may breach that source's terms.

Every source we draw from is credited in [`SOURCES.md`](SOURCES.md).

## Code contributions

For fixes to the site, scripts, or workflow: fork, branch, and open a PR against
`main`. Keep changes focused and describe what and why. By contributing you agree
your code contribution is licensed under this repo's MIT `LICENSE` and any data
contribution under `DATA-LICENSE` (CC BY-SA 4.0).
