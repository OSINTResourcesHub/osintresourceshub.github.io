# Security policy

Thanks for helping keep OSINT Resources Hub safe. This document covers how to
report a problem and the security practices the project follows.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

- Preferred: use GitHub's **private vulnerability reporting** — the repository's
  **Security** tab → **Report a vulnerability**.
- Or email **info@osintresourceshub.com**.

Please include what you found, how to reproduce it, and the impact. We aim to
acknowledge within a few days and to fix confirmed issues as quickly as is
reasonable for a small, volunteer project. Coordinated, good-faith disclosure is
welcome and appreciated.

### Reporting a *listed tool*, not the site

The catalog links to third-party tools. A tool URL is a public fact; each links
to its origin and carries its own terms. If a **listed link is malicious,
phishing, or should be removed**, please flag it (issue or the email above) — our
recurring safety check should catch most, but reports help.

## What's in scope

- The website and portal (`osintresourceshub.com`, the GitHub Pages site).
- The link-health engine (`rotbaseline`) and the curation/intake scripts.
- The catalog data pipeline.

Out of scope: the third-party tools and websites the catalog *links to* — those
are operated by others.

## Our security practices

- **No trackers, data-minimisation.** The public site sets no analytics or
  tracking. The catalog holds public facts, not personal data. The on-site
  assistant runs client-side with a PII-guard and sends nothing to a backend.
- **Link safety-vetting.** Catalog URLs are checked against threat-intel feeds
  (URLhaus + Google Safe Browsing) at intake and on a daily schedule; flagged
  links are labelled/removed and never HTTP-fetched by the health checker.
- **Signed commits.** Maintainer commits are signed (SSH signing) with
  "Vigilant mode" on, so unsigned commits are flagged. Releases are tagged.
- **Protected branches & tags.** `main` is protected against force-push and
  deletion; release tags are protected.
- **Least-privilege automation.** GitHub Actions run with minimal `permissions:`
  scoped per workflow; the daily freshness job only commits `status.json`.
- **Secret hygiene.** API keys (e.g. the safety-feed keys) exist only as
  encrypted GitHub Actions secrets — never committed. Secret scanning with push
  protection is enabled.
- **Dependencies.** Dependabot alerts and security updates are enabled.
- **Accounts.** Two-factor authentication is required for maintainers and the
  organisation.

## Maintainer hardening checklist

A quick reference for anyone maintaining a fork or the main repos:

1. Enable **secret scanning + push protection** (Settings → Code security).
2. Enable **Dependabot** alerts + security updates (grouped).
3. Protect `main`: block **force-push** and **deletion**; protect release tags.
4. Set Actions to **least privilege**; require approval for workflows from
   outside collaborators; prefer pinning third-party actions.
5. Require **2FA** for all org members; keep 2FA **recovery codes** offline and
   add a **passkey/security key**.
6. Push over **SSH** (or a **fine-grained** PAT scoped to these repos only).
7. Sign commits (SSH signing) and enable **Vigilant mode**.

---

_Licences: catalog database under ODbL 1.0, site content under CC BY-SA 4.0, code
under MIT — see [`/licenses.html`](https://osintresourceshub.com/licenses.html)._
