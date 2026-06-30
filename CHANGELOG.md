# Changelog

All notable changes to FATHOM are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-06-29

Security hardening from a full code audit. See [CHANGES.md](CHANGES.md) for detail.

### Security
- **Fixed a stored XSS (HIGH, present since 0.1.0):** the web dashboard embedded
  report JSON into a `<script>` element without escaping `<>&`, so a certificate
  field (read from untrusted hosts) containing `</script>…` could run arbitrary
  JavaScript when the operator opened the dashboard. JSON is now escaped for the
  HTML script context. The standalone HTML report was never affected.
- Dashboard now writes to a private `mkstemp` file (0600) instead of a fixed name
  in shared `/tmp`; the CT cache moved to a per-user `0700` directory with an
  ownership check (no shared-/tmp pre-seeding, symlink, or info-leak).
- CSV export neutralizes spreadsheet formula injection (`= + - @` …).
- CT cache re-validates hostnames on read.

### Changed
- `expand_targets` caps expansion (~/16) and fails fast on a `/8` instead of
  exhausting memory; `resolve_ports` rejects ports outside 1–65535. The CLI
  reports both as clean errors (exit 2).

## [0.2.0] — 2026-06-28

Engine rewrite — faster, lighter, more accurate. See [CHANGES.md](CHANGES.md) for
the full rationale and head-to-head measurements.

### Changed
- **Scanner** rebuilt on native `asyncio` (no thread pool). Each certificate is
  harvested in a single connection, with trust validated **in-process** from the
  presented chain (Python 3.13+) instead of a second verifying handshake. Result:
  ~2× faster on healthy fleets, half the connections to targets, and a flat
  ~2-thread footprint at any concurrency.
- **Discovery** runs Certificate Transparency lookups in parallel and caches them
  on disk with a TTL, so repeat runs skip the network (~300× faster).
- `requires-python` raised to `>=3.11`.

### Added
- Weak-key (RSA<2048 / EC<256 / DSA) and legacy-signature (MD5/SHA-1) detection,
  scored and surfaced in the report, CSV, and summary.
- CLI `--csv`, `--no-cache`, and named `--ports` presets (web/mail/dir/db/remote/all).
- Cert records carry `key_type`, `key_bits`, `sig_algo` (schema additions are
  backward compatible — the dashboard and HTML report are unchanged).
- Test suite expanded to 34 hermetic tests.

## [0.1.0] — 2026-06-27

Initial public release.

### Added
- **Scanner** — async TLS certificate harvesting across web and machine-identity
  ports (HTTPS, mail with STARTTLS, LDAPS, RDP, databases, and more).
- **Analyzer** — risk scoring against the CA/Browser Forum SC-081v3 phase-down
  (398 → 200 → 100 → 47-day validity through March 2029), the "waterline"
  classification (auto-renewing vs unmanaged), and a board-readable verdict.
- **Discovery** — Certificate Transparency (crt.sh) subdomain enumeration,
  certificate SAN pivoting (scope-bounded), and an opt-in DNS brute pass, all
  DNS-resolution filtered and deduplicated.
- **Four interfaces** — command line, an interactive web dashboard, a native
  PyQt6 desktop GUI, and a standalone, print-friendly HTML report.
- Quick Start / Help panel and disclaimers in the GUI.

### Security
- All certificate-supplied strings (issuer, subject, SANs) are HTML-escaped
  before rendering in the dashboard, the HTML report, and GUI tooltips, to
  prevent script injection from a malicious endpoint.
- Discovery hostnames are validated against a strict pattern and CT result size
  is capped.
