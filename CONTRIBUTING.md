# Contributing to FATHOM

Thanks for your interest. FATHOM is a free NEATLABS™ tool and contributions are
welcome.

## Development setup

```bash
git clone https://github.com/neatlabs-ai/fathom
cd fathom
python -m venv .venv && source .venv/bin/activate
pip install -e ".[gui,dev]"
```

## Before you open a PR

```bash
ruff check fathom/ tests/      # lint (house style allows compact one-liners)
pytest -q                      # tests run fully offline — no network needed
```

Please add or update tests for any behavior change. The suite is pure-logic and
mocks the network (CT lookups, DNS, scanning), so it stays fast and hermetic.

## Architecture

One engine, four faces:

- `fathom/scanner.py` — async TLS certificate harvester (web + STARTTLS).
- `fathom/analyzer.py` — SC-081v3 scoring, the waterline rule, and the verdict.
- `fathom/discovery.py` — Certificate Transparency, SAN pivot, DNS, orchestration.
- `fathom/report.py` — standalone HTML report renderer.
- `fathom/cli.py` — command line.
- `fathom/gui.py` — native PyQt6 desktop app.
- `fathom/assets/` — the web dashboard template and a sample report.

## Things worth tuning

- **Issuer classification** lives in two lists in `analyzer.py`
  (`ACME_ISSUER_MARKERS`, `MANUAL_CA_MARKERS`). As you see real fleets, these are
  the first place to refine. The waterline rule also treats any publicly trusted
  ≤100-day web cert as automated, which is a heuristic — improvements welcome.
- **Port map** (`analyzer.PORT_SERVICE`) and **default ports** (`scanner.DEFAULT_PORTS`).
- **DNS brute wordlist** (`discovery.WORDLIST`).

## Ground rules

- Keep it read-only. FATHOM must never issue, modify, or delete certificates.
- HTML-escape any certificate-supplied string before rendering it.
- Be conservative about anything that could enable unauthorized scanning.
