# BASED ON NEATLABS™ FATHOM

**Certificate depth sounding for the CA/Browser Forum phase-down.**


> ⚠️ **Authorized use only.** Run only against domains, hosts, and networks you own or have explicit written permission to assess. The scan and optional brute passes make active connections to the targets. See [SECURITY.md](SECURITY.md).

---

## Why

The hard part isn't renewing certificates, **it's discovering every certificate** Mail servers, LDAP/AD, load balancers, VPN concentrators, RDP hosts, databases, appliances, internal services. Machine identities on ports no host control panel ever touches. Nobody has an inventory. The org finds out the cert existed when the thing it lived on falls over.


## What it does

- **Discovers** hosts you can't name — Certificate Transparency logs, certificate SAN pivoting, and an opt-in DNS brute pass — then sounds the certificate on every responsive TLS port, not just 443 (direct TLS plus STARTTLS for mail).
- **Scores** each cert against the real SC-081v3 schedule: expiry pressure, automation posture (ACME vs manual-purchase vs self-signed), the Oct-2026 cohort, and which certs' validity periods break their renewal cadence at the 2027 and 2029 caps.
- **Classifies** each cert as *above* or *below the waterline* — whether anything is realistically going to renew it for you.
- **Reports** a board-readable verdict and an iceberg/sonar view of the fleet by depth and risk, plus a sortable inventory, a polished HTML report, and JSON for whoever does the remediation.

## What it does **not** do

It does not touch, issue, or modify certificates. It reads what's there and tells you what dies and when. Read-only by design.

## Enhancements


> **v0.2 engine.** The scanner is now native `asyncio` (no thread pool) and grabs
> each certificate in a single connection — validating trust in-process from the
> chain the server presents instead of opening a second verifying handshake. The
> result is roughly **2× faster, half the connections against your targets, and a
> flat ~2-thread footprint** at any concurrency. Certificate Transparency lookups
> run in parallel and are cached on disk, so repeat discovery runs are near-instant.
> See [CHANGES.md](CHANGES.md).

## Use

Type targets in the bar, set ports (raw numbers and/or the same presets the CLI takes — `web`, `mail`, `dir`, `db`, `remote`, `all` — or keep the defaults), tick **discover** to expand subdomains, hit **SOUND**. Contacts plot by depth (how soon they die) and size (risk); click any contact to jump to its row, or select a row to ring its contact. Hosts with a weak key or legacy (MD5/SHA-1) signature are flagged with a ⚠ in the table and the chart tooltip. **EXPORT REPORT** writes the HTML report; **EXPORT JSON** writes the raw data. **? QUICK START** has the full how-to and disclaimers.


## Discovery — find the hosts you can't name

The hardest part of the phase-down isn't renewing certs, it's *knowing they exist*. You can't type in a subdomain you've forgotten. `--discover` finds them for you:

```bash
# expand a domain via Certificate Transparency + certificate SANs, then sound everything
python -m fathom.cli scan neatlabs.ai --discover --report

# add a common-subdomain DNS brute pass for internal names that never got a public cert
python -m fathom.cli scan neatlabs.ai --brute
```

## Three layers

- **Certificate Transparency (crt.sh)** — every publicly trusted cert ever issued is logged in public. One passive query for your domain returns every subdomain ever certified.
- **SAN pivot** — names listed inside the certs become new targets, but restricted.
- **DNS brute** (`--brute`, opt-in) — a small wordlist of common prefixes (www, mail, vpn, api, dev, admin…) for internal names with no public cert.

Each host in the report is tagged with where it came from (`given`, `CT logs`, `cert SANs`, `DNS brute`). 

IP and CIDR seeds and are scanned directly. Certificates secure specific endpoints, not ranges. There's no "wildcard for IP ranges"

## Report

Produce a polished, standalone assessment document — executive verdict, fleet summary, the sonar depth chart, prioritized actions with recommendations, full inventory, methodology, and disclaimers. Light, print-friendly layout (save to PDF from the browser), self-contained in one file.

```bash
# scan and write an HTML report alongside the JSON
python -m fathom.cli scan neatlabs.ai --discover --html

# render a report from a JSON you already have
python -m fathom.cli report fathom-report.json -o assessment.html
```

In the GUI, click **EXPORT REPORT** for HTML, or **EXPORT JSON** for the raw data.

## Use (CLI)

```bash
# scan a few hosts and open the dashboard
python -m fathom.cli scan example.com mail.example.com --report

# scan a network range and a target file, custom ports
python -m fathom.cli scan 10.0.0.0/24 -f targets.txt \
    --ports 443,465,587,993,636,3389,5432 --out fleet.json

# open the dashboard for an existing report
python -m fathom.cli view fleet.json
```

Default ports cover web, mail, directory, and remote-access: `443, 8443, 465, 587, 993, 995, 25, 636, 990, 3389`.

`--ports` also accepts named presets, alone or mixed with raw numbers:

```bash
# named presets: web, mail, dir, db, remote, all
python -m fathom.cli scan example.com --ports web,mail
python -m fathom.cli scan 10.0.0.0/24 --ports db,3389,5061

# also write a flat CSV inventory; --no-cache bypasses the CT disk cache
python -m fathom.cli scan example.com --discover --csv inventory.csv --no-cache

# cap SANs stored per cert (default 100); 0 keeps them all (for SAN-heavy CDN certs)
python -m fathom.cli scan example.com --discover --max-sans 0
```

This now also flags **weak keys** (RSA&lt;2048, EC&lt;256, DSA) and **legacy signatures** (MD5/SHA-1) on every cert it finds.

## The waterline

A cert rides **above the waterline** when it's a web cert on an automated short cycle — an ACME issuer, or a publicly trusted ≤100-day certificate (the ACME/managed signature). Everything else sinks:

- a DigiCert cert bought and pasted into nginx by hand → below
- a Sectigo cert on your IMAP server → below
- a self-signed cert on an RDP host or a database → the abyss

Depth is a blend of automation posture, port obscurity, self-signing, and risk score. The deeper it sits, the less likely anyone renews it in time.

> The "auto-renewing" inference is a heuristic for prioritization, not proof. Verify before acting.

## Output

- `fathom-report.json` — full inventory + per-cert assessment + fleet summary + verdict.
- The **HTML report** — a standalone, print-friendly assessment document.
- The **web dashboard** (`fathom/assets/dashboard.html`) renders the JSON. `--report` / `view` injects your data and opens it; open the file standalone and it shows a sample fleet.


## Tests

```bash
pip install -e ".[dev]"
ruff check fathom/ tests/
pytest -q
```

The suite is hermetic — it mocks the network (CT lookups, DNS, scanning), so it runs offline and fast.

## Caveats

- Risk tiers and the auto-renew inference are prioritization aids, not guarantees.
- Not legal or compliance advice — confirm current requirements with your certificate authority.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it.

## Original Code built by NEATLABS_™_
*Others talk about it. NEATLABS™ is about it.* · [neatlabs.ai](https://neatlabs.ai)
