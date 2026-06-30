# NEATLABS™ FATHOM

**Certificate depth sounding for the CA/Browser Forum phase-down.**
A free NEATLABS™ tool. Find the certificates that die below the waterline — before the 47-day mandate finds them for you.

One read-only engine, four faces: a **command line**, an interactive **web dashboard**, a native **PyQt6 desktop app**, and a standalone **HTML report**.

> ⚠️ **Authorized use only.** Run FATHOM only against domains, hosts, and networks you own or have explicit written permission to assess. The scan and optional brute passes make active connections to the targets. See [SECURITY.md](SECURITY.md).

---

## Why this exists

In April 2025 the CA/Browser Forum passed Ballot **SC-081v3**. The maximum lifetime of a publicly trusted TLS certificate drops on a fixed schedule:

| Date | Max validity | DCV reuse |
|------|-------------:|----------:|
| pre-2026 | 398 days | 398 days |
| **Mar 15, 2026** | **200 days** | 200 days |
| Mar 15, 2027 | 100 days | 100 days |
| Mar 15, 2029 | 47 days | 10 days |

Everyone is building *renewal automation*. That lane is solved — certbot, cert-manager, Cloudflare, and the big hosts already renew the public web automatically. The mom-and-pop website is the **most** automated corner of the whole ecosystem and will mostly be fine.

The part nobody can see is the problem. The hard part isn't renewing — **it's discovering every certificate you actually have.** Mail servers, LDAP/AD, load balancers, VPN concentrators, RDP hosts, databases, appliances, internal services. Machine identities on ports no host control panel ever touches. They don't speak ACME. Nobody has an inventory. The org finds out the cert existed when the thing it lived on falls over.

FATHOM is the sounding line. It measures how deep the iceberg goes.

## What it does

- **Discovers** hosts you can't name — Certificate Transparency logs, certificate SAN pivoting, and an opt-in DNS brute pass — then sounds the certificate on every responsive TLS port, not just 443 (direct TLS plus STARTTLS for mail).
- **Scores** each cert against the real SC-081v3 schedule: expiry pressure, automation posture (ACME vs manual-purchase vs self-signed), the Oct-2026 cohort, and which certs' validity periods break their renewal cadence at the 2027 and 2029 caps.
- **Classifies** each cert as *above* or *below the waterline* — whether anything is realistically going to renew it for you.
- **Reports** a board-readable verdict and an iceberg/sonar view of the fleet by depth and risk, plus a sortable inventory, a polished HTML report, and JSON for whoever does the remediation.

## What it does **not** do

It is **not another ACME renewer.** It does not touch, issue, or modify certificates. It reads what's there and tells you what dies and when. Read-only by design.

## Install

```bash
git clone https://github.com/neatlabs-ai/fathom
cd fathom
pip install -e .            # core (CLI + web dashboard + HTML report)
pip install -e ".[gui]"     # add the desktop GUI (PyQt6)
```

Requires Python 3.11+. The only core dependency is `cryptography`.

> **v0.2 engine.** The scanner is now native `asyncio` (no thread pool) and grabs
> each certificate in a single connection — validating trust in-process from the
> chain the server presents instead of opening a second verifying handshake. The
> result is roughly **2× faster on healthy fleets, half the connections against
> your targets, and a flat ~2-thread footprint** at any concurrency. Certificate
> Transparency lookups run in parallel and are cached on disk, so repeat
> discovery runs are near-instant. See [CHANGES.md](CHANGES.md).

## Desktop GUI

A native PyQt6 app — the sonar iceberg painted in real time, threaded scanning that keeps the window fluid, and two-way selection between the chart and the inventory.

```bash
python -m fathom.gui          # opens with a sample fleet loaded
# or, if installed:  fathom-gui
```

Type targets in the bar, set ports (raw numbers and/or the same presets the CLI takes — `web`, `mail`, `dir`, `db`, `remote`, `all` — or keep the defaults), tick **discover** to expand subdomains, hit **SOUND**. Contacts plot by depth (how soon they die) and size (risk); click any contact to jump to its row, or select a row to ring its contact. Hosts with a weak key or legacy (MD5/SHA-1) signature are flagged with a ⚠ in the table and the chart tooltip. **EXPORT REPORT** writes the HTML report; **EXPORT JSON** writes the raw data. **? QUICK START** has the full how-to and disclaimers.


## Discovery — find the hosts you can't name

The hardest part of the phase-down isn't renewing certs, it's *knowing they exist*. You can't type in a subdomain you've forgotten. `--discover` finds them for you:

```bash
# expand a domain via Certificate Transparency + certificate SANs, then sound everything
python -m fathom.cli scan neatlabs.ai --discover --report

# add a common-subdomain DNS brute pass for internal names that never got a public cert
python -m fathom.cli scan neatlabs.ai --brute
```

Three layers, deduped and DNS-filtered so dead names don't pad the fleet:

- **Certificate Transparency (crt.sh)** — every publicly trusted cert ever issued is logged in public. One passive query for `%.yourdomain` returns every subdomain anyone ever certified, including the box someone stood up years ago and forgot. This is the highest-value, lowest-noise source.
- **SAN pivot** — names listed inside the certs FATHOM harvests become new targets, bounded to your seed domains so it never wanders into unrelated space.
- **DNS brute** (`--brute`, opt-in) — a small wordlist of common prefixes (www, mail, vpn, api, dev, admin…) for internal names with no public cert.

Each host in the report is tagged with where it came from (`given`, `CT logs`, `cert SANs`, `DNS brute`). In the GUI, tick **discover** (and optionally **brute**) before sounding; phase progress streams live.

IP and CIDR seeds skip CT (no domain to query) and are scanned directly — that path covers the internal machine-identity layer regardless of naming.

## HTML report

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

Beyond the phase-down, FATHOM now also flags **weak keys** (RSA&lt;2048, EC&lt;256,
DSA) and **legacy signatures** (MD5/SHA-1) on every cert it sounds.

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

## Project layout

```
fathom/
  scanner.py     async TLS certificate harvester (web + STARTTLS)
  analyzer.py    SC-081v3 scoring, the waterline rule, the verdict
  discovery.py   Certificate Transparency, SAN pivot, DNS, orchestration
  report.py      standalone HTML report renderer
  cli.py         command line
  gui.py         native PyQt6 desktop app
  assets/        web dashboard template + sample report
tests/           offline pytest suite
```

## Tests

```bash
pip install -e ".[dev]"
ruff check fathom/ tests/
pytest -q
```

The suite is hermetic — it mocks the network (CT lookups, DNS, scanning), so it runs offline and fast.

## Caveats

- Discovery completeness depends on third-party data (crt.sh) and DNS, which may be incomplete or temporarily unavailable. FATHOM degrades gracefully.
- Risk tiers and the auto-renew inference are prioritization aids, not guarantees.
- Not legal or compliance advice — confirm current requirements with your certificate authority.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it.

*Others talk about it. NEATLABS™ is about it.* · [neatlabs.ai](https://neatlabs.ai)
