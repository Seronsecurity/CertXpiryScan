**CHANGES**  
Running log of the FATHOM rewrite.  Originals preserved under fathom.orig.bak/ and tests.orig.bak/.  

**Rewrite — engine v2 (in progress)**  
Decision: **stay in Python, rebuild on native ** **asyncio** **.** The workload is  
network-bound (TLS handshakes across many host:port pairs), so the concurrency  
model matters more than the language; native async saturates the network as well  
as Go/Rust here while keeping all four front-ends (CLI, web dashboard, HTML  
report, PyQt6 GUI) and the cryptography dependency.  

**Performance**  
- **scanner**: replaced the ThreadPoolExecutor + blocking-socket design with  
native asyncio (asyncio.open_connection, StreamWriter.start_tls). No more  
100 OS threads at default concurrency.  
- **scanner**: killed the guaranteed double-connect. The old code always opened a  
second TLS connection just to check trust. v2 captures the cert *and* the chain  
in one handshake and validates trust **in-process** (cryptography's path  
verifier on Py3.13+ via get_unverified_chain). One connection per cert in the  
common case; a network fallback only where in-process validation isn't possible.  
- **discovery**: Certificate Transparency lookups now run  **in parallel** across  
seed domains instead of one at a time; DNS resolution uses async getaddrinfo.  
- **discovery**: added an on-disk **CT cache** (TTL) so repeat runs skip crt.sh.  

**Accuracy**  
- In-process chain trust replaces the flaky opportunistic verify probe.  
- Richer issuer classification and self-signed detection; more ports/services.
  
**New features**  
- CLI --csv PATH for a flat inventory;
- --no-cache to bypass the CT cache.  
- --ports now accepts named presets (web, mail, dir, db, remote, all)  
alongside raw port numbers.  
- Weak-key (RSA<2048 / EC<256 / DSA) and legacy-signature (MD5/SHA-1) detection,  
scored and rolled up in the summary, surfaced in the HTML report and CSV.  

**Schema additions (backward compatible)**  
- cert records gain key_type, key_bits, sig_algo.  
- assessments gain weak_key, legacy_sig.  
- summary gains weak_key, legacy_sig counts.  

**Tests**  
- Suite expanded 24 → 34 tests: crypto-hygiene scoring, CT parsing/scope,
 CT-cache round-trip, parallel CT, async scan plumbing, target expansion.  
- pytest scoped to tests/ so the .orig.bak backups aren't collected.  

**Measured results (head-to-head vs the original, same targets)**  
- **~2.35× faster** on a fleet of 10 healthy web hosts (single connection +  
off-loop verification vs the old always-two-connections design).  
- **Half the TCP connections** opened against targets (10 vs 20 for 10 certs) —  
less intrusive, less load on what you're assessing.  
- **~30× fewer OS threads**: peak 2 vs 62 at concurrency 300 (the old design  
spawns one thread per concurrent probe and scales to ~300; the rewrite stays  
flat — this is what lets it scale to thousands of concurrent probes).  
- Pure-timeout (dead host) wall-clock is unchanged — both are bounded by  
timeout × concurrency — but the rewrite gets there on ~2 threads.  
- **CT discovery repeat runs ~300× faster** via the on-disk cache (33s → 0.11s).  

**Front-ends now surface the new signals**  
- **Web dashboard** (assets/dashboard.html): weak-key / legacy-signature counts  
added to the stat strip (shown only when non-zero), a ⚠ badge on flagged hosts  
in the inventory, public-key and signature rows in the per-cert detail, and a  
crypto line in the sounding-chart tooltip. Verified headless with Node against  
the sample fleet (logic runs clean; badge + stat render).  
- **PyQt6 GUI** (gui.py): ⚠ marker on flagged hosts in the inventory table,  
a per-row tooltip with public key / signature / weakness, and a crypto line in  
the chart hover tooltip.  
- **Port presets shared by both interfaces**: the preset table and parser moved  
into the engine (scanner.PORT_PRESETS / scanner.resolve_ports); the CLI and  
the GUI port field now both accept web,mail,dir,db,remote,all mixed with raw  
numbers, from one implementation.  
- **Sample data** (assets/sample-report.json and the dashboard's embedded  
sample) now include key_type/key_bits/sig_algo on every cert, with  
legacy.harborcounty.gov demonstrating an RSA-1024 / SHA-1 cert (high tier),  
so both front-ends showcase the feature on launch. Summaries kept consistent.  

**Security hardening (audit follow-up)**  
Fixes from a full security review. Severities as found:  
**HIGH — dashboard XSS** (pre-existing since v0.1).
Serve_dashboard embedded the report via json.dumps straight into the dashboard's <script> element;  json.dumps doesn't escape <>&, so a cert field containing </script>… executes arbitrary JS when the operator opened the dashboard. Now escaped via _json_for_html (<>& and U+2028/9 →  \uXXXX, still valid JSON). Regression-tested end-to-end.  
- **LOW–MEDIUM — predictable temp files.** The dashboard is now written with  
mkstemp (0600, unpredictable name) instead of a fixed /tmp/fathom_dashboard.html;  
the CT cache moved from shared /tmp/fathom-cache to a per-user dir  
($XDG_CACHE_HOME/~/.cache/fathom) created 0700 with an ownership check,  
so it can't be pre-seeded, symlink-attacked, or read by other local users.  
- **LOW — CSV formula injection** (my v0.2 --csv). Cells starting with  
= + - @ / tab / CR are now prefixed with ' so spreadsheets treat them as  
text. Numeric/boolean cells untouched.  
- **LOW — CT cache trusted its own file** (my v0.2 cache). Names are now  
re-validated against the hostname regex on read, so a tampered cache can't  
inject entries.  
- **Hardening — CIDR expansion cap.** expand_targets refuses target sets above  
 MAX_EXPANDED_HOSTS (~/16) with a clear error instead of OOMing on a /8;  
the CLI reports it cleanly (exit 2). resolve_ports now rejects ports outside  
1–65535.  
- Tests: +9 (34 → 43), covering each fix.  

**Quality / correctness pass (review follow-up)**  
- **CT scope-bleed fixed (correctness):**_parse_ct matched any name *ending*  
*with* the domain, so example.com could admit notexample.com from a shared  
multi-SAN cert. Now exact-suffix on a label boundary (== d or endswith("."+d)),  
matching san_candidates.  
- **Bounded scan worker-pool:** scan() was creating one coroutine per  
host×port up front (hundreds of thousands at the CIDR cap). Now a fixed pool of  
concurrency workers pulls from a lazy pair stream — memory is flat at  
~concurrency, same throughput. Also clamps concurrency≥1 (no Semaphore(0)  
deadlock) and guards timeout>0.  
- **No leaked TLS connections:** probe/_verify_chain_network now close()  
*and*await wait_closed() (bounded), so no "Unclosed transport" warnings.  
Verified live with ResourceWarning promoted to error.  
- **SAN-pivot completeness:** stored-SAN cap raised 12 → 100 (MAX_SANS) so  
multi-SAN certs aren't starved; the dashboard caps the *display* at 24 with a  
"+N more". The cap is **configurable** — scan()/probe()/sound() take a  
max_sans argument (None = unlimited) and the CLI exposes --max-sans N  
(0 = unlimited). The PyQt6 GUI has a matching max-SANs field (0 = unlimited,  
non-negative-int validated) wired through ScanWorker — verified with a  
headless (offscreen) smoke test of the field → worker plumbing.  
- **DRY:** one canonical analyzer.build_report(); the CLI aliases it and the  
GUI calls it (was a duplicated inline copy). Removed now-unused dataclasses  
imports from cli/gui.  
- **Tidy:** STARTTLS+TLS open extracted to _open_tls() (shared by probe and the  
verify fallback); _key_info crypto imports hoisted to module scope.  
- **Empty CT not cached:** a transient [] from crt.sh no longer suppresses  
discovery for the whole TTL.  
- Tests: +5 (43 → 48) covering scope filter, shared builder, bounded pool,  
zero-concurrency, and empty-cache behavior.  

**Files**  
- Rewritten: scanner.py, discovery.py.  
- Enhanced: analyzer.py, cli.py, report.py, gui.py,  
 assets/dashboard.html, assets/sample-report.json,  
 tests/test_fathom.py, pyproject.toml, __init__.py.  
- The report JSON schema stayed backward compatible (additive only).  
