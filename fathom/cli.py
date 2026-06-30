"""
FATHOM — command line.

    fathom scan example.com 10.0.0.0/24 --out report.json
    fathom scan -f targets.txt --ports 443,465,993,636 --report
    fathom view report.json          # open the dashboard on an existing report

A free NEATLABS tool. Find the certificates that die below the waterline
before the CA/Browser Forum phase-down finds them for you.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import webbrowser
from pathlib import Path

from . import analyzer, discovery, scanner
from . import report as report_html

BANNER = r"""
   ___      _   _
  | __|__ _| |_| |_  ___ _ __    FATHOM
  | _/ _` |  _| ' \/ _ \ '  \   certificate depth sounding
  |_|\__,_|\__|_||_\___/_|_|_|  neatlabs / open source
"""

DASHBOARD = Path(__file__).resolve().parent / "assets" / "dashboard.html"

# port presets + parsing live in the engine so the CLI and GUI share one impl.
PORT_PRESETS = scanner.PORT_PRESETS
_resolve_ports = scanner.resolve_ports  # dedupe, keep order


def _bar(done, total, host, port):
    width = 28
    filled = int(width * done / total) if total else width
    sys.stderr.write(
        f"\r  sounding [{'='*filled}{' '*(width-filled)}] {done}/{total}  {host}:{port}      "
    )
    sys.stderr.flush()


# the report builder lives in analyzer now (shared by the CLI and the GUI)
build_report = analyzer.build_report


def _csv_safe(v):
    """Neutralize CSV/spreadsheet formula injection. A cert-supplied string that
    starts with a formula trigger (= + - @, or a leading tab/CR) is prefixed with
    a single quote so a spreadsheet treats it as text, not a formula. Numeric and
    boolean cells are left untouched (no injection risk, keeps negatives intact)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return "" if v is None else v


def _to_csv(report: dict) -> str:
    import csv
    import io

    cols = ["host", "port", "service", "tier", "score", "above_waterline",
            "issuer", "issuer_class", "subject_cn", "not_after", "days_remaining",
            "validity_days", "self_signed", "chain_trusted", "key_type", "key_bits",
            "sig_algo", "weak_key", "legacy_sig"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for c in report.get("certs", []):
        a = c.get("assessment", {})
        row = {**c, **a}
        w.writerow([_csv_safe(row.get(k, "")) for k in cols])
    return buf.getvalue()


def _read_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.file:
        targets += Path(args.file).read_text(encoding="utf-8").splitlines()
    return [t for t in targets if t.strip()]


def _json_for_html(data) -> str:
    """Serialize data for safe embedding inside an HTML <script> element.

    json.dumps does NOT escape <, >, & — so a certificate field containing
    "</script>" would break out of the script element and inject markup (the data
    comes from untrusted, possibly hostile hosts). Escaping these to \\uXXXX keeps
    the JSON valid and decodes back to the same characters in the browser."""
    s = json.dumps(data)
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                    ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        s = s.replace(ch, esc)
    return s


def _render_dashboard(report_path: Path) -> str:
    html = DASHBOARD.read_text(encoding="utf-8")
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    return html.replace("/*__FATHOM_DATA__*/null/*__END__*/", _json_for_html(data))


def serve_dashboard(report_path: Path):
    """Inject the report into the dashboard and open it in a browser."""
    injected = _render_dashboard(report_path)
    # A private, unpredictable temp file (0600) — not a fixed name in shared /tmp,
    # which a local user could pre-create/symlink or read.
    fd, name = tempfile.mkstemp(prefix="fathom-dashboard-", suffix=".html")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(injected)
    out = Path(name)
    print(f"\n  dashboard → {out}")
    try:
        webbrowser.open(out.as_uri())
    except Exception:
        print("  (open the file above in your browser)")


def cmd_scan(args):
    print(BANNER, file=sys.stderr)
    targets = _read_targets(args)

    provenance = None
    max_sans = None if args.max_sans == 0 else args.max_sans  # 0 = unlimited
    try:
        ports = _resolve_ports(args.ports)
        if args.discover or args.brute:
            def say(m):
                sys.stderr.write(f"  · {m}\n"); sys.stderr.flush()
            records, provenance = asyncio.run(discovery.sound(
                targets, ports=ports, timeout=args.timeout, concurrency=args.concurrency,
                use_ct=args.discover or args.brute, use_brute=args.brute,
                resolve=not args.no_resolve, cache=not args.no_cache,
                progress=None if args.quiet else _bar, say=say, max_sans=max_sans))
            sys.stderr.write("\n")
        else:
            records = asyncio.run(scanner.scan(
                targets, ports=ports, timeout=args.timeout,
                concurrency=args.concurrency, progress=None if args.quiet else _bar,
                max_sans=max_sans))
            sys.stderr.write("\n")
    except ValueError as e:
        print(f"\n  error: {e}", file=sys.stderr)
        sys.exit(2)

    report = build_report(records)
    if provenance:
        report["discovery"] = discovery.provenance_summary(provenance)
    s = report["summary"]
    v = report["verdict"]

    out_path = Path(args.out) if args.out else Path("fathom-report.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n  {v['headline'].upper()} — {v['detail']}")
    if provenance:
        bs = report["discovery"]["by_source"]
        srcs = " · ".join(f"{n} {discovery.SOURCE_LABEL.get(k, k)}" for k, n in bs.items())
        print(f"  Hosts discovered:     {report['discovery']['total_hosts']}  ({srcs})")
    print(f"  Certificates surfaced:{s['total']}")
    print(f"  Below the waterline:  {s['below_waterline']}  ({s['below_waterline_pct']}%)")
    print(f"  Critical / Expired:   {s['tiers']['critical']} / {s['expired']}")
    print(f"  Cadence breaks @2027: {s['breaks_at_phase2']}    @2029: {s['breaks_at_phase3']}")
    if s.get("weak_key") or s.get("legacy_sig"):
        print(f"  Weak key / Legacy sig:{s.get('weak_key', 0)} / {s.get('legacy_sig', 0)}")
    print(f"\n  Report written → {out_path}")

    if args.csv:
        csv_path = Path(args.csv)
        csv_path.write_text(_to_csv(report), encoding="utf-8")
        print(f"  CSV written   → {csv_path}")

    if args.html is not None:
        html_path = Path(args.html) if args.html else out_path.with_suffix(".html")
        html_path.write_text(report_html.render_html(report), encoding="utf-8")
        print(f"  HTML report   → {html_path}")
        if args.report:
            try:
                webbrowser.open(html_path.resolve().as_uri())
            except Exception:
                pass

    if args.report and args.html is None:
        serve_dashboard(out_path)


def cmd_report(args):
    rep = json.loads(Path(args.report_json).read_text(encoding="utf-8"))
    out = Path(args.out) if args.out else Path(args.report_json).with_suffix(".html")
    out.write_text(report_html.render_html(rep), encoding="utf-8")
    print(f"  HTML report → {out}")
    if not args.no_open:
        try:
            webbrowser.open(out.resolve().as_uri())
        except Exception:
            pass


def cmd_view(args):
    serve_dashboard(Path(args.report))


def main(argv=None):
    # Windows consoles default to a legacy codepage (cp1252) that can't encode
    # the ·, →, ● glyphs FATHOM prints; force UTF-8 where supported.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    p = argparse.ArgumentParser(
        prog="fathom",
        description="Certificate depth sounding for the CA/Browser Forum phase-down.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan hosts and write a report")
    sc.add_argument("targets", nargs="*", help="hostnames, IPs, or CIDR blocks")
    sc.add_argument("-f", "--file", help="file with one target per line")
    sc.add_argument("--ports", metavar="LIST",
                    help="comma list of ports and/or presets "
                         "(web, mail, dir, db, remote, all). default: web+mail+dir+remote")
    sc.add_argument("--discover", action="store_true",
                    help="expand domains via Certificate Transparency + cert SANs")
    sc.add_argument("--brute", action="store_true",
                    help="also try a common-subdomain DNS wordlist (implies --discover)")
    sc.add_argument("--no-resolve", action="store_true",
                    help="don't drop discovered names that fail DNS resolution")
    sc.add_argument("--no-cache", action="store_true",
                    help="ignore the on-disk Certificate Transparency cache")
    sc.add_argument("--out", help="output JSON path (default fathom-report.json)")
    sc.add_argument("--csv", metavar="PATH", help="also write a CSV inventory")
    sc.add_argument("--html", nargs="?", const="", default=None,
                    metavar="PATH",
                    help="also write a formatted HTML report (optional path)")
    sc.add_argument("--timeout", type=float, default=6.0)
    sc.add_argument("--concurrency", type=int, default=100)
    sc.add_argument("--max-sans", type=int, default=scanner.MAX_SANS, metavar="N",
                    help="max SANs kept per certificate (0 = unlimited; "
                         "default %(default)s)")
    sc.add_argument("--report", action="store_true", help="open dashboard (or HTML report) when done")
    sc.add_argument("--quiet", action="store_true")
    sc.set_defaults(func=cmd_scan)

    rp = sub.add_parser("report", help="render an HTML report from an existing JSON report")
    rp.add_argument("report_json", help="path to a fathom report JSON")
    rp.add_argument("-o", "--out", help="output HTML path (default: alongside the JSON)")
    rp.add_argument("--no-open", action="store_true", help="don't open the report in a browser")
    rp.set_defaults(func=cmd_report)

    vw = sub.add_parser("view", help="open the dashboard for an existing report")
    vw.add_argument("report", help="path to a fathom report JSON")
    vw.set_defaults(func=cmd_view)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
