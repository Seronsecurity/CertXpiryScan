"""
FATHOM — HTML report.

Renders a FATHOM report dict into a standalone, print-friendly assessment
document: executive verdict, fleet summary, the sonar depth chart, prioritized
actions with recommendations, the full inventory, methodology, and disclaimers.

Light/paper layout for credibility and clean printing, with the dark sonar
chart embedded as a hero panel so the iceberg signature carries through.
Self-contained — one HTML file, no external assets required (web fonts degrade
gracefully).
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

VERSION = "0.1.0"
SITE = "https://neatlabs.ai"

# tier colors tuned for a light background
TIER_HEX = {"critical": "#d83a4a", "high": "#e0772a", "medium": "#c2900f",
            "low": "#2a9d8f", "ok": "#12a98f"}
TIER_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "ok": "OK"}
# dark-panel tier colors (sonar)
TIER_PING = {"critical": "#ff5d6c", "high": "#f5893e", "medium": "#f5c451",
             "low": "#73d7c7", "ok": "#45f0d0"}
SOURCE_LABEL = {"seed": "given", "ct": "CT logs", "san": "cert SANs",
                "dns-brute": "DNS brute"}


def _e(s):
    return html.escape(str(s if s is not None else ""))


def _hashx(s):
    h = 2166136261
    for ch in str(s):
        h ^= ord(ch); h = (h * 16777619) & 0xffffffff
    return (h % 1000) / 1000.0


def _fmt_days(d):
    if d is None:
        return "—"
    return f"{abs(d)}d ago" if d < 0 else f"{d}d"


def _recommendation(c):
    a = c["assessment"]
    dr = a["days_remaining"]
    if dr is not None and dr < 0:
        return "Replace immediately — the service may already be failing TLS."
    if a["service"] and not a["is_web"] and (c.get("self_signed") or a["issuer_class"] != "acme"):
        return ("No automated renewal path. Assign an owner and stand up ACME/managed "
                "renewal, or schedule manual replacement before the next phase.")
    if dr is not None and dr <= 30:
        return f"Renew within {dr} days; confirm who owns this renewal."
    if c.get("self_signed"):
        return "Self-signed — move to a managed CA or document an internal renewal process."
    if a["issuer_class"] == "manual":
        return "Manual-purchase certificate; automate before the 2027 (100-day) cap makes the cadence unworkable."
    if a["dies_at_phase2"]:
        return "Validity exceeds the 2027 cap. Shorten the renewal cycle / automate ahead of March 2027."
    return "Monitor; no immediate action required."


def _sonar_svg(certs, below_pct, small_sample, total):
    W, H, WL, FLOOR = 1000, 460, 96, 430
    bands = [(WL, WL + (FLOOR - WL) * 0.25, "2026", "Phase 1 · 200-day · live now"),
             (WL + (FLOOR - WL) * 0.25, WL + (FLOOR - WL) * 0.50, "2027", "Phase 2 · 100-day"),
             (WL + (FLOOR - WL) * 0.50, WL + (FLOOR - WL) * 0.74, "2029", "Phase 3 · 47-day"),
             (WL + (FLOOR - WL) * 0.74, FLOOR, "\u221e", "Abyss · self-signed / unmanaged")]
    g = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
         f'font-family="JetBrains Mono, monospace">']
    g.append('<defs><linearGradient id="w" x1="0" y1="0" x2="0" y2="1">'
             '<stop offset="0" stop-color="#0a4254" stop-opacity=".55"/>'
             '<stop offset="1" stop-color="#020c11"/></linearGradient></defs>')
    g.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="#03141b"/>')
    g.append(f'<rect x="0" y="{WL}" width="{W}" height="{FLOOR-WL}" fill="url(#w)"/>')
    g.append(f'<rect x="0" y="0" width="{W}" height="{WL}" fill="#7df0ff" opacity=".03"/>')
    for y0, y1, yr, lab in bands:
        g.append(f'<line x1="0" y1="{y1:.0f}" x2="{W}" y2="{y1:.0f}" stroke="#45f0d0" stroke-opacity=".10"/>')
        g.append(f'<text x="14" y="{y0+16:.0f}" font-size="10.5" letter-spacing=".5" '
                 f'fill="#7fa1ad">{lab}</text>')
        g.append(f'<text x="{W-14}" y="{y0+20:.0f}" font-size="13" text-anchor="end" '
                 f'fill="#7fa1ad" opacity=".5" font-family="Space Grotesk, sans-serif" '
                 f'font-weight="700">{yr}</text>')
    # hero stat
    g.append('<text x="18" y="30" font-size="11" letter-spacing="1.5" fill="#7fa1ad">BELOW THE WATERLINE</text>')
    g.append(f'<text x="16" y="68" font-size="40" font-weight="700" fill="#45f0d0" '
             f'font-family="Space Grotesk, sans-serif">{below_pct}%</text>')
    if small_sample:
        g.append(f'<text x="18" y="{FLOOR-8:.0f}" font-size="10" fill="#f5c451">'
                 f'\u26a0 percentage over a small sample (n={total})</text>')
    # waterline
    g.append(f'<line x1="0" y1="{WL}" x2="{W}" y2="{WL}" stroke="#7df0ff" stroke-width="1.4" stroke-opacity=".8"/>')
    g.append(f'<text x="{W-14}" y="20" font-size="10" text-anchor="end" fill="#4f7681">'
             f'depth = how soon it dies · size = risk</text>')
    # contacts
    for i, c in enumerate(certs):
        a = c["assessment"]
        above = a["above_waterline"]
        hx = _hashx((c.get("fingerprint_sha256") or c["host"]) + str(c["port"]))
        if above:
            x = W * 0.42 + hx * (W * 0.52)
            y = 24 + _hashx(c["host"] + str(i)) * (WL - 48)
        else:
            x = 36 + hx * (W - 72)
            y = WL + 14 + a["depth"] * (FLOOR - WL - 24)
        r = 4 + (a["score"] / 100) * 8
        col = TIER_PING[a["tier"]]
        if a["tier"] == "critical":
            g.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r+7:.1f}" fill="{col}" opacity=".16"/>')
        g.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{col}" '
                 f'fill-opacity=".88" stroke="{col}" stroke-opacity=".5"/>')
    g.append('</svg>')
    return "".join(g)


def _bar(summary):
    t = summary["tiers"]; total = summary["total"] or 1
    order = ["critical", "high", "medium", "low", "ok"]
    seg = []
    for k in order:
        if t.get(k):
            pct = t[k] / total * 100
            seg.append(f'<span style="width:{pct:.2f}%;background:{TIER_HEX[k]}" '
                       f'title="{TIER_LABEL[k]}: {t[k]}"></span>')
    return f'<div class="bar">{"".join(seg)}</div>'


def render_html(report: dict) -> str:
    s = report["summary"]
    v = report.get("verdict") or {}
    certs = report["certs"]
    disc = report.get("discovery")
    cp = s["current_phase"]
    now = datetime.now(UTC)
    vcol = TIER_HEX.get(v.get("color"), "#5a7682") if v.get("color") in TIER_HEX else {
        "ok": TIER_HEX["ok"], "medium": TIER_HEX["medium"], "high": TIER_HEX["high"],
        "critical": TIER_HEX["critical"], "haze": "#5a7682", "none": "#5a7682"}.get(v.get("color"), "#5a7682")

    hosts = len({c["host"] for c in certs})
    scope = (f"{disc['total_hosts']} hosts discovered · {s['total']} certificates"
             if disc else f"{hosts} hosts · {s['total']} certificates")
    prov = ""
    if disc:
        parts = " · ".join(f"{n} {SOURCE_LABEL.get(k, k)}" for k, n in disc["by_source"].items())
        prov = f'<div class="prov">Discovery: {_e(parts)}</div>'

    # priority actions: critical/high/expiring
    pri = [c for c in certs if c["assessment"]["tier"] in ("critical", "high")
           or (c["assessment"]["days_remaining"] is not None and c["assessment"]["days_remaining"] <= 30)]
    pri.sort(key=lambda c: (0 if c["assessment"]["tier"] == "critical" else 1,
                            c["assessment"]["days_remaining"]
                            if c["assessment"]["days_remaining"] is not None else 9999))

    def pri_card(c):
        a = c["assessment"]
        return f"""<div class="action">
          <div class="action-h">
            <span class="host">{_e(c['host'])}<span class="port">:{_e(c['port'])}</span></span>
            <span class="chip" style="background:{TIER_HEX[a['tier']]}1a;color:{TIER_HEX[a['tier']]}">{TIER_LABEL[a['tier']]}</span>
          </div>
          <div class="action-meta">{_e(a['service'])} · {_e((c.get('issuer') or '—').split(' —')[0])} · expires {_fmt_days(a['days_remaining'])} · {'above' if a['above_waterline'] else 'below'} the waterline</div>
          <ul class="reasons">{''.join(f'<li>{_e(r)}</li>' for r in a['reasons'])}</ul>
          <div class="rec"><b>Recommended:</b> {_e(_recommendation(c))}</div>
        </div>"""

    actions_html = ("".join(pri_card(c) for c in pri) if pri
                    else '<div class="none">No certificates require immediate action.</div>')

    # full inventory rows
    def inv_row(c):
        a = c["assessment"]; dr = a["days_remaining"]
        drcls = "neg" if (dr is not None and dr < 0) else ("soon" if (dr is not None and dr <= 30) else "")
        return f"""<tr>
          <td class="host">{_e(c['host'])}<span class="port">:{_e(c['port'])}</span></td>
          <td>{_e(a['service'])}</td>
          <td class="muted">{_e((c.get('issuer') or '—').split(' —')[0])}</td>
          <td class="{'below' if not a['above_waterline'] else ''}">{'▼ below' if not a['above_waterline'] else '▲ above'}</td>
          <td class="num">{a['validity_days'] if a['validity_days'] is not None else '—'}d</td>
          <td class="num {drcls}">{_fmt_days(dr)}</td>
          <td class="num"><span class="chip" style="background:{TIER_HEX[a['tier']]}1a;color:{TIER_HEX[a['tier']]}">{TIER_LABEL[a['tier']]}</span></td>
        </tr>"""

    inv_html = "".join(inv_row(c) for c in certs)

    stats = [
        ("certificates", s["total"], "ink"),
        ("below waterline", f"{s['below_waterline']} ({s['below_waterline_pct']}%)", "deep"),
        ("critical", s["tiers"]["critical"], "crit"),
        ("expired", s["expired"], "crit"),
        ("Oct-2026 cohort", s["october_cohort"], "warn"),
        ("cadence breaks · 2027", s["breaks_at_phase2"], "warn"),
        ("cadence breaks · 2029", s["breaks_at_phase3"], "warn"),
    ]
    if s.get("weak_key"):
        stats.append(("weak keys", s["weak_key"], "crit"))
    if s.get("legacy_sig"):
        stats.append(("legacy signatures", s["legacy_sig"], "crit"))
    stat_html = "".join(
        f'<div class="stat {cls}"><div class="v">{_e(val)}</div><div class="k">{_e(k)}</div></div>'
        for k, val, cls in stats)

    phases = [("pre-2026", 398, 398, ""), ("Mar 2026", 200, 200, "s200"),
              ("Mar 2027", 100, 100, "s100"), ("Mar 2029", 47, 10, "s47")]
    phase_html = "".join(
        f'<div class="ph {"now" if cp["max_validity"]==d else ""}">'
        f'{"<span class=now-tag>LIVE NOW</span>" if cp["max_validity"]==d else ""}'
        f'<div class="yr">{yr}</div><div class="days {cls}">{d}<small> days</small></div>'
        f'<div class="dcv">DCV reuse · {dcv}d</div></div>'
        for yr, d, dcv, cls in phases)

    svg = _sonar_svg(certs, s["below_waterline_pct"], v.get("small_sample", False), s["total"])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NEATLABS&trade; FATHOM — Certificate Phase-Down Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root{{
    --paper:#fbfcfd; --panel:#fff; --ink:#0c2630; --muted:#5a7682; --faint:#8aa3ad;
    --hair:#e3eaed; --deep:#0a3a48; --accent:#12a98f; --water:#0a90b8;
    --crit:#d83a4a; --warn:#c2900f;
    --mono:"JetBrains Mono",ui-monospace,monospace;
    --body:"IBM Plex Sans",system-ui,sans-serif; --display:"Space Grotesk",sans-serif;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--paper);color:var(--ink);font-family:var(--body);
    font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}}
  .page{{max-width:920px;margin:0 auto;padding:0 26px}}
  a{{color:var(--water);text-decoration:none}}

  header.mast{{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;
    flex-wrap:wrap;padding:34px 0 18px;border-bottom:3px solid var(--deep)}}
  .tag{{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--muted)}}
  .logo{{font-family:var(--display);font-weight:700;font-size:34px;letter-spacing:1px;line-height:1}}
  .logo .o{{color:var(--accent)}}
  .doctype{{font-family:var(--mono);font-size:11px;letter-spacing:2px;text-transform:uppercase;
    color:var(--muted);margin-top:6px}}
  .mast-r{{text-align:right;font-family:var(--mono);font-size:12px;color:var(--muted)}}
  .mast-r b{{color:var(--ink);font-weight:500}}
  .prov{{margin-top:3px;color:var(--faint)}}

  section{{padding:26px 0;border-bottom:1px solid var(--hair)}}
  h2{{font-family:var(--mono);font-size:12px;letter-spacing:2.4px;text-transform:uppercase;
    color:var(--accent);margin:0 0 16px}}

  .verdict{{display:flex;gap:16px;align-items:flex-start;padding:18px 20px;border-radius:12px;
    background:#fff;border:1px solid var(--hair);border-left:5px solid var(--muted)}}
  .verdict .dot{{font-size:18px;line-height:1.3}}
  .verdict h3{{font-family:var(--display);font-weight:700;font-size:20px;margin:0 0 3px}}
  .verdict p{{margin:0;color:var(--muted);font-size:14px}}

  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
  .stat{{background:#fff;border:1px solid var(--hair);border-radius:10px;padding:14px 16px}}
  .stat .v{{font-family:var(--display);font-weight:700;font-size:24px;line-height:1}}
  .stat .k{{font-family:var(--mono);font-size:10px;letter-spacing:1px;text-transform:uppercase;
    color:var(--muted);margin-top:7px}}
  .stat.crit .v{{color:var(--crit)}} .stat.warn .v{{color:var(--warn)}} .stat.deep .v{{color:var(--water)}}
  .summary-note{{margin:18px 0 0;color:var(--ink)}}

  .bar{{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--hair);margin:4px 0 12px}}
  .bar span{{display:block;height:100%}}
  .legend{{display:flex;gap:18px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;color:var(--muted)}}
  .legend i{{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:6px;vertical-align:middle}}

  .chartwrap{{border-radius:12px;overflow:hidden;border:1px solid var(--deep);background:#03141b}}
  .chartwrap svg{{display:block;width:100%}}

  .track{{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--hair);
    border-radius:10px;overflow:hidden}}
  .ph{{padding:15px 16px;border-right:1px solid var(--hair);position:relative;background:#fff}}
  .ph:last-child{{border-right:none}}
  .ph.now{{background:#f0f8f9}}
  .ph .yr{{font-family:var(--mono);font-size:11px;color:var(--muted)}}
  .ph .days{{font-family:var(--display);font-weight:700;font-size:28px;margin:3px 0 2px}}
  .ph .days small{{font-size:13px;color:var(--muted);font-weight:500}}
  .ph .dcv{{font-family:var(--mono);font-size:10px;color:var(--faint)}}
  .ph .days.s200{{color:var(--warn)}} .ph .days.s100{{color:#e0772a}} .ph .days.s47{{color:var(--crit)}}
  .ph .now-tag{{position:absolute;top:10px;right:10px;font-family:var(--mono);font-size:8.5px;
    letter-spacing:1.5px;color:var(--accent);border:1px solid var(--accent);border-radius:4px;padding:2px 5px}}

  .action{{border:1px solid var(--hair);border-left:4px solid var(--crit);border-radius:10px;
    padding:14px 16px;margin-bottom:12px;background:#fff;break-inside:avoid}}
  .action-h{{display:flex;justify-content:space-between;align-items:center;gap:12px}}
  .action-meta{{font-family:var(--mono);font-size:11.5px;color:var(--muted);margin:5px 0 8px}}
  .host{{font-family:var(--mono);font-weight:500}}
  .port{{color:var(--faint)}}
  .chip{{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.5px;
    padding:3px 8px;border-radius:5px;text-transform:uppercase}}
  .reasons{{margin:0 0 8px;padding-left:18px;color:var(--ink)}}
  .reasons li{{margin:2px 0;font-size:13px}}
  .rec{{font-size:13px;color:var(--ink);background:#f4f8f9;border-radius:7px;padding:8px 11px}}
  .rec b{{color:var(--accent)}}
  .none{{color:var(--muted);font-style:italic}}

  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead th{{font-family:var(--mono);font-size:9.5px;letter-spacing:1px;text-transform:uppercase;
    color:var(--muted);text-align:left;padding:8px 10px;border-bottom:2px solid var(--hair)}}
  thead th.num{{text-align:right}}
  tbody td{{padding:9px 10px;border-bottom:1px solid var(--hair)}}
  td.num{{text-align:right;font-family:var(--mono)}}
  td.muted{{color:var(--muted)}}
  td.below{{color:#e0772a;font-family:var(--mono);font-size:11px}}
  td .port{{color:var(--faint)}}
  td.num.neg{{color:var(--crit);font-weight:600}} td.num.soon{{color:#e0772a;font-weight:600}}

  .fine{{font-size:12.5px;color:var(--muted)}}
  .fine p{{margin:0 0 9px}} .fine b{{color:var(--ink)}}
  footer{{padding:24px 0 60px;font-family:var(--mono);font-size:11px;color:var(--faint);
    display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}}

  @media print{{
    body{{font-size:12px}}
    *{{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
    section{{break-inside:avoid}} .action{{break-inside:avoid}}
    .stats{{grid-template-columns:repeat(4,1fr)}}
    footer{{position:fixed;bottom:0}}
  }}
  @media (max-width:680px){{ .stats,.track{{grid-template-columns:repeat(2,1fr)}} }}
</style></head>
<body><div class="page">

  <header class="mast">
    <div>
      <div class="tag">NEATLABS&trade;</div>
      <div class="logo">FATH<span class="o">O</span>M</div>
      <div class="doctype">Certificate Phase-Down Assessment</div>
    </div>
    <div class="mast-r">
      <div>{_e(scope)}</div>
      <div>schedule · <b>CA/Browser Forum SC-081v3</b></div>
      <div>current · <b>{_e(cp['label'])}</b></div>
      <div>generated · <b>{now.strftime('%Y-%m-%d %H:%M UTC')}</b></div>
      {prov}
    </div>
  </header>

  <section>
    <h2>Bottom line</h2>
    <div class="verdict" style="border-left-color:{vcol}">
      <span class="dot" style="color:{vcol}">●</span>
      <div><h3 style="color:{vcol}">{_e(v.get('headline','—'))}</h3>
      <p>{_e(v.get('detail',''))}</p></div>
    </div>
  </section>

  <section>
    <h2>Executive summary</h2>
    <div class="stats">{stat_html}</div>
    <p class="summary-note">Of {s['total']} certificate(s) sounded, <b>{s['below_waterline']}
    ({s['below_waterline_pct']}%)</b> sit below the waterline — no host automation will renew them.
    {s['tiers']['critical']} are critical and {s['expired']} have already expired. As the CA/Browser
    Forum phase-down tightens, <b>{s['breaks_at_phase2']}</b> certificate(s) will outlive the 2027
    (100-day) cap and <b>{s['breaks_at_phase3']}</b> the 2029 (47-day) cap on their current cadence.</p>
  </section>

  <section>
    <h2>Fleet by depth</h2>
    <div class="chartwrap">{svg}</div>
  </section>

  <section>
    <h2>Risk distribution</h2>
    {_bar(s)}
    <div class="legend">
      <span><i style="background:{TIER_HEX['critical']}"></i>Critical {s['tiers']['critical']}</span>
      <span><i style="background:{TIER_HEX['high']}"></i>High {s['tiers']['high']}</span>
      <span><i style="background:{TIER_HEX['medium']}"></i>Medium {s['tiers']['medium']}</span>
      <span><i style="background:{TIER_HEX['low']}"></i>Low {s['tiers']['low']}</span>
      <span><i style="background:{TIER_HEX['ok']}"></i>OK {s['tiers']['ok']}</span>
    </div>
  </section>

  <section>
    <h2>The phase-down · maximum certificate validity</h2>
    <div class="track">{phase_html}</div>
  </section>

  <section>
    <h2>Priority actions</h2>
    {actions_html}
  </section>

  <section>
    <h2>Full inventory · {s['total']} certificate(s)</h2>
    <table>
      <thead><tr>
        <th>Host</th><th>Service</th><th>Issuer</th><th>Waterline</th>
        <th class="num">Validity</th><th class="num">Expires</th><th class="num">Risk</th>
      </tr></thead>
      <tbody>{inv_html}</tbody>
    </table>
  </section>

  <section class="fine">
    <h2>Methodology &amp; scope</h2>
    <p><b>Discovery.</b> Domains are expanded via Certificate Transparency logs (crt.sh) and
    certificate Subject Alternative Names; candidates are filtered by DNS resolution. IP and CIDR
    targets are scanned directly.</p>
    <p><b>Sounding.</b> FATHOM connects to each responsive TLS port (web, mail, directory, remote
    access, database) and reads the presented certificate. It is read-only and never issues,
    modifies, or deletes certificates.</p>
    <p><b>Waterline.</b> A certificate is "above the waterline" when it is a web certificate on an
    automated short cycle (an ACME issuer, or a publicly trusted ≤100-day certificate). Everything
    else — machine identities with no host automation — sits below.</p>
    <p><b>Scoring.</b> Risk reflects expiry pressure, automation posture, port exposure, and the
    CA/Browser Forum phase-down (SC-081v3: 398 → 200 → 100 → 47-day validity through March 2029).
    Tiers and the auto-renew inference are prioritization aids, not guarantees.</p>
  </section>

  <section class="fine">
    <h2>Disclaimers</h2>
    <p><b>Authorized use only.</b> This assessment must be run only against domains, hosts, and
    networks owned by, or with explicit written permission from, the assessed party.</p>
    <p><b>Heuristics, not guarantees.</b> Verify findings before acting. Discovery completeness
    depends on third-party data (crt.sh) and DNS, which may be incomplete or unavailable.</p>
    <p><b>Not legal or compliance advice.</b> Confirm current certificate requirements with your
    certificate authority.</p>
  </section>

  <footer>
    <span>NEATLABS&trade; FATHOM v{VERSION} · read-only certificate assessment</span>
    <span><a href="{SITE}">neatlabs.ai</a> · github.com/neatlabs-ai</span>
  </footer>

</div></body></html>"""
