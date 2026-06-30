"""
FATHOM — desktop GUI.

A native PyQt6 instrument for sounding a certificate fleet against the
CA/Browser Forum phase-down. The sonar iceberg is painted with QPainter, not
embedded HTML: contacts plotted by depth (how soon they die) and sized by risk,
a live sweep, and two-way selection between the chart and the inventory table.

    python -m fathom.gui            # opens with a sample fleet loaded
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
from pathlib import Path

from PyQt6.QtCore import (
    QPointF,
    QRectF,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPen,
    QRadialGradient,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from . import analyzer, discovery, scanner
from . import report as report_html

# ---------------------------------------------------------------------------
# palette
# ---------------------------------------------------------------------------
C = {
    "abyss": "#03141b", "deep": "#06222e", "shelf": "#0a3340", "ridge": "#0e4254",
    "line": "#155468", "foam": "#d7eef1", "haze": "#7fa1ad", "dim": "#4f7681",
    "ping": "#45f0d0", "waterline": "#7df0ff",
    "critical": "#ff5d6c", "high": "#f5893e", "medium": "#f5c451",
    "low": "#73d7c7", "ok": "#45f0d0",
}
def col(name, a=255):
    c = QColor(C[name]); c.setAlpha(a); return c

TIER_COL = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "ok": "ok"}

DISPLAY = "Space Grotesk"
MONO = "JetBrains Mono"
BODY = "IBM Plex Sans"

VERSION = "0.1.0"
SITE = "https://neatlabs.ai"


class HelpDialog(QDialog):
    """Quick start, what the readout means, and disclaimers."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NEATLABS\u2122 FATHOM — quick start")
        self.resize(640, 680)
        self.setStyleSheet(f"QDialog {{ background:{C['abyss']}; }}")
        lay = QVBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0)
        view = QTextBrowser()
        view.setOpenExternalLinks(True)
        view.setHtml(self._html())
        view.setStyleSheet(
            f"QTextBrowser {{ background:{C['abyss']}; border:none; padding:24px 28px; }}")
        lay.addWidget(view)

    def _html(self):
        c = C
        return f"""
        <style>
          body {{ color:{c['foam']}; font-family:'IBM Plex Sans',sans-serif; font-size:14px; line-height:1.55; }}
          h1 {{ font-family:'Space Grotesk',sans-serif; color:{c['foam']}; font-size:22px; margin:0 0 2px; }}
          .tag {{ color:{c['haze']}; font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:2px; }}
          h2 {{ font-family:'JetBrains Mono',monospace; color:{c['ping']}; font-size:12px;
                letter-spacing:2px; text-transform:uppercase; margin:26px 0 8px; }}
          a {{ color:{c['waterline']}; text-decoration:none; }}
          code {{ font-family:'JetBrains Mono',monospace; color:{c['waterline']};
                  background:{c['deep']}; padding:1px 5px; border-radius:4px; }}
          .step {{ color:{c['foam']}; margin:0 0 8px; }}
          .num {{ color:{c['ping']}; font-family:'Space Grotesk',sans-serif; font-weight:700; }}
          .muted {{ color:{c['haze']}; }}
          .pill {{ color:{c['abyss']}; background:{c['ping']}; padding:1px 7px; border-radius:4px;
                   font-family:'JetBrains Mono',monospace; font-size:12px; }}
          .warn {{ color:{c['medium']}; }}
          hr {{ border:none; border-top:1px solid {c['line']}; margin:22px 0; }}
          .disc {{ color:{c['haze']}; font-size:13px; margin:0 0 9px; }}
          .disc b {{ color:{c['foam']}; }}
        </style>

        <div class="tag">NEATLABS&trade;</div>
        <h1>FATHOM</h1>
        <div class="muted">Certificate depth sounding for the CA/Browser Forum phase-down.</div>

        <h2>Quick start</h2>
        <p class="step"><span class="num">1.</span> Type one or more targets in the bar —
        hostnames, IPs, or CIDR blocks (e.g. <code>example.com</code>, <code>10.0.0.0/24</code>).
        Separate several with spaces or commas.</p>
        <p class="step"><span class="num">2.</span> Optional: tick <span class="pill">discover</span>
        to expand a domain into its real subdomains via Certificate Transparency logs and
        certificate SANs. Add <span class="pill">brute</span> to also try common subdomain names.</p>
        <p class="step"><span class="num">3.</span> Press <span class="pill">SOUND</span>.
        The verdict banner gives you the bottom line; the chart and table show every certificate
        by depth and risk. <span class="pill">EXPORT JSON</span> saves the full report.</p>

        <h2>Reading the result</h2>
        <p class="disc"><b>The banner</b> is the bottom line — read it first. Green means no action needed;
        amber means manual renewals are coming; red means something will fail.</p>
        <p class="disc"><b>The waterline</b> separates certificates that auto-renew (above) from those with
        no automation behind them (below). Below-the-waterline certs — mail, directory, RDP, databases,
        appliances — are the ones no host will quietly renew for you.</p>
        <p class="disc"><b>Depth</b> = how soon a certificate dies. <b>Size</b> = risk. <b>Click</b> any contact
        to jump to its row, or select a row to ring its contact.</p>

        <h2>The phase-down</h2>
        <p class="disc">CA/Browser Forum ballot SC-081v3 shortens maximum certificate validity:
        398 &rarr; <b>200 days</b> (live now) &rarr; <b>100 days</b> (Mar 2027) &rarr; <b>47 days</b> (Mar 2029),
        with domain-validation reuse dropping to 10 days. Manual renewal stops being workable well before 2029.</p>

        <hr>
        <h2>Please read</h2>
        <p class="disc"><b class="warn">Authorized use only.</b> Scan only domains, hosts, and networks you
        own or have explicit written permission to assess. The discovery and scan passes connect to the
        hosts you target; unauthorized scanning may violate law or policy.</p>
        <p class="disc"><b>Passive vs active.</b> Certificate Transparency lookups read public logs and are
        passive. DNS resolution, the brute pass, and the port scan are active connections to the targets.</p>
        <p class="disc"><b>Heuristics, not guarantees.</b> Risk tiers and the &ldquo;auto-renewing&rdquo;
        inference are prioritization aids, not proof. Verify before acting. FATHOM is read-only and never
        issues, modifies, or deletes certificates.</p>
        <p class="disc"><b>Discovery depends on third parties.</b> Certificate Transparency results come from
        crt.sh, which may be slow or rate-limited; FATHOM degrades gracefully if it's unavailable.</p>
        <p class="disc"><b>Not legal or compliance advice.</b> The schedule summarized here is for planning;
        confirm current requirements with your certificate authority.</p>

        <hr>
        <p class="muted">NEATLABS&trade; FATHOM v{VERSION} &nbsp;·&nbsp; MIT licensed &nbsp;·&nbsp;
        <a href="{SITE}">neatlabs.ai</a> &nbsp;·&nbsp;
        <a href="https://github.com/neatlabs-ai">github.com/neatlabs-ai</a></p>
        <p class="muted" style="font-size:12px">Others talk about it. NEATLABS&trade; is about it.</p>
        """


def font(family, size, weight=QFont.Weight.Normal, spacing=0.0):
    f = QFont(family, size); f.setWeight(weight)
    fams = {DISPLAY: ["Space Grotesk", "Eurostile", "Bahnschrift", "Arial"],
            MONO: ["JetBrains Mono", "Cascadia Code", "Consolas", "Menlo", "monospace"],
            BODY: ["IBM Plex Sans", "Segoe UI", "Helvetica Neue", "Arial"]}
    f.setFamilies(fams.get(family, [family]))
    if spacing:
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    return f


# ---------------------------------------------------------------------------
# scan worker (threaded; keeps the UI fluid)
# ---------------------------------------------------------------------------
class ScanWorker(QThread):
    progress = pyqtSignal(int, int, str)      # done, total, label
    status = pyqtSignal(str)                   # discovery phase messages
    finished_report = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, targets, ports, timeout, concurrency,
                 discover=False, brute=False, max_sans=scanner.MAX_SANS):
        super().__init__()
        self.targets, self.ports = targets, ports
        self.timeout, self.concurrency = timeout, concurrency
        self.discover, self.brute = discover, brute
        self.max_sans = max_sans

    def run(self):
        try:
            def prog(done, total, host, port):
                self.progress.emit(done, total, f"{host}:{port}")
            provenance = None
            if self.discover or self.brute:
                records, provenance = asyncio.run(discovery.sound(
                    self.targets, ports=self.ports, timeout=self.timeout,
                    concurrency=self.concurrency,
                    use_ct=True, use_brute=self.brute, resolve=True,
                    progress=prog, say=self.status.emit, max_sans=self.max_sans))
            else:
                records = asyncio.run(scanner.scan(
                    self.targets, ports=self.ports, timeout=self.timeout,
                    concurrency=self.concurrency, progress=prog,
                    max_sans=self.max_sans))
            report = analyzer.build_report(records)
            if provenance:
                report["discovery"] = discovery.provenance_summary(provenance)
            self.finished_report.emit(report)
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# the signature: sonar iceberg, painted natively
# ---------------------------------------------------------------------------
class SonarChart(QWidget):
    contactClicked = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(380)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._certs = []
        self._contacts = []          # (x, y, r, idx, tiercolname)
        self._hover = -1
        self._selected = -1
        self._sweep = 0.0
        self._below_pct = 0
        self._small_sample = False
        self._total = 0
        self._timer = QTimer(self); self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_certs(self, certs, below_pct, small_sample=False, total=0):
        self._certs = certs; self._below_pct = below_pct
        self._small_sample = small_sample; self._total = total
        self._selected = -1; self._layout(); self.update()

    def select(self, idx):
        self._selected = idx; self.update()

    def _tick(self):
        self._sweep = (self._sweep + 0.0042) % 1.0
        self.update()

    @staticmethod
    def _hashx(s):
        h = 2166136261
        for ch in s:
            h ^= ord(ch); h = (h * 16777619) & 0xffffffff
        return (h % 1000) / 1000.0

    def _geom(self):
        w, h = self.width(), self.height()
        wl = h * 0.24
        floor = h - 18
        return w, h, wl, floor

    def _layout(self):
        w, h, wl, floor = self._geom()
        self._contacts = []
        for i, c in enumerate(self._certs):
            a = c["assessment"]
            above = a["above_waterline"]
            hx = self._hashx((c.get("fingerprint_sha256") or c["host"]) + str(c["port"]))
            if above:
                # keep surface contacts clear of the hero callout (top-left)
                x = w * 0.44 + hx * (w * 0.50)
                y = 26 + self._hashx(c["host"] + str(i)) * (wl - 56)
            else:
                x = 36 + hx * (w - 72)
                y = wl + 16 + a["depth"] * (floor - wl - 26)
            r = 4 + (a["score"] / 100) * 8
            self._contacts.append((x, y, r, i, TIER_COL[a["tier"]]))

    def resizeEvent(self, e):
        self._layout(); super().resizeEvent(e)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h, wl, floor = self._geom()

        # background water column
        g = QLinearGradient(0, wl, 0, floor)
        g.setColorAt(0, col("ridge", 130)); g.setColorAt(1, QColor(2, 12, 17, 255))
        p.fillRect(QRectF(0, 0, w, h), col("abyss"))
        p.fillRect(QRectF(0, wl, w, floor - wl), QBrush(g))
        # sky
        p.fillRect(QRectF(0, 0, w, wl), QColor(125, 240, 255, 8))

        # hero callout in the sky — the punch line
        p.setFont(font(MONO, 8, spacing=1.4)); p.setPen(col("haze"))
        p.drawText(QRectF(18, 6, 240, 14), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                   "BELOW THE WATERLINE")
        p.setFont(font(DISPLAY, 38, QFont.Weight.Bold)); p.setPen(col("ping"))
        p.drawText(QRectF(16, 20, 300, 48), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                   f"{self._below_pct}%")
        p.setFont(font(BODY, 9)); p.setPen(col("foam", 205))
        p.drawText(QRectF(18, 66, 330, 18), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop),
                   "no host automation will renew these")

        # depth bands + labels
        bands = [(wl, wl + (floor-wl)*0.25, "2026", "Phase 1 · 200-day · live now"),
                 (wl + (floor-wl)*0.25, wl + (floor-wl)*0.50, "2027", "Phase 2 · 100-day"),
                 (wl + (floor-wl)*0.50, wl + (floor-wl)*0.74, "2029", "Phase 3 · 47-day"),
                 (wl + (floor-wl)*0.74, floor, "\u221e", "Abyss · self-signed / unmanaged")]
        p.setFont(font(MONO, 8, spacing=0.6))
        for y0, y1, yr, lab in bands:
            p.setPen(QPen(col("ping", 22), 1))
            p.drawLine(QPointF(0, y1), QPointF(w, y1))
            p.setPen(col("haze", 150))
            p.drawText(QRectF(12, y0 + 4, 320, 16), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), lab)
            p.setPen(col("haze", 70)); p.setFont(font(DISPLAY, 11, QFont.Weight.Bold))
            p.drawText(QRectF(w - 90, y0 + 4, 78, 18), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter), yr)
            p.setFont(font(MONO, 8, spacing=0.6))

        # sweep glow (sonar trace moving left -> right)
        sx = self._sweep * w
        sg = QLinearGradient(sx - 80, 0, sx + 8, 0)
        sg.setColorAt(0, QColor(69, 240, 208, 0)); sg.setColorAt(1, QColor(69, 240, 208, 26))
        p.fillRect(QRectF(sx - 80, wl, 88, floor - wl), QBrush(sg))
        p.setPen(QPen(col("ping", 60), 1)); p.drawLine(QPointF(sx, wl), QPointF(sx, floor))

        # waterline
        p.setPen(QPen(col("waterline", 210), 1.4))
        p.drawLine(QPointF(0, wl), QPointF(w, wl))

        # contacts
        for (x, y, r, idx, tc) in self._contacts:
            base = col(tc)
            near_sweep = abs((x / w) - self._sweep) < 0.04
            crit = tc == "critical"
            # pulse / sweep brighten
            glow = 0.0
            if crit:
                glow = 0.5 + 0.5 * math.sin(self._sweep * math.tau * 2)
            if near_sweep:
                glow = max(glow, 1.0)
            if glow > 0:
                gr = QRadialGradient(x, y, r + 9)
                gc = QColor(base); gc.setAlpha(int(70 * glow))
                gr.setColorAt(0, gc); gc2 = QColor(base); gc2.setAlpha(0); gr.setColorAt(1, gc2)
                p.setBrush(QBrush(gr)); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(x, y), r + 9, r + 9)
            # body
            fill = QColor(base); fill.setAlpha(220)
            p.setBrush(QBrush(fill))
            p.setPen(QPen(QColor(base), 1))
            p.drawEllipse(QPointF(x, y), r, r)
            # core highlight
            hl = QRadialGradient(x - r*0.3, y - r*0.3, r)
            hl.setColorAt(0, QColor(255, 255, 255, 150)); hl.setColorAt(1, QColor(255, 255, 255, 0))
            p.setBrush(QBrush(hl)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), r*0.55, r*0.55)
            # selection / hover ring
            if idx == self._selected or idx == self._hover:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(col("foam", 230 if idx == self._selected else 150), 1.6))
                p.drawEllipse(QPointF(x, y), r + 4, r + 4)
        # caption top-right in the sky
        p.setFont(font(MONO, 8, spacing=0.8)); p.setPen(col("dim"))
        p.drawText(QRectF(w - 320, 12, 308, 30),
                   int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop),
                   "depth = how soon it dies\nsize = risk")
        # small-sample caveat, tucked in the empty abyss floor
        if getattr(self, "_small_sample", False):
            p.setFont(font(MONO, 8, spacing=0.6)); p.setPen(col("medium", 210))
            p.drawText(QRectF(18, floor - 18, 360, 14),
                       int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                       f"\u26a0 percentage over a small sample (n={self._total})")
        p.end()

    def _hit(self, pos):
        for (x, y, r, idx, _) in self._contacts:
            if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= (r + 5) ** 2:
                return idx
        return -1

    def mouseMoveEvent(self, e):
        idx = self._hit(e.position())
        if idx != self._hover:
            self._hover = idx; self.update()
        if idx >= 0:
            c = self._certs[idx]; a = c["assessment"]
            dr = a["days_remaining"]
            drs = "—" if dr is None else (f"{abs(dr)}d ago" if dr < 0 else f"{dr}d")
            esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;")
                             .replace(">", "&gt;"))
            crypto = ""
            if a.get("weak_key") or a.get("legacy_sig"):
                flags = " · ".join(f for f in (
                    "weak key" if a.get("weak_key") else "",
                    "legacy sig" if a.get("legacy_sig") else "") if f)
                crypto = f"\n⚠ {flags}"
            QToolTip.showText(e.globalPosition().toPoint(),
                f"{esc(c['host'])}:{esc(c['port'])}\n{esc(a['service'])} · "
                f"{a['tier'].upper()} ({a['score']})\n"
                f"expires {drs} · {'above' if a['above_waterline'] else 'below'} waterline\n"
                f"issuer: {esc(a['issuer_class'])}{crypto}",
                self)
        self.setCursor(Qt.CursorShape.PointingHandCursor if idx >= 0 else Qt.CursorShape.ArrowCursor)

    def mousePressEvent(self, e):
        idx = self._hit(e.position())
        if idx >= 0:
            self._selected = idx; self.update(); self.contactClicked.emit(idx)


# ---------------------------------------------------------------------------
# small widgets
# ---------------------------------------------------------------------------
class BlufBanner(QFrame):
    """The bottom line up front — board-readable verdict, color-coded."""
    def __init__(self):
        super().__init__()
        self.setObjectName("bluf")
        self._accent = C["line"]
        lay = QHBoxLayout(self); lay.setContentsMargins(18, 14, 18, 14); lay.setSpacing(16)
        self.dot = QLabel("●"); self.dot.setFont(font(BODY, 16))
        self.dot.setStyleSheet(f"color:{C['haze']}")
        col_text = QVBoxLayout(); col_text.setSpacing(2)
        self.head = QLabel("—"); self.head.setFont(font(DISPLAY, 16, QFont.Weight.Bold))
        self.detail = QLabel(""); self.detail.setFont(font(BODY, 11))
        self.detail.setStyleSheet(f"color:{C['haze']}"); self.detail.setWordWrap(True)
        col_text.addWidget(self.head); col_text.addWidget(self.detail)
        lay.addWidget(self.dot); lay.addLayout(col_text, 1)

    def set_verdict(self, v):
        accent = C.get(v.get("color", "haze"), C["haze"])
        self._accent = accent
        self.dot.setStyleSheet(f"color:{accent}")
        self.head.setStyleSheet(f"color:{accent}")
        self.head.setText(v["headline"])
        self.detail.setText(v["detail"])
        self.setStyleSheet(
            f"QFrame#bluf {{ background:{C['deep']}; border:1px solid {C['line']};"
            f"border-left:4px solid {accent}; border-radius:12px; }}")


class StatCard(QFrame):
    def __init__(self, key, accent="foam"):
        super().__init__()
        self.setObjectName("stat")
        lay = QVBoxLayout(self); lay.setContentsMargins(15, 13, 15, 13); lay.setSpacing(6)
        self.v = QLabel("—"); self.v.setFont(font(DISPLAY, 24, QFont.Weight.Bold))
        self.v.setStyleSheet(f"color:{C[accent]}")
        self.k = QLabel(key.upper()); self.k.setFont(font(MONO, 8, spacing=1.0))
        self.k.setStyleSheet(f"color:{C['haze']}")
        lay.addWidget(self.v); lay.addWidget(self.k)
    def set(self, val): self.v.setText(str(val))


class DepthDelegate(QStyledItemDelegate):
    """Gradient depth bar in the Depth column."""
    def paint(self, p, opt, idx):
        depth = idx.data(Qt.ItemDataRole.UserRole) or 0.0
        p.save(); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = opt.rect.adjusted(10, opt.rect.height()//2 - 3, -12, -(opt.rect.height()//2 - 3))
        p.setBrush(col("line", 120)); p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(r), 3, 3)
        fillw = max(2, int(r.width() * depth))
        g = QLinearGradient(r.left(), 0, r.left() + r.width(), 0)
        g.setColorAt(0, col("ping")); g.setColorAt(1, col("critical"))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(QRectF(r.left(), r.top(), fillw, r.height()), 3, 3)
        p.restore()


# ---------------------------------------------------------------------------
# main window
# ---------------------------------------------------------------------------
class Fathom(QMainWindow):
    HEADERS = ["Host", "Service", "Issuer", "Waterline", "Expires", "Risk", "Depth"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NEATLABS\u2122 FATHOM — certificate depth sounding")
        self.resize(1240, 880)
        self._report = None
        self._build()
        self._load_sample()

    # ---- ui construction ----
    def _build(self):
        root = QWidget(); self.setCentralWidget(root)
        lay = QVBoxLayout(root); lay.setContentsMargins(22, 18, 22, 18); lay.setSpacing(16)

        lay.addLayout(self._masthead())
        lay.addLayout(self._controls())

        self.bluf = BlufBanner()
        lay.addWidget(self.bluf)

        self.chart = SonarChart()
        self.chart.contactClicked.connect(self._select_row)
        chart_frame = QFrame(); chart_frame.setObjectName("hero")
        cf = QVBoxLayout(chart_frame); cf.setContentsMargins(1, 1, 1, 1)
        cf.addWidget(self.chart)
        lay.addWidget(chart_frame, 3)

        self.stats_row, self.cards = self._stats()
        lay.addLayout(self.stats_row)

        self.table = self._build_table()
        lay.addWidget(self.table, 4)

        self.status = QLabel("Ready · sample fleet loaded")
        self.status.setFont(font(MONO, 9)); self.status.setStyleSheet(f"color:{C['dim']}")
        footer = QHBoxLayout()
        footer.addWidget(self.status); footer.addStretch()
        link = QLabel(f'NEATLABS\u2122 FATHOM · <a href="{SITE}" '
                      f'style="color:{C["haze"]};text-decoration:none">neatlabs.ai</a>')
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setOpenExternalLinks(True)
        link.setFont(font(MONO, 9)); link.setStyleSheet(f"color:{C['dim']}")
        footer.addWidget(link)
        lay.addLayout(footer)

        self.setStyleSheet(self._qss())

    def _masthead(self):
        row = QHBoxLayout()
        brandbox = QVBoxLayout(); brandbox.setSpacing(0)
        tag = QLabel("NEATLABS\u2122"); tag.setFont(font(MONO, 8, spacing=3.0))
        tag.setStyleSheet(f"color:{C['haze']}")
        brand = QLabel('FATH<span style="color:%s">O</span>M' % C["ping"])
        brand.setTextFormat(Qt.TextFormat.RichText)
        brand.setFont(font(DISPLAY, 26, QFont.Weight.Bold))
        brand.setStyleSheet(f"color:{C['foam']}; letter-spacing:2px")
        brandbox.addWidget(tag); brandbox.addWidget(brand)
        sub = QLabel("CERTIFICATE DEPTH SOUNDING")
        sub.setFont(font(MONO, 9, spacing=2.4)); sub.setStyleSheet(f"color:{C['haze']}")
        sub.setContentsMargins(12, 0, 0, 4)
        row.addLayout(brandbox)
        row.addWidget(sub, alignment=Qt.AlignmentFlag.AlignBottom)
        row.addStretch()
        self.help_btn = QPushButton("?  QUICK START"); self.help_btn.setObjectName("ghost")
        self.help_btn.setFont(font(MONO, 9)); self.help_btn.clicked.connect(self._show_help)
        right = QVBoxLayout(); right.setSpacing(6)
        self.phase_lbl = QLabel("—")
        self.phase_lbl.setFont(font(MONO, 9)); self.phase_lbl.setObjectName("phasechip")
        right.addWidget(self.help_btn, alignment=Qt.AlignmentFlag.AlignRight)
        right.addWidget(self.phase_lbl, alignment=Qt.AlignmentFlag.AlignRight)
        row.addLayout(right)
        return row

    def _show_help(self):
        HelpDialog(self).exec()

    def _controls(self):
        row = QHBoxLayout(); row.setSpacing(8)
        self.targets = QLineEdit(); self.targets.setObjectName("inp")
        self.targets.setPlaceholderText("hosts, IPs, or CIDR  ·  e.g.  example.com  mail.example.com  10.0.0.0/24")
        self.targets.setFont(font(MONO, 10))
        self.ports = QLineEdit(); self.ports.setObjectName("inp")
        self.ports.setText("443,8443,465,587,993,995,25,636,990,3389")
        self.ports.setFont(font(MONO, 9)); self.ports.setMaximumWidth(330)
        self.ports.setToolTip("ports to sound — numbers and/or presets: "
                              "web, mail, dir, db, remote, all")
        self.max_sans = QLineEdit(); self.max_sans.setObjectName("inp")
        self.max_sans.setText(str(scanner.MAX_SANS))
        self.max_sans.setFont(font(MONO, 9)); self.max_sans.setMaximumWidth(70)
        self.max_sans.setToolTip("max SANs kept per certificate (0 = unlimited)")
        self.scan_btn = QPushButton("SOUND"); self.scan_btn.setObjectName("primary")
        self.scan_btn.setFont(font(MONO, 10, QFont.Weight.Bold)); self.scan_btn.clicked.connect(self._scan)
        self.export_btn = QPushButton("EXPORT JSON"); self.export_btn.setObjectName("ghost")
        self.export_btn.setFont(font(MONO, 9)); self.export_btn.clicked.connect(self._export)
        self.report_btn = QPushButton("EXPORT REPORT"); self.report_btn.setObjectName("primary")
        self.report_btn.setFont(font(MONO, 9, QFont.Weight.Bold)); self.report_btn.clicked.connect(self._export_html)
        self.cb_discover = QCheckBox("discover"); self.cb_discover.setObjectName("chk")
        self.cb_discover.setFont(font(MONO, 9))
        self.cb_discover.setToolTip("Expand domains via Certificate Transparency logs + certificate SANs")
        self.cb_brute = QCheckBox("brute"); self.cb_brute.setObjectName("chk")
        self.cb_brute.setFont(font(MONO, 9))
        self.cb_brute.setToolTip("Also try a common-subdomain DNS wordlist")
        for w in (self.targets,): row.addWidget(w, 1)
        row.addWidget(self.ports); row.addWidget(self.max_sans)
        row.addWidget(self.cb_discover); row.addWidget(self.cb_brute)
        row.addWidget(self.scan_btn); row.addWidget(self.export_btn); row.addWidget(self.report_btn)
        return row

    def _stats(self):
        row = QHBoxLayout(); row.setSpacing(12)
        cards = {
            "total": StatCard("certificates"),
            "below": StatCard("below waterline", "waterline"),
            "critical": StatCard("critical", "critical"),
            "expired": StatCard("expired", "critical"),
            "october": StatCard("Oct-2026 cohort", "medium"),
            "p2": StatCard("breaks · 2027", "medium"),
        }
        for c in cards.values(): row.addWidget(c)
        return row, cards

    def _build_table(self):
        t = QTableWidget(0, len(self.HEADERS))
        t.setHorizontalHeaderLabels(self.HEADERS)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setAlternatingRowColors(False)
        t.setItemDelegateForColumn(6, DepthDelegate(t))
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for cidx in (1, 3, 4, 5, 6):
            hh.setSectionResizeMode(cidx, QHeaderView.ResizeMode.ResizeToContents)
        hh.setFont(font(MONO, 8, spacing=1.2))
        t.setFont(font(BODY, 10))
        t.itemSelectionChanged.connect(self._row_selected)
        t.setSortingEnabled(False)
        return t

    # ---- data ----
    def _load_sample(self):
        path = Path(__file__).resolve().parent / "assets" / "sample-report.json"
        if path.exists():
            self._set_report(json.loads(path.read_text(encoding="utf-8")))

    def _set_report(self, report):
        self._report = report
        s = report["summary"]
        verdict = report.get("verdict") or analyzer.fleet_verdict(s)
        self.bluf.set_verdict(verdict)
        self.cards["total"].set(s["total"])
        self.cards["below"].set(f"{s['below_waterline']}")
        self.cards["critical"].set(s["tiers"]["critical"])
        self.cards["expired"].set(s["expired"])
        self.cards["october"].set(s["october_cohort"])
        self.cards["p2"].set(s["breaks_at_phase2"])
        cp = s["current_phase"]
        self.phase_lbl.setText(f"  ● {cp['label']} · DCV reuse {cp['dcv_reuse']}d  ")
        self.chart.set_certs(report["certs"], s["below_waterline_pct"],
                             verdict.get("small_sample", False), s["total"])
        self._fill_table(report["certs"])
        disc = report.get("discovery")
        if disc:
            srcs = " · ".join(f"{n} {discovery.SOURCE_LABEL.get(k, k)}"
                              for k, n in disc["by_source"].items())
            self.status.setText(
                f"{disc['total_hosts']} hosts discovered ({srcs}) · "
                f"{s['total']} certificates · {s['below_waterline_pct']}% below the waterline")
        else:
            self.status.setText(
                f"{s['total']} certificates · {s['below_waterline_pct']}% below the waterline · "
                f"{s['tiers']['critical']} critical · {s['expired']} expired")

    def _fill_table(self, certs):
        t = self.table; t.setRowCount(len(certs))
        for r, c in enumerate(certs):
            a = c["assessment"]; dr = a["days_remaining"]
            drs = "—" if dr is None else (f"{abs(dr)}d ago" if dr < 0 else f"{dr}d")
            flagged = a.get("weak_key") or a.get("legacy_sig")
            host = QTableWidgetItem(f"{c['host']}:{c['port']}" + ("  ⚠" if flagged else ""))
            host.setFont(font(MONO, 10))
            keystr = (f"{c.get('key_type') or '—'}"
                      + (f"-{c['key_bits']}" if c.get("key_bits") else ""))
            tip = (f"public key: {keystr}\nsignature: {(c.get('sig_algo') or '—').upper()}")
            if flagged:
                fl = " · ".join(f for f in (
                    "weak key" if a.get("weak_key") else "",
                    "legacy signature" if a.get("legacy_sig") else "") if f)
                tip += f"\n⚠ {fl}"
            host.setToolTip(tip)
            svc = QTableWidgetItem(a["service"])
            svc.setForeground(col("haze"))
            iss = QTableWidgetItem((c.get("issuer") or "—").split(" —")[0])
            iss.setForeground(col("haze"))
            wl = QTableWidgetItem("▲ above" if a["above_waterline"] else "▼ below")
            wl.setForeground(col("dim") if a["above_waterline"] else col("high"))
            wl.setFont(font(MONO, 9))
            exp = QTableWidgetItem(drs); exp.setFont(font(MONO, 9, QFont.Weight.Bold))
            exp.setTextAlignment(int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
            exp.setForeground(col("critical") if (dr is not None and dr < 0)
                              else col("high") if (dr is not None and dr <= 30) else col("foam"))
            risk = QTableWidgetItem(a["tier"].upper())
            risk.setFont(font(MONO, 8, QFont.Weight.Bold))
            risk.setForeground(col(TIER_COL[a["tier"]]))
            risk.setTextAlignment(int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
            depth = QTableWidgetItem("")
            depth.setData(Qt.ItemDataRole.UserRole, a["depth"])
            for cidx, it in enumerate((host, svc, iss, wl, exp, risk, depth)):
                t.setItem(r, cidx, it)
            t.setRowHeight(r, 38)

    # ---- interaction ----
    def _select_row(self, idx):
        self.table.blockSignals(True)
        self.table.selectRow(idx)
        self.table.scrollToItem(self.table.item(idx, 0),
                                QAbstractItemView.ScrollHint.PositionAtCenter)
        self.table.blockSignals(False)

    def _row_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.chart.select(rows[0].row())

    # ---- scanning ----
    def _scan(self):
        raw = self.targets.text().strip()
        if not raw:
            self.status.setText("Enter at least one host, IP, or CIDR to sound."); return
        targets = raw.replace(",", " ").split()
        try:
            ports = scanner.resolve_ports(self.ports.text()) or scanner.DEFAULT_PORTS
        except ValueError:
            self.status.setText("Ports: use numbers and/or presets "
                                "(web, mail, dir, db, remote, all)."); return
        try:
            n = int(self.max_sans.text().strip() or scanner.MAX_SANS)
            if n < 0:
                raise ValueError
            max_sans = None if n == 0 else n          # 0 = unlimited
        except ValueError:
            self.status.setText("Max SANs must be a non-negative integer (0 = unlimited)."); return
        self.scan_btn.setEnabled(False); self.scan_btn.setText("SOUNDING…")
        discover = self.cb_discover.isChecked() or self.cb_brute.isChecked()
        self.worker = ScanWorker(targets, ports, 6.0, 100,
                                 discover=discover, brute=self.cb_brute.isChecked(),
                                 max_sans=max_sans)
        self.worker.progress.connect(self._on_progress)
        self.worker.status.connect(lambda m: self.status.setText(m))
        self.worker.finished_report.connect(self._on_done)
        self.worker.failed.connect(self._on_fail)
        self.worker.start()

    def _on_progress(self, done, total, label):
        self.status.setText(f"sounding [{done}/{total}]  {label}")

    def _on_done(self, report):
        self.scan_btn.setEnabled(True); self.scan_btn.setText("SOUND")
        if not report["certs"]:
            self.status.setText("No TLS certificates surfaced on those hosts/ports."); return
        self._set_report(report)

    def _on_fail(self, msg):
        self.scan_btn.setEnabled(True); self.scan_btn.setText("SOUND")
        self.status.setText("Scan failed — " + msg)

    def _export(self):
        if not self._report:
            self.status.setText("Nothing to export yet — run a sounding first."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export report", "fathom-report.json",
                                              "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self._report, indent=2), encoding="utf-8")
            self.status.setText(f"Report written → {path}")

    def _export_html(self):
        if not self._report:
            self.status.setText("Nothing to export yet — run a sounding first."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML report",
                                              "fathom-report.html", "HTML report (*.html)")
        if not path:
            return
        if not path.lower().endswith(".html"):
            path += ".html"
        Path(path).write_text(report_html.render_html(self._report), encoding="utf-8")
        self.status.setText(f"HTML report written → {path}")
        try:
            import webbrowser
            webbrowser.open(Path(path).resolve().as_uri())
        except Exception:
            pass

    # ---- theme ----
    def _qss(self):
        return f"""
        QWidget {{ background:{C['abyss']}; color:{C['foam']}; }}
        QFrame#hero {{ background:{C['deep']}; border:1px solid {C['line']}; border-radius:14px; }}
        QFrame#stat {{ background:{C['deep']}; border:1px solid {C['line']}; border-radius:11px; }}
        QLineEdit#inp {{ background:{C['deep']}; border:1px solid {C['line']}; border-radius:9px;
            padding:10px 13px; color:{C['foam']}; selection-background-color:{C['ping']};
            selection-color:{C['abyss']}; }}
        QLineEdit#inp:focus {{ border:1px solid {C['ping']}; }}
        QLabel#phasechip {{ border:1px solid {C['line']}; border-radius:999px;
            padding:6px 4px; color:{C['waterline']}; background:{C['shelf']}; }}
        QPushButton#primary {{ background:{C['ping']}; color:{C['abyss']}; border:none;
            border-radius:9px; padding:10px 22px; letter-spacing:1px; }}
        QPushButton#primary:hover {{ background:#5cf7d9; }}
        QPushButton#primary:disabled {{ background:{C['ridge']}; color:{C['haze']}; }}
        QPushButton#ghost {{ background:transparent; color:{C['haze']};
            border:1px solid {C['line']}; border-radius:9px; padding:10px 16px; }}
        QPushButton#ghost:hover {{ color:{C['foam']}; border-color:{C['ridge']}; }}
        QCheckBox#chk {{ color:{C['haze']}; spacing:6px; padding:0 4px; }}
        QCheckBox#chk::indicator {{ width:15px; height:15px; border:1px solid {C['line']};
            border-radius:4px; background:{C['deep']}; }}
        QCheckBox#chk::indicator:checked {{ background:{C['ping']}; border-color:{C['ping']}; }}
        QCheckBox#chk:hover {{ color:{C['foam']}; }}
        QTableWidget {{ background:{C['abyss']}; border:none; gridline-color:transparent; }}
        QTableWidget::item {{ padding:0 10px; border-bottom:1px solid rgba(21,84,104,.35); }}
        QTableWidget::item:selected {{ background:{C['shelf']}; color:{C['foam']}; }}
        QHeaderView::section {{ background:{C['abyss']}; color:{C['haze']};
            border:none; border-bottom:1px solid {C['line']}; padding:9px 10px; }}
        QScrollBar:vertical {{ background:{C['deep']}; width:10px; margin:0; }}
        QScrollBar::handle:vertical {{ background:{C['ridge']}; border-radius:5px; min-height:30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ height:0; }}
        QToolTip {{ background:{C['deep']}; color:{C['foam']}; border:1px solid {C['line']};
            padding:6px; }}
        """


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NEATLABS\u2122 FATHOM")
    win = Fathom(); win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
