"""
FATHOM — phase-down risk analyzer.

Scores every discovered certificate against the CA/Browser Forum SC-081v3
schedule (the "47-day" ballot, passed April 2025) and classifies each one as
above or below the waterline — i.e. whether anything is realistically going to
renew it for you, or whether it's a hidden machine identity that dies silently.

The rules here are the actual published schedule, not vendor marketing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime

# ---------------------------------------------------------------------------
# SC-081v3 schedule. Maximum certificate validity (days) at time of ISSUANCE,
# and the Domain Control Validation (DCV) reuse window, by enforcement date.
# ---------------------------------------------------------------------------
PHASES = [
    # (enforcement_date, max_validity_days, dcv_reuse_days, label)
    (date(2025, 1, 1), 398, 398, "Legacy (398-day)"),
    (date(2026, 3, 15), 200, 200, "Phase 1 (200-day)"),
    (date(2027, 3, 15), 100, 100, "Phase 2 (100-day)"),
    (date(2029, 3, 15), 47, 10, "Phase 3 (47-day)"),
]

# Issuers that almost always auto-renew via ACME / managed pipelines. A cert
# from one of these on a web port is the part of the ecosystem that genuinely
# takes care of itself.
ACME_ISSUER_MARKERS = [
    "let's encrypt", "lets encrypt",
    # Let's Encrypt rotating intermediates (when only the CN is exposed)
    "r3", "r10", "r11", "r12", "r13", "r14", "e1", "e5", "e6", "e7", "e8", "e9",
    "google trust services", "gts ", "pki.goog", "we1", "we2", "wr1", "wr2", "wr3",
    "zerossl", "cloudflare", "amazon", "azure", "microsoft azure",
    "buypass", "actalis", "gogetssl", "sslmate", "smallstep",
]

# Publicly trusted, but typically bought and pasted in by a human.
MANUAL_CA_MARKERS = [
    "digicert", "sectigo", "godaddy", "entrust", "globalsign", "comodo",
    "thawte", "geotrust", "rapidssl", "network solutions", "identrust",
    "ssl.com", "starfield", "certum", "trustwave", "quovadis", "wisekey",
    "swisssign", "harica", "secom", "twca",
]

# port -> (service, is_web). Web ports are the ones a host control panel might
# plausibly cover. Everything else is machine identity nobody is watching.
PORT_SERVICE = {
    443: ("HTTPS", True), 8443: ("HTTPS-alt", True), 4443: ("HTTPS-alt", True),
    8080: ("HTTP-proxy/TLS", True), 9443: ("HTTPS-alt", True),
    25: ("SMTP", False), 465: ("SMTPS", False), 587: ("Submission", False),
    993: ("IMAPS", False), 995: ("POP3S", False), 143: ("IMAP/STARTTLS", False),
    636: ("LDAPS", False), 389: ("LDAP/STARTTLS", False),
    3389: ("RDP", False), 5986: ("WinRM-HTTPS", False),
    5432: ("PostgreSQL", False), 3306: ("MySQL", False), 1433: ("MSSQL", False),
    5433: ("PostgreSQL-alt", False), 27017: ("MongoDB", False),
    6379: ("Redis", False), 9200: ("Elasticsearch", False), 9300: ("Elasticsearch", False),
    5671: ("AMQPS", False), 8883: ("MQTTS", False), 5061: ("SIP-TLS", False),
    989: ("FTPS-data", False), 990: ("FTPS", False),
    6443: ("Kubernetes-API", False), 2376: ("Docker-TLS", False),
}

# Public-key strength floors. Below these is a real weakness, not just old.
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
# Signature hashes that no longer belong on a public-facing cert.
LEGACY_SIG_HASHES = {"md5", "sha1"}

TIER_CRITICAL = "critical"
TIER_HIGH = "high"
TIER_MEDIUM = "medium"
TIER_LOW = "low"
TIER_OK = "ok"

TIER_ORDER = {TIER_CRITICAL: 0, TIER_HIGH: 1, TIER_MEDIUM: 2, TIER_LOW: 3, TIER_OK: 4}


def _now() -> datetime:
    return datetime.now(UTC)


def current_phase(on: date | None = None):
    on = on or _now().date()
    chosen = PHASES[0]
    for p in PHASES:
        if on >= p[0]:
            chosen = p
    return chosen


def phase_for_date(d: date):
    """Which phase governs a certificate issued on date d."""
    return current_phase(d)


def issuer_class(issuer_str: str) -> str:
    s = (issuer_str or "").lower()
    for m in ACME_ISSUER_MARKERS:
        if m in s:
            return "acme"
    for m in MANUAL_CA_MARKERS:
        if m in s:
            return "manual"
    return "unknown"


def service_for_port(port: int):
    return PORT_SERVICE.get(port, ("TLS service", False))


@dataclass
class Assessment:
    tier: str
    score: int                     # 0-100, higher = worse
    depth: float                   # 0.0 surface .. 1.0 abyss (for the iceberg)
    above_waterline: bool
    service: str
    is_web: bool
    issuer_class: str
    publicly_trusted: bool
    days_remaining: int | None
    validity_days: int | None
    october_cohort: bool           # 200-day cert that expires ~Oct 2026
    dies_at_phase2: bool           # validity illegal once 100-day cap hits
    dies_at_phase3: bool           # validity illegal once 47-day cap hits
    weak_key: bool = False         # RSA<2048 / EC<256 / DSA
    legacy_sig: bool = False       # signed with MD5 or SHA-1
    reasons: list = field(default_factory=list)


def assess(cert: dict) -> Assessment:
    """
    cert is a dict from the scanner with at least:
      port, issuer, not_before (iso), not_after (iso),
      self_signed (bool), chain_trusted (bool|None), error (str|None)
    """
    port = int(cert.get("port", 0))
    service, is_web = service_for_port(port)
    icls = issuer_class(cert.get("issuer", ""))
    self_signed = bool(cert.get("self_signed"))
    # treat trusted as True only when explicitly verified; unknown -> assume
    # publicly trusted if issued by a known public CA marker.
    chain_trusted = cert.get("chain_trusted")
    publicly_trusted = bool(chain_trusted) if chain_trusted is not None else (
        icls in ("acme", "manual") and not self_signed
    )

    reasons: list[str] = []
    now = _now()

    def parse(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None

    nb = parse(cert.get("not_before"))
    na = parse(cert.get("not_after"))
    days_remaining = int((na - now).total_seconds() // 86400) if na else None
    validity_days = int((na - nb).total_seconds() // 86400) if (na and nb) else None

    # October-2026 cohort: a ~200-day cert issued near the 2026-03-15 cap, the
    # first batch to expire early under Phase 1. notAfter lands ~Oct 2026.
    october_cohort = False
    if validity_days is not None and na is not None:
        if 150 <= validity_days <= 205 and date(2026, 9, 1) <= na.date() <= date(2026, 11, 15):
            october_cohort = True

    # Will this cert's *validity period* be illegal at future caps? A long-lived
    # cert isn't itself illegal, but its renewal cadence assumption breaks: the
    # team thinks they renew on this schedule, and they don't anymore.
    dies_at_phase2 = bool(validity_days and validity_days > 100)
    dies_at_phase3 = bool(validity_days and validity_days > 47)

    # cryptographic hygiene — independent of the phase-down, but a cert tool
    # would be negligent not to surface it.
    key_type = cert.get("key_type")
    key_bits = cert.get("key_bits")
    weak_key = False
    if key_type and key_bits:
        if key_type == "RSA" and key_bits < MIN_RSA_BITS:
            weak_key = True
        elif key_type in ("EC",) and key_bits < MIN_EC_BITS:
            weak_key = True
        elif key_type == "DSA":
            weak_key = True
    sig = (cert.get("sig_algo") or "").lower()
    legacy_sig = sig in LEGACY_SIG_HASHES

    # ---- scoring -------------------------------------------------------
    score = 0

    # expiry pressure
    if days_remaining is not None:
        if days_remaining < 0:
            score += 60
            reasons.append(f"Expired {abs(days_remaining)}d ago")
        elif days_remaining <= 14:
            score += 45
            reasons.append(f"Expires in {days_remaining}d")
        elif days_remaining <= 30:
            score += 25
            reasons.append(f"Expires in {days_remaining}d")
        elif days_remaining <= 60:
            score += 10

    # automation posture
    if self_signed:
        score += 20
        reasons.append("Self-signed / private CA — no public automation path")
    elif icls == "manual":
        score += 18
        reasons.append("Manual-purchase CA — renewal is a human task")
    elif icls == "unknown":
        score += 12
        reasons.append("Unrecognized issuer — automation posture unknown")
    elif icls == "acme":
        score -= 8  # this is the part that takes care of itself

    # waterline: is anything realistically going to renew this without a human?
    # A cert rides the surface if it's a web cert that's clearly on an automated
    # short-cycle: an ACME issuer, OR a publicly trusted ≤100-day cert (the
    # ACME/managed signature) regardless of issuer-name matching. This no longer
    # hinges on a single opportunistic chain-verify probe, which was producing
    # OK-but-below contradictions for Let's Encrypt certs.
    auto_renewing = (icls == "acme") or (
        validity_days is not None and validity_days <= 100
        and not self_signed and publicly_trusted
    )
    above_waterline = is_web and auto_renewing and not self_signed
    if not is_web:
        score += 22
        reasons.append(f"{service} cert — below the waterline, no host renews this")

    # cadence shock from the phase-down
    if dies_at_phase3:
        score += 8
        if dies_at_phase2:
            score += 6
            reasons.append("Validity exceeds the 2027 (100-day) cap — cadence will break")
        else:
            reasons.append("Validity exceeds the 2029 (47-day) cap")
    if october_cohort:
        score += 8
        reasons.append("Oct-2026 cohort: first 200-day batch to expire early")

    # cryptographic weakness
    if weak_key:
        score += 15
        reasons.append(f"Weak key ({key_type}-{key_bits}) — below modern minimums")
    if legacy_sig:
        score += 15
        reasons.append(f"Legacy signature ({sig.upper()}) — deprecated for public trust")

    score = max(0, min(100, score))

    # tier
    if (days_remaining is not None and days_remaining < 14) or \
       (self_signed and not is_web and (days_remaining is None or days_remaining < 90)):
        tier = TIER_CRITICAL
    elif score >= 55:
        tier = TIER_HIGH
    elif score >= 30:
        tier = TIER_MEDIUM
    elif score >= 12:
        tier = TIER_LOW
    else:
        tier = TIER_OK

    # depth for the iceberg: 0 = floating safely on the surface, 1 = abyss.
    depth = 0.0
    if not above_waterline:
        depth += 0.30
    if not is_web:
        depth += 0.25
    if self_signed:
        depth += 0.15
    if icls == "manual":
        depth += 0.10
    if icls == "unknown":
        depth += 0.12
    depth += min(0.30, score / 100 * 0.30)
    depth = round(min(1.0, depth), 3)

    if not reasons:
        reasons.append("Auto-renewing web cert — riding the surface")

    return Assessment(
        tier=tier, score=score, depth=depth, above_waterline=above_waterline,
        service=service, is_web=is_web, issuer_class=icls,
        publicly_trusted=publicly_trusted, days_remaining=days_remaining,
        validity_days=validity_days, october_cohort=october_cohort,
        dies_at_phase2=dies_at_phase2, dies_at_phase3=dies_at_phase3,
        weak_key=weak_key, legacy_sig=legacy_sig,
        reasons=reasons,
    )


def build_report(records: list[dict]) -> dict:
    """Assess every record, sort worst-first, and roll up a full report dict.
    The one canonical report builder — used by the CLI and the GUI alike."""
    assessed = [{**rec, "assessment": asdict(assess(rec))} for rec in records]
    assessed.sort(key=lambda a: (TIER_ORDER[a["assessment"]["tier"]],
                                 -a["assessment"]["score"]))
    summary = fleet_summary(assessed)
    return {
        "tool": "FATHOM",
        "schedule": "CA/Browser Forum SC-081v3",
        "verdict": fleet_verdict(summary),
        "summary": summary,
        "certs": assessed,
    }


def fleet_verdict(summary: dict) -> dict:
    """The bottom line, in one board-readable sentence.

    Executive tone: states the verdict and the single most material number,
    not the inputs. Keeps the percentage but flags small samples.
    """
    t = summary["tiers"]
    total = summary["total"]
    crit = t["critical"]
    high = t["high"]
    expired = summary["expired"]
    below = summary["below_waterline"]
    small = total < 5

    def n(x):
        return "certificate" if x == 1 else "certificates"

    note = ""
    if small and total > 0:
        note = f" Small sample (n={total}) — scan more hosts for a fleet-level read."
    elif total == 0:
        return {"severity": "none", "color": "haze",
                "headline": "No certificates found",
                "detail": "Nothing responded with a TLS certificate on the ports scanned.",
                "small_sample": False}

    if crit or expired:
        bits = []
        if expired:
            bits.append(f"{expired} already expired")
        if crit:
            bits.append(f"{crit} {n(crit)} will fail before anything renews "
                        f"{'it' if crit == 1 else 'them'}")
        return {"severity": "action", "color": "critical",
                "headline": "Action required",
                "detail": f"{' · '.join(bits)}, out of {total} found.{note}",
                "small_sample": small}

    if high:
        return {"severity": "watch", "color": "high",
                "headline": "Attention needed",
                "detail": f"{high} of {total} {n(total)} are at risk in the "
                          f"phase-down with no automation to renew "
                          f"{'it' if high == 1 else 'them'}.{note}",
                "small_sample": small}

    if below:
        return {"severity": "watch", "color": "medium",
                "headline": "Manual renewals ahead",
                "detail": f"{below} of {total} {n(total)} have no host automation "
                          f"and will need hands-on renewal as windows shorten — "
                          f"none critical yet.{note}",
                "small_sample": small}

    verb = "is" if total == 1 else "are"
    return {"severity": "ok", "color": "ok",
            "headline": "No action required",
            "detail": f"All {total} {n(total)} {verb} auto-renewing and current.{note}",
            "small_sample": small}


def fleet_summary(assessed: list[dict]) -> dict:
    """Roll up per-cert assessments into the numbers a board wants to see."""
    total = len(assessed)
    tiers = {t: 0 for t in (TIER_CRITICAL, TIER_HIGH, TIER_MEDIUM, TIER_LOW, TIER_OK)}
    below = 0
    october = 0
    p2 = 0
    p3 = 0
    expired = 0
    expiring_30 = 0
    weak = 0
    legacy = 0
    for a in assessed:
        asmt = a["assessment"]
        tiers[asmt["tier"]] += 1
        if not asmt["above_waterline"]:
            below += 1
        if asmt["october_cohort"]:
            october += 1
        if asmt["dies_at_phase2"]:
            p2 += 1
        if asmt["dies_at_phase3"]:
            p3 += 1
        if asmt.get("weak_key"):
            weak += 1
        if asmt.get("legacy_sig"):
            legacy += 1
        dr = asmt["days_remaining"]
        if dr is not None and dr < 0:
            expired += 1
        elif dr is not None and dr <= 30:
            expiring_30 += 1

    ph = current_phase()
    return {
        "total": total,
        "tiers": tiers,
        "below_waterline": below,
        "below_waterline_pct": round(below / total * 100) if total else 0,
        "october_cohort": october,
        "breaks_at_phase2": p2,
        "breaks_at_phase3": p3,
        "expired": expired,
        "expiring_30d": expiring_30,
        "weak_key": weak,
        "legacy_sig": legacy,
        "current_phase": {"label": ph[3], "max_validity": ph[1], "dcv_reuse": ph[2]},
        "generated": _now().isoformat(),
    }
