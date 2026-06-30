"""FATHOM test suite — pure-logic coverage that runs offline (no network)."""

import asyncio
from datetime import datetime, timedelta, timezone

from fathom import analyzer, discovery, report

NOW = datetime.now(timezone.utc)


def _iso(days):
    return (NOW + timedelta(days=days)).isoformat()


def cert(**kw):
    base = dict(host="h.example.com", port=443, subject_cn="h.example.com",
                issuer="Let's Encrypt — R10", not_before=_iso(-10), not_after=_iso(80),
                self_signed=False, chain_trusted=True, sans=["h.example.com"],
                fingerprint_sha256="ab" * 32, tls_version="TLSv1.3", error=None)
    base.update(kw)
    return base


# ----------------------------- analyzer ---------------------------------
def test_acme_web_cert_is_above_waterline_and_ok():
    a = analyzer.assess(cert())
    assert a.above_waterline is True
    assert a.tier in ("ok", "low")


def test_letsencrypt_above_even_when_verify_probe_failed():
    # regression: a flaky chain-verify must not push an ACME web cert below
    a = analyzer.assess(cert(chain_trusted=False))
    assert a.above_waterline is True
    assert a.tier in ("ok", "low")  # no OK-but-below contradiction


def test_short_lived_trusted_web_cert_counts_as_automated():
    a = analyzer.assess(cert(issuer="Acme Internal CA", not_after=_iso(60)))
    assert a.above_waterline is True


def test_manual_long_web_cert_is_below():
    a = analyzer.assess(cert(issuer="DigiCert Inc — G2", not_after=_iso(190)))
    assert a.above_waterline is False
    assert a.issuer_class == "manual"


def test_mail_cert_is_below_the_waterline():
    a = analyzer.assess(cert(port=993))
    assert a.is_web is False
    assert a.above_waterline is False


def test_self_signed_expiring_soon_is_critical():
    a = analyzer.assess(cert(port=3389, issuer="ts.local", self_signed=True,
                             chain_trusted=False, not_after=_iso(5)))
    assert a.tier == "critical"
    assert a.above_waterline is False


def test_expired_cert_scored_high():
    a = analyzer.assess(cert(not_after=_iso(-3)))
    assert a.days_remaining < 0


def test_october_cohort_flag():
    a = analyzer.assess(cert(issuer="DigiCert Inc", not_before="2026-03-15T00:00:00+00:00",
                             not_after="2026-10-01T00:00:00+00:00"))
    assert a.october_cohort is True


def test_depth_within_bounds():
    a = analyzer.assess(cert(port=3389, self_signed=True, chain_trusted=False))
    assert 0.0 <= a.depth <= 1.0


# ----------------------------- verdict ----------------------------------
def _summary(certs):
    assessed = [{**c, "assessment": vars(analyzer.assess(c))} for c in certs]
    # vars() of a dataclass instance won't include all; use asdict
    import dataclasses
    assessed = [{**c, "assessment": dataclasses.asdict(analyzer.assess(c))} for c in certs]
    return analyzer.fleet_summary(assessed)


def test_verdict_ok_for_clean_fleet():
    v = analyzer.fleet_verdict(_summary([cert(), cert(host="b.example.com")]))
    assert v["severity"] == "ok"


def test_verdict_action_when_expired():
    v = analyzer.fleet_verdict(_summary([cert(not_after=_iso(-1))]))
    assert v["severity"] == "action"


def test_verdict_small_sample_note():
    v = analyzer.fleet_verdict(_summary([cert()]))
    assert v["small_sample"] is True
    assert "small sample" in v["detail"].lower()


def test_verdict_no_certs():
    v = analyzer.fleet_verdict(analyzer.fleet_summary([]))
    assert v["severity"] == "none"


# ----------------------------- discovery --------------------------------
def test_hostname_regex_rejects_junk():
    assert discovery._HOSTNAME_RE.match("www.neatlabs.ai")
    assert not discovery._HOSTNAME_RE.match("bad_host")
    assert not discovery._HOSTNAME_RE.match("no spaces.com")


def test_san_pivot_scope_guard():
    recs = [{"host": "www.x.com", "port": 443,
             "sans": ["www.x.com", "api.x.com", "cdn.fastly.net", "<bad>.x.com"]}]
    out = discovery.san_candidates(recs, ["x.com"], known={"www.x.com"})
    assert out == {"api.x.com"}  # in-scope only, junk + out-of-scope dropped


def test_dedupe():
    recs = [{"host": "a", "port": 443, "fingerprint_sha256": "x"},
            {"host": "a", "port": 443, "fingerprint_sha256": "x"},
            {"host": "a", "port": 993, "fingerprint_sha256": "y"}]
    assert len(discovery._dedupe(recs)) == 2


def test_ip_and_cidr_detection():
    assert discovery._is_ip_or_cidr("10.0.0.0/24")
    assert discovery._is_ip_or_cidr("192.168.1.1")
    assert not discovery._is_ip_or_cidr("example.com")


def test_sound_orchestration(monkeypatch):
    monkeypatch.setattr(discovery, "ct_lookup",
                        lambda d, timeout=30: {"www." + d, "dead." + d})
    monkeypatch.setattr(discovery, "dns_resolvable", lambda h: not h.startswith("dead."))

    async def fake_scan(targets, ports=None, timeout=6.0, concurrency=100, progress=None):
        return [cert(host=t, sans=[t] + (["api.x.com"] if t == "www.x.com" else []),
                     fingerprint_sha256="fp" + t) for t in targets]
    monkeypatch.setattr(discovery.scanner, "scan", fake_scan)

    recs, prov = asyncio.run(discovery.sound(["x.com"], use_ct=True, resolve=True))
    assert prov.get("www.x.com") == "ct"
    assert "dead.x.com" not in prov          # dropped by resolve filter
    assert prov.get("api.x.com") == "san"    # SAN pivot worked


# ----------------------------- report / XSS -----------------------------
def test_report_escapes_malicious_cert_data():
    payload = '<img src=x onerror="alert(1)">'
    c = cert(host="evil" + payload, subject_cn=payload, issuer="EvilCA " + payload,
             sans=[payload], self_signed=True, chain_trusted=False, not_after=_iso(2))
    import dataclasses
    assessed = [{**c, "assessment": dataclasses.asdict(analyzer.assess(c))}]
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "<img src=x onerror" not in html       # raw payload must not appear
    assert "&lt;img" in html                        # it appears escaped


def test_report_renders_minimal():
    import dataclasses
    assessed = [{**cert(), "assessment": dataclasses.asdict(analyzer.assess(cert()))}]
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "<!DOCTYPE html>" in html
    assert "FATH" in html


def test_report_writes_utf8_on_any_platform(tmp_path):
    """The verdict banner uses ● / → glyphs; writing must be UTF-8, not cp1252."""
    import dataclasses
    c = cert()
    assessed = [{**c, "assessment": dataclasses.asdict(analyzer.assess(c))}]
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "●" in html or "→" in html  # contains non-cp1252 glyphs
    out = tmp_path / "r.html"
    out.write_text(html, encoding="utf-8")          # the code path FATHOM uses
    assert out.read_text(encoding="utf-8") == html
    # prove it would have failed the naive Windows default
    import pytest
    with pytest.raises(UnicodeEncodeError):
        html.encode("cp1252")
