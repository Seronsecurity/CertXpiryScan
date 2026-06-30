"""FATHOM test suite — pure-logic coverage that runs offline (no network)."""

import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from fathom import analyzer, cli, discovery, report, scanner

NOW = datetime.now(UTC)


def _iso(days):
    return (NOW + timedelta(days=days)).isoformat()


def cert(**kw):
    base = dict(host="h.example.com", port=443, subject_cn="h.example.com",
                issuer="Let's Encrypt — R10", not_before=_iso(-10), not_after=_iso(80),
                self_signed=False, chain_trusted=True, sans=["h.example.com"],
                fingerprint_sha256="ab" * 32, tls_version="TLSv1.3",
                key_type="EC", key_bits=256, sig_algo="sha256", error=None)
    base.update(kw)
    return base


def _assessed(*certs):
    return [{**c, "assessment": dataclasses.asdict(analyzer.assess(c))} for c in certs]


# ----------------------------- analyzer ---------------------------------
def test_acme_web_cert_is_above_waterline_and_ok():
    a = analyzer.assess(cert())
    assert a.above_waterline is True
    assert a.tier in ("ok", "low")


def test_letsencrypt_above_even_when_verify_probe_failed():
    # regression: a flaky chain-verify must not push an ACME web cert below
    a = analyzer.assess(cert(chain_trusted=False))
    assert a.above_waterline is True
    assert a.tier in ("ok", "low")


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


def test_new_acme_intermediates_recognized():
    # R13/WR2 rotating intermediates seen in the wild must classify as ACME
    assert analyzer.issuer_class("Let's Encrypt — R13") == "acme"
    assert analyzer.issuer_class("Google Trust Services — WR2") == "acme"


# ----------------------------- crypto hygiene ---------------------------
def test_weak_rsa_key_flagged():
    a = analyzer.assess(cert(key_type="RSA", key_bits=1024))
    assert a.weak_key is True
    assert any("Weak key" in r for r in a.reasons)


def test_strong_keys_not_flagged():
    assert analyzer.assess(cert(key_type="RSA", key_bits=2048)).weak_key is False
    assert analyzer.assess(cert(key_type="EC", key_bits=256)).weak_key is False


def test_legacy_sha1_signature_flagged():
    a = analyzer.assess(cert(sig_algo="sha1"))
    assert a.legacy_sig is True
    assert any("Legacy signature" in r for r in a.reasons)


def test_missing_key_info_is_safe():
    a = analyzer.assess(cert(key_type=None, key_bits=None, sig_algo=None))
    assert a.weak_key is False and a.legacy_sig is False


# ----------------------------- verdict / summary ------------------------
def _summary(certs):
    return analyzer.fleet_summary(_assessed(*certs))


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


def test_summary_counts_weak_and_legacy():
    s = _summary([cert(key_type="RSA", key_bits=1024), cert(sig_algo="md5"), cert()])
    assert s["weak_key"] == 1
    assert s["legacy_sig"] == 1


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


def test_ct_parsing_handles_multiline_and_wildcards():
    raw = '[{"name_value":"*.x.com\\nwww.x.com","common_name":"x.com"},' \
          '{"name_value":"api.x.com"}]'
    names = discovery._parse_ct(raw, "x.com")
    assert names == {"x.com", "www.x.com", "api.x.com"}


def test_ct_parsing_rejects_out_of_scope():
    raw = '[{"name_value":"evil.other.com","common_name":"www.x.com"}]'
    assert discovery._parse_ct(raw, "x.com") == {"www.x.com"}


def test_ct_cache_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "CACHE_DIR", str(tmp_path))
    calls = {"n": 0}

    def fake_lookup(domain, timeout=30):
        calls["n"] += 1
        return {"www." + domain}

    monkeypatch.setattr(discovery, "ct_lookup", fake_lookup)
    first = discovery.cached_ct_lookup("x.com")
    second = discovery.cached_ct_lookup("x.com")  # served from cache
    assert first == second == {"www.x.com"}
    assert calls["n"] == 1  # network hit only once


def test_parallel_ct_runs_concurrently(monkeypatch):
    monkeypatch.setattr(discovery, "ct_lookup",
                        lambda d, timeout=30: {"www." + d})
    monkeypatch.setattr(discovery, "dns_resolvable", lambda h: True)
    targets, prov = asyncio.run(discovery.discover(
        ["a.com", "b.com"], use_ct=True, resolve=True, cache=False))
    assert prov.get("www.a.com") == "ct"
    assert prov.get("www.b.com") == "ct"


def test_sound_orchestration(monkeypatch):
    monkeypatch.setattr(discovery, "ct_lookup",
                        lambda d, timeout=30: {"www." + d, "dead." + d})
    monkeypatch.setattr(discovery, "dns_resolvable", lambda h: not h.startswith("dead."))

    async def fake_scan(targets, ports=None, timeout=6.0, concurrency=100,
                        progress=None, max_sans=None):
        return [cert(host=t, sans=[t] + (["api.x.com"] if t == "www.x.com" else []),
                     fingerprint_sha256="fp" + t) for t in targets]
    monkeypatch.setattr(discovery.scanner, "scan", fake_scan)

    recs, prov = asyncio.run(discovery.sound(["x.com"], use_ct=True, resolve=True,
                                             cache=False))
    assert prov.get("www.x.com") == "ct"
    assert "dead.x.com" not in prov          # dropped by resolve filter
    assert prov.get("api.x.com") == "san"    # SAN pivot worked


# ----------------------------- scanner (offline) ------------------------
def test_expand_targets_cidr_and_dedupe():
    out = scanner.expand_targets(["10.0.0.0/30", "example.com", "example.com", "# c"])
    assert "example.com" in out
    assert out.count("example.com") == 1
    assert "10.0.0.1" in out and "10.0.0.2" in out


def test_is_ip_helper():
    assert scanner._is_ip("192.168.0.1")
    assert not scanner._is_ip("example.com")


def test_resolve_ports_numbers_presets_and_mix():
    assert scanner.resolve_ports(None) is None
    assert scanner.resolve_ports("") is None
    assert scanner.resolve_ports("443,8443") == [443, 8443]
    assert scanner.resolve_ports("web") == scanner.PORT_PRESETS["web"]
    # mix of preset + numbers, deduped, order preserved
    assert scanner.resolve_ports("web,443,3389") == scanner.PORT_PRESETS["web"] + [3389]
    assert scanner.resolve_ports(" MAIL ") == scanner.PORT_PRESETS["mail"]  # case/space


def test_resolve_ports_rejects_junk():
    import pytest as _pt
    with _pt.raises(ValueError):
        scanner.resolve_ports("web,notaport")


def test_scan_skips_dead_pairs(monkeypatch):
    async def fake_probe(host, port, timeout=6.0, max_sans=None):
        return cert(host=host, port=port) if port == 443 else None
    monkeypatch.setattr(scanner, "probe", fake_probe)
    recs = asyncio.run(scanner.scan(["a.com"], ports=[443, 9999]))
    assert len(recs) == 1 and recs[0]["port"] == 443


# ----------------------------- report / XSS -----------------------------
def test_report_escapes_malicious_cert_data():
    payload = '<img src=x onerror="alert(1)">'
    c = cert(host="evil" + payload, subject_cn=payload, issuer="EvilCA " + payload,
             sans=[payload], self_signed=True, chain_trusted=False, not_after=_iso(2))
    assessed = _assessed(c)
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "<img src=x onerror" not in html       # raw payload must not appear
    assert "&lt;img" in html                        # it appears escaped


def test_report_renders_minimal():
    assessed = _assessed(cert())
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "<!DOCTYPE html>" in html
    assert "FATH" in html


def test_report_writes_utf8_on_any_platform(tmp_path):
    """The verdict banner uses ● / → glyphs; writing must be UTF-8, not cp1252."""
    assessed = _assessed(cert())
    s = analyzer.fleet_summary(assessed)
    html = report.render_html({"verdict": analyzer.fleet_verdict(s),
                               "summary": s, "certs": assessed})
    assert "●" in html or "→" in html  # contains non-cp1252 glyphs
    out = tmp_path / "r.html"
    out.write_text(html, encoding="utf-8")          # the code path FATHOM uses
    assert out.read_text(encoding="utf-8") == html
    with pytest.raises(UnicodeEncodeError):
        html.encode("cp1252")


# ----------------------------- security hardening -----------------------
def test_json_for_html_escapes_script_breakout():
    payload = {"certs": [{"issuer": '</script><img src=x onerror=alert(1)>'}]}
    out = cli._json_for_html(payload)
    assert "</script>" not in out          # no raw breakout
    assert "<" not in out and ">" not in out and "&" not in out
    # still valid JSON that decodes to the original data
    import json as _json
    assert _json.loads(out) == payload


def test_render_dashboard_neutralizes_malicious_cert(tmp_path):
    """End-to-end: a hostile cert field can't break out of the dashboard <script>."""
    rep = {"summary": {"total": 1,
                       "tiers": {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 1},
                       "below_waterline": 0, "below_waterline_pct": 0, "october_cohort": 0,
                       "breaks_at_phase2": 0, "breaks_at_phase3": 0, "expired": 0,
                       "expiring_30d": 0,
                       "current_phase": {"label": "x", "max_validity": 200, "dcv_reuse": 200}},
           "certs": [{"host": "evil", "port": 443,
                      "issuer": "</script><img src=x onerror=alert(document.domain)>",
                      "sans": ["a"], "assessment": dataclasses.asdict(analyzer.assess(cert()))}]}
    p = tmp_path / "rep.json"
    import json as _json
    p.write_text(_json.dumps(rep), encoding="utf-8")
    html = cli._render_dashboard(p)
    assert "</script><img" not in html     # the breakout payload is neutralized


def test_csv_neutralizes_formula_injection():
    import csv as _csv
    import io as _io
    rep = {"certs": [{"host": "=HYPERLINK(1)", "issuer": "+evil", "subject_cn": "@x",
                      "port": 443, "assessment": {"service": "-cmd"}}]}
    rows = list(_csv.reader(_io.StringIO(cli._to_csv(rep))))
    d = dict(zip(rows[0], rows[1], strict=True))
    assert d["host"] == "'=HYPERLINK(1)"
    assert d["issuer"] == "'+evil"
    assert d["subject_cn"] == "'@x"
    assert d["service"] == "'-cmd"


def test_expand_targets_caps_large_cidr():
    with pytest.raises(ValueError):
        scanner.expand_targets(["10.0.0.0/8"])
    # a small range and hostnames still work, and a custom cap is honored
    assert len(scanner.expand_targets(["10.0.0.0/30"])) >= 2
    with pytest.raises(ValueError):
        scanner.expand_targets(["10.0.0.0/24"], max_hosts=10)


def test_resolve_ports_rejects_out_of_range():
    with pytest.raises(ValueError):
        scanner.resolve_ports("70000")
    with pytest.raises(ValueError):
        scanner.resolve_ports("0")


def test_ct_cache_rejects_invalid_hostnames_on_read(tmp_path, monkeypatch):
    import json as _json
    monkeypatch.setattr(discovery, "CACHE_DIR", str(tmp_path))
    discovery._prepare_cache_dir()
    # poison the cache file with junk alongside one valid name
    path = discovery._cache_path("x.com")
    _json.dump({"domain": "x.com",
                "names": ["bad host", "evil;rm -rf", "../../etc", "www.x.com"]},
               open(path, "w", encoding="utf-8"))

    def boom(domain, timeout=30):
        raise AssertionError("network must not be hit — cache is fresh")
    monkeypatch.setattr(discovery, "ct_lookup", boom)

    names = discovery.cached_ct_lookup("x.com")
    assert names == {"www.x.com"}          # junk filtered on read


def test_cache_dir_is_not_world_shared_tmp(monkeypatch):
    # with a HOME set, the cache lives under the user's private cache home
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/fathomtester")
    d = discovery._default_cache_dir()
    assert d == "/home/fathomtester/.cache/fathom"


# ----------------------------- review-batch improvements ----------------
def test_parse_ct_rejects_lookalike_domains():
    raw = ('[{"name_value":"www.example.com\\nnotexample.com\\n'
           'example.com.evil.com\\nexample.com","common_name":"api.example.com"}]')
    names = discovery._parse_ct(raw, "example.com")
    assert names == {"www.example.com", "example.com", "api.example.com"}
    assert "notexample.com" not in names          # different registrable domain
    assert "example.com.evil.com" not in names    # suffix attack


def test_build_report_is_shared_and_sorted():
    assert cli.build_report is analyzer.build_report
    rep = analyzer.build_report([cert(not_after=_iso(-1)), cert(host="ok.example.com")])
    assert rep["tool"] == "FATHOM" and rep["summary"]["total"] == 2
    assert "verdict" in rep and "certs" in rep
    ranks = [analyzer.TIER_ORDER[c["assessment"]["tier"]] for c in rep["certs"]]
    assert ranks == sorted(ranks)                 # worst-first


def test_scan_bounded_pool_covers_all_pairs(monkeypatch):
    seen = []

    async def fake_probe(host, port, timeout=6.0, max_sans=None):
        seen.append((host, port))
        return cert(host=host, port=port) if port == 443 else None
    monkeypatch.setattr(scanner, "probe", fake_probe)
    recs = asyncio.run(scanner.scan(["a.com", "b.com", "c.com"], ports=[443, 8443],
                                    concurrency=2))
    assert len(seen) == 6        # every pair probed despite a 2-worker pool
    assert len(recs) == 3        # only :443 returned a cert


def test_scan_handles_zero_concurrency(monkeypatch):
    async def fake_probe(host, port, timeout=6.0, max_sans=None):
        return cert(host=host, port=port)
    monkeypatch.setattr(scanner, "probe", fake_probe)
    recs = asyncio.run(scanner.scan(["a.com"], ports=[443], concurrency=0))
    assert len(recs) == 1        # clamped to 1, no deadlock


def test_ct_empty_result_not_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "CACHE_DIR", str(tmp_path))
    calls = {"n": 0}

    def empty(domain, timeout=30):
        calls["n"] += 1
        return set()
    monkeypatch.setattr(discovery, "ct_lookup", empty)
    assert discovery.cached_ct_lookup("x.com") == set()
    assert discovery.cached_ct_lookup("x.com") == set()
    assert calls["n"] == 2       # empty isn't cached, so re-queried


def test_scan_forwards_max_sans(monkeypatch):
    seen = {}

    async def fake_probe(host, port, timeout=6.0, max_sans=scanner.MAX_SANS):
        seen["max_sans"] = max_sans
        return cert(host=host, port=port)
    monkeypatch.setattr(scanner, "probe", fake_probe)
    asyncio.run(scanner.scan(["a.com"], ports=[443], max_sans=5))
    assert seen["max_sans"] == 5
    asyncio.run(scanner.scan(["a.com"], ports=[443], max_sans=None))  # unlimited
    assert seen["max_sans"] is None
    asyncio.run(scanner.scan(["a.com"], ports=[443]))                 # default
    assert seen["max_sans"] == scanner.MAX_SANS
