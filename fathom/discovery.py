"""
FATHOM — discovery (engine v2).

Answers the question a domain owner can't answer from memory: *what hosts do I
actually have?* Three passive-to-active layers:

  1. Certificate Transparency (crt.sh) — every publicly trusted cert ever issued
     is logged in public. One query for %.domain returns every subdomain anyone
     ever got a cert for, including the dev box stood up in 2022 and forgotten.
     Passive. Highest value, lowest noise.
  2. SAN pivot — names listed inside the certs we harvest become new targets,
     bounded to the seed domains so we never wander off into unrelated space.
  3. DNS brute (opt-in) — a small wordlist of common prefixes, for internal
     names that never earned a public cert.

v2 improvements: CT lookups run in parallel across seed domains, results are
cached on disk with a TTL so repeat runs skip the network, and discovered
candidates are filtered through async DNS resolution so dead CT entries don't pad
the fleet. Pure standard library.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import tempfile
import time
import urllib.parse
import urllib.request

from . import scanner

CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CT_TIMEOUT = 30
CT_RETRIES = 2
CT_MAX_NAMES = 5000          # guard against domains with enormous CT histories
USER_AGENT = "FATHOM/0.2 (+https://github.com/neatlabs-ai)"

CACHE_TTL = 12 * 3600        # crt.sh data changes slowly; 12h cache is plenty


def _default_cache_dir() -> str:
    """A per-user cache path. Prefer the user's private cache home over shared
    /tmp, so cache files aren't world-readable and can't be pre-seeded or
    symlink-attacked by another local user."""
    base = os.environ.get("XDG_CACHE_HOME")
    if not base:
        home = os.path.expanduser("~")
        if home and home != "~":
            base = os.path.join(home, ".cache")
    if not base:
        uid = os.getuid() if hasattr(os, "getuid") else "u"
        return os.path.join(tempfile.gettempdir(), f"fathom-cache-{uid}")
    return os.path.join(base, "fathom")


CACHE_DIR = _default_cache_dir()

# only plausible DNS hostnames are ever scanned or queried. Permissive on the
# label set (real CT data includes digits and IDNs / xn-- TLDs) but still
# requires a dotted name with no whitespace or junk.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$", re.I)

# common prefixes for the opt-in DNS brute pass
WORDLIST = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "mx", "mx1", "mx2",
    "autodiscover", "owa", "exchange", "vpn", "remote", "gateway", "portal",
    "api", "app", "apps", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "cpanel", "whm", "git", "gitlab", "jenkins", "ci", "ns1", "ns2",
    "dns", "ftp", "sftp", "files", "db", "database", "sql", "ldap", "ad",
    "dc", "dc1", "intranet", "internal", "secure", "login", "sso", "auth",
    "status", "monitor", "grafana", "kibana", "proxy",
]

SOURCE_LABEL = {"seed": "given", "ct": "CT logs", "san": "cert SANs",
                "dns-brute": "DNS brute"}


def _is_ip_or_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _registrable(s: str) -> bool:
    return ("." in s) and not _is_ip_or_cidr(s) and not s.startswith("#")


# --------------------------------------------------------------------------- #
# Certificate Transparency
# --------------------------------------------------------------------------- #
def _parse_ct(raw: str, domain: str) -> set[str]:
    if not raw.strip():
        return set()
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        # crt.sh occasionally returns concatenated objects rather than an array
        rows = json.loads("[" + raw.replace("}{", "},{") + "]")
    names: set[str] = set()
    d = domain.lower()
    for row in rows:
        for field in (row.get("name_value", ""), row.get("common_name", "")):
            for nm in str(field).split("\n"):
                nm = nm.strip().lower().lstrip("*.")
                # exact-suffix on a label boundary, so example.com never admits
                # notexample.com (a different registrable domain on a shared cert)
                in_scope = nm == d or nm.endswith("." + d)
                if nm and in_scope and _HOSTNAME_RE.match(nm):
                    names.add(nm)
                    if len(names) >= CT_MAX_NAMES:
                        return names
    return names


def ct_lookup(domain: str, timeout: int = CT_TIMEOUT) -> set[str]:
    """Query crt.sh for every name ever certified under `domain`."""
    url = CT_URL.format(domain=urllib.parse.quote(domain, safe=""))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last: Exception | None = None
    for attempt in range(CT_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
            return _parse_ct(raw, domain)
        except Exception as e:  # noqa: BLE001 — network/parse, retry then surface
            last = e
            if attempt < CT_RETRIES:
                time.sleep(1.0 * (attempt + 1))
    raise last if last else RuntimeError("CT lookup failed")


def _cache_path(domain: str) -> str:
    h = hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"ct-{h}.json")


def _prepare_cache_dir() -> bool:
    """Create CACHE_DIR as a private (0700) directory and confirm we own it.
    Returns False (caching disabled) if the path exists but isn't a directory we
    own — e.g. another local user pre-created it — so we never read attacker-
    planted cache contents or follow a planted symlink."""
    try:
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        st = os.lstat(CACHE_DIR)
        if not stat.S_ISDIR(st.st_mode):
            return False
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return False
        try:
            os.chmod(CACHE_DIR, 0o700)
        except OSError:
            pass
        return True
    except OSError:
        return False


def cached_ct_lookup(domain: str, timeout: int = CT_TIMEOUT, ttl: int = CACHE_TTL) -> set[str]:
    """ct_lookup with an on-disk TTL cache so repeat runs skip crt.sh."""
    path = _cache_path(domain)
    safe = _prepare_cache_dir()
    if safe:
        try:
            st = os.stat(path)
            if time.time() - st.st_mtime < ttl:
                with open(path, encoding="utf-8") as fh:
                    blob = json.load(fh)
                if blob.get("domain") == domain.lower():
                    # re-validate names on read: cache contents are not trusted
                    # input — only well-formed hostnames are ever returned.
                    return {n for n in blob.get("names", [])
                            if isinstance(n, str) and _HOSTNAME_RE.match(n)}
        except (OSError, ValueError):
            pass

    names = ct_lookup(domain, timeout=timeout)  # may raise — caller handles

    # don't cache an empty result: a transient crt.sh hiccup (200 + []) shouldn't
    # suppress discovery for the whole TTL.
    if safe and names:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"domain": domain.lower(), "names": sorted(names)}, fh)
            os.replace(tmp, path)
        except OSError:
            pass
    return names


# --------------------------------------------------------------------------- #
# DNS resolution
# --------------------------------------------------------------------------- #
def dns_resolvable(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False


async def _filter_resolvable(hosts: list[str], concurrency: int = 64) -> set[str]:
    out: set[str] = set()
    sem = asyncio.Semaphore(concurrency)

    async def check(h):
        async with sem:
            if await asyncio.to_thread(dns_resolvable, h):
                out.add(h)

    await asyncio.gather(*(check(h) for h in hosts))
    return out


# --------------------------------------------------------------------------- #
# SAN pivot
# --------------------------------------------------------------------------- #
def san_candidates(records: list[dict], seed_domains: list[str],
                   known: set[str]) -> set[str]:
    """SAN names within the seed domains' scope that we haven't scanned yet."""
    out: set[str] = set()
    suffixes = [d.lower() for d in seed_domains]
    for rec in records:
        for nm in rec.get("sans", []) or []:
            nm = str(nm).strip().lower().lstrip("*.")
            if not nm or nm in known or not _HOSTNAME_RE.match(nm):
                continue
            if any(nm == d or nm.endswith("." + d) for d in suffixes):
                out.add(nm)
    return out


def _dedupe(records: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in records:
        key = (r.get("host"), r.get("port"), r.get("fingerprint_sha256"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
async def discover(seeds: list[str], use_ct=True, use_brute=False, resolve=True,
                   concurrency=64, cache=True, say=None) -> tuple[list[str], dict]:
    """Expand seeds into a deduped target list with per-host provenance."""
    def note(m):
        if say:
            say(m)

    provenance: dict[str, str] = {}
    passthrough, hostnames, domains = [], [], []
    for s in (x.strip() for x in seeds):
        if not s or s.startswith("#"):
            continue
        if _is_ip_or_cidr(s):
            passthrough.append(s)
            provenance[s] = "seed"
        else:
            hostnames.append(s)
            provenance[s] = "seed"
            if _registrable(s):
                domains.append(s)

    cand: dict[str, str] = {}

    if use_ct and domains:
        note(f"querying Certificate Transparency logs for {len(domains)} domain(s)")
        lookup = cached_ct_lookup if cache else ct_lookup

        async def one(d):
            try:
                names = await asyncio.to_thread(lookup, d)
                note(f"CT logs: {len(names)} names known for {d}")
                return names
            except Exception as e:  # noqa: BLE001
                note(f"CT lookup unavailable for {d} ({type(e).__name__})")
                return set()

        for names in await asyncio.gather(*(one(d) for d in domains)):
            for nm in names:
                if nm not in provenance and nm not in cand and _HOSTNAME_RE.match(nm):
                    cand[nm] = "ct"

    if use_brute:
        for d in domains:
            for p in WORDLIST:
                h = f"{p}.{d}"
                if h not in provenance and h not in cand:
                    cand[h] = "dns-brute"
        note(f"DNS brute: {sum(1 for v in cand.values() if v=='dns-brute')} candidates queued")

    if resolve and cand:
        note(f"resolving {len(cand)} discovered candidates")
        live = await _filter_resolvable(list(cand), concurrency)
        dropped = len(cand) - len(live)
        cand = {h: s for h, s in cand.items() if h in live}
        if dropped:
            note(f"dropped {dropped} non-resolving names")

    provenance.update(cand)
    targets = list(dict.fromkeys(hostnames + list(cand) + passthrough))
    return targets, provenance


async def sound(seeds, ports=None, timeout=6.0, concurrency=100,
                use_ct=True, use_brute=False, resolve=True, cache=True,
                progress=None, say=None, max_sans=scanner.MAX_SANS):
    """Discover, scan, SAN-pivot, scan again — return (records, provenance)."""
    targets, provenance = await discover(
        seeds, use_ct=use_ct, use_brute=use_brute, resolve=resolve,
        concurrency=min(concurrency, 64), cache=cache, say=say)

    if say:
        say(f"sounding {len(targets)} hosts")
    records = await scanner.scan(targets, ports=ports, timeout=timeout,
                                 concurrency=concurrency, progress=progress,
                                 max_sans=max_sans)

    seed_domains = [s for s in seeds if _registrable(s)]
    known = set(targets)
    pivot = san_candidates(records, seed_domains, known)
    if pivot and resolve:
        if say:
            say(f"pivoting on {len(pivot)} names found in certificate SANs")
        pivot = await _filter_resolvable(list(pivot), min(concurrency, 64))
    if pivot:
        if say:
            say(f"sounding {len(pivot)} additional hosts from SANs")
        more = await scanner.scan(list(pivot), ports=ports, timeout=timeout,
                                  concurrency=concurrency, progress=progress,
                                  max_sans=max_sans)
        for h in pivot:
            provenance[h] = "san"
        records = _dedupe(records + more)

    return records, provenance


def provenance_summary(provenance: dict) -> dict:
    counts: dict[str, int] = {}
    for src in provenance.values():
        counts[src] = counts.get(src, 0) + 1
    return {"total_hosts": len(provenance), "by_source": counts}
