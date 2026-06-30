"""
FATHOM — certificate scanner (engine v2, native asyncio).

Harvests the certificate presented on every responsive TLS port of a host, not
just 443. Speaks direct TLS for implicit-TLS ports and STARTTLS for SMTP and
IMAP, because the certs that bite you live on mail servers, directories, and
databases — the ports no host control panel ever touches.

Design notes
------------
* Pure `asyncio` — one coroutine per host:port, bounded by a semaphore. No
  thread pool, no per-connection OS thread.
* One connection per certificate in the common case. We grab the leaf cert *and*
  the chain the server offered in a single permissive handshake, then decide
  trust **in-process** with `cryptography`'s path verifier (Python 3.13+, where
  `SSLObject.get_unverified_chain()` exists). Where in-process validation isn't
  possible (older Python, IP targets, missing chain) we fall back to a second
  verifying handshake — the old always-two-connections behaviour, but only on the
  cases that actually need it.

Standard library + `cryptography`. No external services beyond the hosts you
point it at.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from datetime import UTC
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

# Default cap on SANs stored per cert: enough for any realistic multi-SAN cert
# (so SAN-pivot discovery isn't starved) while bounding pathological certs with
# thousands. Overridable per scan via the `max_sans` argument (None = unlimited).
MAX_SANS = 100

DEFAULT_PORTS = [443, 8443, 465, 587, 993, 995, 25, 636, 990, 3389]

# named port sets, so callers don't have to remember the numbers. Shared by the
# CLI (--ports) and the GUI port field.
PORT_PRESETS = {
    "web": [443, 8443, 4443, 8080, 9443],
    "mail": [25, 465, 587, 993, 995, 143],
    "dir": [636, 389],
    "db": [5432, 5433, 3306, 1433, 27017, 6379, 9200],
    "remote": [3389, 5986],
    "all": sorted(set(DEFAULT_PORTS) | {
        4443, 8080, 9443, 143, 389, 1433, 5433, 27017, 6379, 9200,
        5986, 6443, 2376, 5061, 8883, 5671,
    }),
}


def resolve_ports(spec: str | None) -> list[int] | None:
    """Parse a --ports / port-field string: comma list of numbers and/or preset
    names (web, mail, dir, db, remote, all). Returns a deduped, order-preserving
    list, or None for an empty spec (caller falls back to DEFAULT_PORTS). Raises
    ValueError on a token that is neither a preset nor an integer."""
    if not spec:
        return None
    ports: list[int] = []
    for tok in spec.split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if tok in PORT_PRESETS:
            ports.extend(PORT_PRESETS[tok])
        else:
            p = int(tok)  # ValueError on junk — caller reports it
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of range (1-65535): {p}")
            ports.append(p)
    return list(dict.fromkeys(ports)) or None


# STARTTLS protocols keyed by port — the plaintext greeting/upgrade dance differs.
STARTTLS_SMTP = frozenset({25, 587})
STARTTLS_IMAP = frozenset({143})
STARTTLS_PORTS = STARTTLS_SMTP | STARTTLS_IMAP

# Feature detection: get_unverified_chain() landed in CPython 3.13. With it we can
# read the chain the server sent without a verifying handshake and validate it
# ourselves — collapsing the cert-grab and the trust-check into one connection.
_HAS_UNVERIFIED_CHAIN = hasattr(ssl.SSLSocket, "get_unverified_chain")

try:
    from cryptography.x509.verification import DNSName, IPAddress, PolicyBuilder, Store

    _HAS_VERIFIER = True
except ImportError:  # cryptography < 42
    _HAS_VERIFIER = False


# --------------------------------------------------------------------------- #
# certificate field extraction
# --------------------------------------------------------------------------- #
def _name(name: x509.Name, oid) -> str:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _readable_issuer(cert: x509.Certificate) -> str:
    org = _name(cert.issuer, NameOID.ORGANIZATION_NAME)
    cn = _name(cert.issuer, NameOID.COMMON_NAME)
    if org and cn:
        return f"{org} — {cn}"
    return org or cn or "Unknown issuer"


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def _aia_has_ca_issuers(cert: x509.Certificate) -> bool:
    """A cert carrying an AIA caIssuers URL is part of a real PKI chain — a strong
    signal it is not self-signed even when issuer == subject in odd setups."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        from cryptography.x509.oid import AuthorityInformationAccessOID

        return any(d.access_method == AuthorityInformationAccessOID.CA_ISSUERS for d in aia.value)
    except Exception:
        return False


def _is_self_signed(cert: x509.Certificate) -> bool:
    """issuer == subject is the usual tell; corroborate with SKI/AKI when present
    so a self-issued cert in a real chain isn't misread."""
    if cert.issuer != cert.subject:
        return False
    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value.key_identifier
        if aki is not None:
            return ski.digest == aki
    except Exception:
        pass
    return True


# --------------------------------------------------------------------------- #
# in-process trust validation
# --------------------------------------------------------------------------- #
def _load_system_roots() -> list[x509.Certificate]:
    """System trust anchors, gathered from wherever this platform keeps them.

    `SSLContext.get_ca_certs()` is empty on systems that load roots lazily from a
    directory (common on Linux), so we also read the configured CA bundle file
    and, failing that, the hashed capath directory. Real-world trust stores carry
    a few certs that trip deprecation warnings (non-RFC serials etc.); those are
    the platform's roots, not ours, so we load them quietly."""
    import os
    import warnings

    roots: list[x509.Certificate] = []

    def _load_pem(data: bytes) -> list[x509.Certificate]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return x509.load_pem_x509_certificates(data)

    # 1) certs already loaded into an SSL context's memory store
    try:
        ctx = ssl.create_default_context()
        for der in ctx.get_ca_certs(binary_form=True):
            try:
                roots.append(x509.load_der_x509_certificate(der))
            except Exception:
                pass
    except Exception:
        pass
    if roots:
        return roots

    paths = ssl.get_default_verify_paths()

    # 2) a single aggregate PEM bundle
    for cafile in (paths.cafile, paths.openssl_cafile, "/etc/ssl/certs/ca-certificates.crt"):
        if cafile and os.path.exists(cafile):
            try:
                with open(cafile, "rb") as fh:
                    roots = _load_pem(fh.read())
            except Exception:
                roots = []
            if roots:
                return roots

    # 3) a directory of individual PEM/.0 hashed certs
    for capath in (paths.capath, paths.openssl_capath):
        if capath and os.path.isdir(capath):
            for fn in os.listdir(capath):
                try:
                    with open(os.path.join(capath, fn), "rb") as fh:
                        roots.extend(_load_pem(fh.read()))
                except Exception:
                    continue
            if roots:
                return roots

    return roots


@lru_cache(maxsize=1)
def _trust_store():
    """System root certificates as a cryptography Store, built once."""
    if not _HAS_VERIFIER:
        return None
    roots = _load_system_roots()
    if not roots:
        return None
    try:
        return Store(roots)
    except Exception:
        return None


def _verify_chain_in_process(
    leaf: x509.Certificate, intermediates: list[x509.Certificate], host: str
) -> bool | None:
    """True/False if we can decide trust locally, None if we can't.

    Validates the chain the server presented against the system trust store and
    checks the hostname — i.e. "would a browser trust this right now". Expired or
    hostname-mismatched certs come back False, which is correct: the analyzer
    scores expiry separately, so there's no double counting of the *reason*.
    """
    store = _trust_store()
    if store is None:
        return None
    try:
        try:
            subject = IPAddress(ipaddress.ip_address(host))
        except ValueError:
            subject = DNSName(host)
        verifier = PolicyBuilder().store(store).build_server_verifier(subject)
        verifier.verify(leaf, intermediates)
        return True
    except Exception:
        # VerificationError (untrusted / expired / mismatch) -> not trusted.
        return False


# --------------------------------------------------------------------------- #
# STARTTLS upgrades (async)
# --------------------------------------------------------------------------- #
async def _read(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.read(n), timeout)


async def _starttls_smtp(reader, writer, timeout: float) -> None:
    await _read(reader, 1024, timeout)
    writer.write(b"EHLO fathom.local\r\n")
    await writer.drain()
    await _read(reader, 2048, timeout)
    writer.write(b"STARTTLS\r\n")
    await writer.drain()
    await _read(reader, 1024, timeout)


async def _starttls_imap(reader, writer, timeout: float) -> None:
    await _read(reader, 1024, timeout)
    writer.write(b"a1 STARTTLS\r\n")
    await writer.drain()
    await _read(reader, 1024, timeout)


def _permissive_ctx() -> ssl.SSLContext:
    """A deliberately non-verifying TLS context — DO NOT "harden" this.

    FATHOM's whole job is to inspect the certificate that's actually there:
    expired, self-signed, wrong-host, untrusted-CA. A verifying context aborts
    the handshake on exactly those certs and we'd never see them. We capture the
    cert here with verification OFF, then determine trust *separately* and
    safely, in-process, via `_verify_chain_in_process` (or `_verify_chain_network`
    as a fallback). Turning on check_hostname / CERT_NONE->CERT_REQUIRED would
    blind the scanner to every cert it most needs to report.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _aclose(writer) -> None:
    """Close a StreamWriter and await the transport closing, so we don't leak
    half-open TLS connections or trigger 'Unclosed transport' warnings. Bounded
    so a dead peer can't hang the close."""
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    except Exception:
        pass


async def _open_tls(host: str, port: int, ctx: ssl.SSLContext,
                    server_hostname: str | None, timeout: float):
    """Open a TLS stream to host:port — direct TLS, or plaintext + STARTTLS
    upgrade for SMTP/IMAP ports. Returns (reader, writer)."""
    if port in STARTTLS_PORTS:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        if port in STARTTLS_SMTP:
            await _starttls_smtp(reader, writer, timeout)
        else:
            await _starttls_imap(reader, writer, timeout)
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=server_hostname), timeout)
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname), timeout)
    return reader, writer


# --------------------------------------------------------------------------- #
# the probe
# --------------------------------------------------------------------------- #
async def probe(host: str, port: int, timeout: float = 6.0,
                max_sans: int | None = MAX_SANS) -> dict | None:
    """Probe a single host:port. Returns a cert record, or None if nothing
    listens / no certificate is offered. `max_sans` caps SANs stored per cert
    (None = keep all)."""
    result: dict = {"host": host, "port": port}
    server_hostname = None if _is_ip(host) else host
    ctx = _permissive_ctx()

    writer = None
    try:
        reader, writer = await _open_tls(host, port, ctx, server_hostname, timeout)
    except (TimeoutError, OSError, ssl.SSLError):
        return None  # closed / filtered / not TLS — skip silently
    except Exception:
        return None

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            return None
        try:
            negotiated = ssl_obj.version()
        except Exception:
            negotiated = None

        chain = _chain_from(ssl_obj)
        cert = x509.load_der_x509_certificate(der)
        self_signed = _is_self_signed(cert) and not _aia_has_ca_issuers(cert)

        # trust: in-process when we have the chain and a real hostname; else fall
        # back to a verifying network handshake; IP targets stay unknown (None).
        chain_trusted: bool | None
        if chain and server_hostname is not None:
            # cryptography's verifier releases the GIL, so running it off the event
            # loop keeps the loop free and lets verifications run in parallel.
            chain_trusted = await asyncio.to_thread(
                _verify_chain_in_process, cert, chain[1:], host
            )
        elif server_hostname is not None:
            chain_trusted = await _verify_chain_network(host, port, timeout)
        else:
            chain_trusted = None

        nb = _aware(cert, "not_valid_before")
        na = _aware(cert, "not_valid_after")
        key_type, key_bits = _key_info(cert)
        result.update(
            {
                "subject_cn": _name(cert.subject, NameOID.COMMON_NAME),
                "issuer": _readable_issuer(cert),
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
                "sans": _sans(cert)[:max_sans],
                "self_signed": self_signed,
                "serial": format(cert.serial_number, "x"),
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "tls_version": negotiated,
                "chain_trusted": chain_trusted,
                "key_type": key_type,
                "key_bits": key_bits,
                "sig_algo": _sig_algo(cert),
                "error": None,
            }
        )
        return result
    except Exception as e:
        result.update({"error": f"{type(e).__name__}: {e}", "self_signed": None})
        return result
    finally:
        if writer is not None:
            await _aclose(writer)


def _key_info(cert: x509.Certificate) -> tuple[str | None, int | None]:
    """(algorithm, bits) for the cert's public key — for weak-key flagging."""
    try:
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            return "RSA", pk.key_size
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return "EC", pk.curve.key_size
        if isinstance(pk, dsa.DSAPublicKey):
            return "DSA", pk.key_size
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return "Ed25519", 256
        if isinstance(pk, ed448.Ed448PublicKey):
            return "Ed448", 448
        return type(pk).__name__, None
    except Exception:
        return None, None


def _sig_algo(cert: x509.Certificate) -> str | None:
    try:
        algo = cert.signature_hash_algorithm
        return algo.name if algo else None
    except Exception:
        return None


def _aware(cert: x509.Certificate, field: str):
    """Timezone-aware notBefore/notAfter across cryptography versions."""
    val = getattr(cert, field + "_utc", None)
    if val is not None:
        return val
    return getattr(cert, field).replace(tzinfo=UTC)


def _chain_from(ssl_obj) -> list[x509.Certificate]:
    """The chain the server presented, leaf first. get_unverified_chain() yields
    raw DER bytes per certificate (CPython 3.13+)."""
    if not _HAS_UNVERIFIED_CHAIN:
        return []
    try:
        out = []
        for der in ssl_obj.get_unverified_chain() or []:
            if isinstance(der, (bytes, bytearray)):
                out.append(x509.load_der_x509_certificate(bytes(der)))
        return out
    except Exception:
        return []


async def _verify_chain_network(host: str, port: int, timeout: float) -> bool | None:
    """Fallback: a second handshake that verifies against the system store."""
    ctx = ssl.create_default_context()
    writer = None
    try:
        _, writer = await _open_tls(host, port, ctx, host, timeout)
        return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return None
    finally:
        if writer is not None:
            await _aclose(writer)


# backwards-compatible synchronous probe (some callers/tests expect it)
def probe_one(host: str, port: int, timeout: float = 6.0) -> dict | None:
    return asyncio.run(probe(host, port, timeout))


# --------------------------------------------------------------------------- #
# target expansion + scan orchestration
# --------------------------------------------------------------------------- #
MAX_EXPANDED_HOSTS = 65536  # ~a /16; guard against /8-style blowups that OOM


def expand_targets(targets: list[str], max_hosts: int = MAX_EXPANDED_HOSTS) -> list[str]:
    """Expand CIDR blocks; pass through hostnames and bare IPs. De-duplicates
    while preserving first-seen order. Raises ValueError if the target set would
    exceed `max_hosts`, so a fat-fingered /8 fails fast instead of exhausting
    memory."""
    out: list[str] = []
    seen: set[str] = set()

    def add(x: str):
        if x not in seen:
            seen.add(x)
            out.append(x)

    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            net = None  # not an IP/CIDR — treat as a hostname
        if net is not None and net.num_addresses > 1:
            # check before materializing so a huge range never starts expanding
            if net.num_addresses > max_hosts:
                raise ValueError(
                    f"{t} expands to {net.num_addresses} addresses "
                    f"(cap {max_hosts}). Narrow the range.")
            for ip in net.hosts():
                add(str(ip))
                if len(out) > max_hosts:
                    raise ValueError(
                        f"target set exceeds {max_hosts} hosts — narrow the scope.")
            continue
        add(t)  # hostname or single address
    return out


async def scan(
    targets: list[str],
    ports: list[int] | None = None,
    timeout: float = 6.0,
    concurrency: int = 100,
    progress=None,
    max_sans: int | None = MAX_SANS,
) -> list[dict]:
    """Scan every (host, port) pair concurrently. Returns cert records.

    Uses a fixed pool of `concurrency` workers pulling from a lazily-evaluated
    stream of (host, port) pairs, so memory stays bounded at ~concurrency even
    when the target set is huge — we never materialize one coroutine per pair.
    """
    ports = ports or DEFAULT_PORTS
    concurrency = max(1, int(concurrency))
    if timeout <= 0:
        timeout = 6.0

    hosts = expand_targets(targets)
    total = len(hosts) * len(ports)
    if total == 0:
        return []

    pairs = ((h, p) for h in hosts for p in ports)  # lazy — not materialized
    found: list[dict] = []
    done = 0

    async def worker():
        nonlocal done
        for host, port in pairs:  # safe: asyncio is single-threaded; next() is atomic
            rec = await probe(host, port, timeout, max_sans)
            done += 1
            if progress:
                progress(done, total, host, port)
            if rec:
                found.append(rec)

    await asyncio.gather(*(worker() for _ in range(min(concurrency, total))))
    return found
