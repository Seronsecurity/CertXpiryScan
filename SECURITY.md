# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.
Email **security@seronsecurity.com** with a description, reproduction steps, and the
affected version. We aim to acknowledge within a few business days.

Please do not file public issues for vulnerabilities until a fix is available.

## Scope and intended use

This is a **read-only** assessment tool. It connects to TLS endpoints, reads
the certificate they present, and reports on it. It never issues, modifies,
renews, or deletes certificates, and it transmits no credentials or payloads to
the targets.

**Authorized use only.** Run only against domains, hosts, and networks
you own or have explicit written permission to assess. The discovery and scan
passes (DNS resolution, the optional brute pass, and the port scan) make active
connections to the targets you provide; Certificate Transparency lookups via
crt.sh are passive reads of public logs. Unauthorized scanning may violate law
or policy.

## Handling of untrusted data

Certificate fields (issuer, subject CN, SANs) are attacker-controlled — a
malicious endpoint can present a certificate containing arbitrary bytes. You should
always treat all certificate-supplied strings as hostile and "HTML-escape" them before
they reach any rendered output (the web dashboard, the HTML report, and GUI
tooltips). When harvesting, this disables certificate verification *only* to
read whatever certificate is presented (including expired or self-signed ones);
it never sends data over those connections and never trusts the harvested
material as a basis for further action.
