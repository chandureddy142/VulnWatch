"""
DNS Security & Email Posture Analyzer (Enterprise Module)
=========================================================
Performs passive DNS reconnaissance:
  - DNSSEC validation (DNSKEY / RRSIG)
  - CAA record presence
  - DMARC policy strictness and BIMI selector
  - Dangling CNAME detection against cloud provider patterns

All operations use read-only DNS queries — no active exploitation.
"""
from __future__ import annotations

import re
import socket
from typing import List

import dns.exception
import dns.rdatatype
import dns.resolver

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel

# Cloud provider CNAME target patterns that may indicate subdomain takeover risk
DANGLING_CNAME_PATTERNS = [
    r"\.s3\.amazonaws\.com$",
    r"\.s3-[a-z0-9-]+\.amazonaws\.com$",
    r"\.elasticbeanstalk\.com$",
    r"\.azurewebsites\.net$",
    r"\.cloudapp\.azure\.com$",
    r"\.github\.io$",
    r"\.myshopify\.com$",
    r"\.pantheonsite\.io$",
    r"\.readthedocs\.io$",
    r"\.surge\.sh$",
    r"\.netlify\.app$",
    r"\.vercel\.app$",
    r"\.firebaseapp\.com$",
    r"\.fastly\.net$",
    r"\.herokuapp\.com$",
    r"\.fly\.dev$",
]

_DMARC_SELECTOR_RE = re.compile(r"p\s*=\s*([a-z]+)", re.IGNORECASE)


def _resolve_txt(qname: str, timeout: float = 4.0) -> List[str]:
    """Resolve TXT records for a domain name. Returns list of record strings."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(qname, "TXT")
        records = []
        for rdata in answers:
            for string in rdata.strings:
                records.append(string.decode("utf-8", errors="ignore") if isinstance(string, bytes) else string)
        return records
    except Exception:
        return []


def _resolve_caa(domain: str, timeout: float = 4.0) -> List[str]:
    """Resolve CAA records. Returns raw string representations."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "CAA")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def _has_dnssec(domain: str, timeout: float = 5.0) -> bool:
    """Check if domain publishes DNSKEY records (DNSSEC indicator)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False


def _get_cname(subdomain: str, timeout: float = 3.0):
    """Returns the CNAME target string for a subdomain, or None if not a CNAME."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None


def _is_nxdomain(host: str) -> bool:
    """Check if hostname resolves to NXDOMAIN (unregistered)."""
    try:
        socket.getaddrinfo(host, None)
        return False
    except socket.gaierror:
        return True


def audit_dns_sec(domain: str, subdomains: List[str] | None = None) -> List[RawFinding]:
    """
    Passive DNS security posture analyzer.

    Args:
        domain: Apex domain to audit (e.g. 'example.com').
        subdomains: Optional list of subdomains to check for dangling CNAMEs.

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    if not domain or domain in ("localhost", "127.0.0.1"):
        return findings

    # ── 1. DNSSEC ──────────────────────────────────────────────────────────────
    try:
        has_dnssec = _has_dnssec(domain)
        if not has_dnssec:
            findings.append(RawFinding(
                title="DNSSEC Not Enabled",
                category="DNS & Mail Security",
                severity=SeverityLevel.LOW,
                description=(
                    f"The domain '{domain}' does not publish DNSKEY records, indicating "
                    "DNSSEC is not deployed. Without DNSSEC, DNS responses cannot be "
                    "cryptographically verified, leaving the domain susceptible to DNS cache "
                    "poisoning and Kaminsky-style spoofing attacks."
                ),
                remediation=(
                    "Enable DNSSEC signing at your DNS registrar or authoritative DNS provider. "
                    "Publish DS records at your domain registrar and configure DNSKEY/RRSIG records. "
                    "Use DNSSEC validators at https://dnssec-analyzer.verisignlabs.com/"
                ),
                affected_url=f"dns://{domain}",
                evidence={"domain": domain, "dnskey_present": False},
            ))
    except Exception:
        pass

    # ── 2. CAA Records ─────────────────────────────────────────────────────────
    try:
        caa_records = _resolve_caa(domain)
        if not caa_records:
            findings.append(RawFinding(
                title="CAA Record Not Configured",
                category="DNS & Mail Security",
                severity=SeverityLevel.INFO,
                description=(
                    f"No Certification Authority Authorization (CAA) records found for '{domain}'. "
                    "Without CAA records, any public Certificate Authority can issue TLS certificates "
                    "for this domain. Misconfigured or compromised CAs could issue unauthorized "
                    "certificates, enabling MITM attacks."
                ),
                remediation=(
                    "Add CAA records specifying which CAs are permitted to issue certificates for your domain. "
                    "Example: '0 issue \"letsencrypt.org\"'. This prevents unauthorized certificate issuance."
                ),
                affected_url=f"dns://{domain}",
                evidence={"domain": domain, "caa_records": []},
            ))
    except Exception:
        pass

    # ── 3. DMARC Strictness ────────────────────────────────────────────────────
    try:
        dmarc_records = _resolve_txt(f"_dmarc.{domain}")
        if not dmarc_records:
            findings.append(RawFinding(
                title="DMARC Record Missing",
                category="DNS & Mail Security",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"No DMARC TXT record found at '_dmarc.{domain}'. Without DMARC, "
                    "malicious actors can send spoofed emails appearing to originate from "
                    "your domain, enabling phishing campaigns."
                ),
                remediation=(
                    "Publish a DMARC TXT record at '_dmarc.yourdomain.com' starting with "
                    "'v=DMARC1; p=quarantine; ...' and progressively enforce to 'p=reject'. "
                    "Use a DMARC reporting address (rua=) to monitor abuse."
                ),
                affected_url=f"dns://_dmarc.{domain}",
                evidence={"dmarc_record": None},
            ))
        else:
            dmarc_value = " ".join(dmarc_records)
            policy_match = _DMARC_SELECTOR_RE.search(dmarc_value)
            policy = policy_match.group(1).lower() if policy_match else "none"
            if policy == "none":
                findings.append(RawFinding(
                    title="DMARC Policy Set to 'p=none' (Not Enforced)",
                    category="DNS & Mail Security",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"The DMARC policy for '{domain}' is set to 'p=none', meaning failing "
                        "messages are only monitored — not quarantined or rejected. This provides "
                        "no active protection against email spoofing and phishing."
                    ),
                    remediation=(
                        "Progressively harden DMARC by changing from 'p=none' to 'p=quarantine', "
                        "then to 'p=reject' once legitimate mail flows are confirmed. "
                        "Monitor DMARC aggregate reports to identify misconfigurations."
                    ),
                    affected_url=f"dns://_dmarc.{domain}",
                    evidence={"dmarc_record": dmarc_value, "policy": policy},
                ))
    except Exception:
        pass

    # ── 4. BIMI Selector (Informational) ───────────────────────────────────────
    try:
        bimi_records = _resolve_txt(f"default._bimi.{domain}")
        if bimi_records:
            findings.append(RawFinding(
                title="BIMI Selector Detected",
                category="DNS & Mail Security",
                severity=SeverityLevel.INFO,
                description=(
                    f"A BIMI (Brand Indicators for Message Identification) TXT record was discovered "
                    f"at 'default._bimi.{domain}'. BIMI enables brand logo display in supporting email "
                    "clients and requires a DMARC policy of 'p=quarantine' or 'p=reject'."
                ),
                remediation="Ensure the BIMI VMC certificate remains valid and the logo URL is reachable.",
                affected_url=f"dns://default._bimi.{domain}",
                evidence={"bimi_record": bimi_records[0] if bimi_records else None},
            ))
    except Exception:
        pass

    # ── 5. Dangling CNAMEs ─────────────────────────────────────────────────────
    hosts_to_check = list({domain} | set((subdomains or [])[:20]))
    for subdomain in hosts_to_check:
        try:
            cname_target = _get_cname(subdomain, timeout=3.0)
            if not cname_target:
                continue
            for pattern in DANGLING_CNAME_PATTERNS:
                if re.search(pattern, cname_target, re.IGNORECASE):
                    if _is_nxdomain(cname_target):
                        findings.append(RawFinding(
                            title=f"Potential Subdomain Takeover — Dangling CNAME",
                            category="DNS & Mail Security",
                            severity=SeverityLevel.HIGH,
                            description=(
                                f"'{subdomain}' has a CNAME pointing to '{cname_target}' which resolves "
                                "to NXDOMAIN (unregistered). An attacker may be able to claim this "
                                "resource and serve malicious content under your domain name."
                            ),
                            remediation=(
                                f"Immediately remove the CNAME record for '{subdomain}' or re-provision "
                                f"the resource at '{cname_target}'. Audit all DNS records for similar "
                                "dangling references to cloud platforms."
                            ),
                            affected_url=f"dns://{subdomain}",
                            evidence={"subdomain": subdomain, "cname_target": cname_target},
                        ))
                    break
        except Exception:
            continue

    return findings
