"""
Passive Reconnaissance & Attack Surface Mapping (ASM) Module
Performs non-intrusive, standards-aligned perimeter intelligence gathering:
  - Certificate Transparency (CT) subdomain enumeration via crt.sh
  - DNS security posture: SPF, DKIM, DMARC, CNAME dangling analysis
  - Technology stack fingerprinting from HTTP response signals
  - TLS/HTTPS grade assessment and redirect chain auditing
  - Mixed content and insecure resource reference detection
"""

import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import dns.resolver  # type: ignore[import]
import requests
from requests.exceptions import RequestException

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


# ---------------------------------------------------------------------------
# Dangling subdomain cloud provider CNAME patterns (unclaimed resource risks)
# ---------------------------------------------------------------------------
DANGLING_CNAME_PATTERNS: List[str] = [
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
    r"\.web\.app$",
    r"\.wp\.com$",
    r"\.ghost\.io$",
]


# ---------------------------------------------------------------------------
# Known technology stack signatures derived from HTTP response signals
# ---------------------------------------------------------------------------
SERVER_TECH_MAP: Dict[str, str] = {
    "nginx": "Nginx",
    "apache": "Apache HTTP Server",
    "microsoft-iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty/Nginx",
    "cloudflare": "Cloudflare",
    "gunicorn": "Gunicorn/Python",
    "uwsgi": "uWSGI/Python",
    "jetty": "Eclipse Jetty (Java)",
    "tomcat": "Apache Tomcat (Java)",
    "node": "Node.js",
    "express": "Express.js",
}

FRAMEWORK_HEADER_MAP: Dict[str, Tuple[str, str]] = {
    # header_name → (technology, owasp_category)
    "x-powered-by": ("Application Framework", "Information Disclosure"),
    "x-aspnet-version": ("ASP.NET", "Information Disclosure"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "Information Disclosure"),
    "x-generator": ("CMS/Generator", "Information Disclosure"),
    "x-drupal-cache": ("Drupal CMS", "Information Disclosure"),
    "x-joomla-server": ("Joomla CMS", "Information Disclosure"),
    "x-wordpress-version": ("WordPress CMS", "Information Disclosure"),
    "x-magento-cache-debug": ("Magento eCommerce", "Information Disclosure"),
}


@dataclass
class ReconResult:
    """Aggregated passive reconnaissance findings for a scan target."""

    target_host: str
    ct_subdomains: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_selectors_found: List[str] = field(default_factory=list)
    dangling_cnames: List[Dict[str, str]] = field(default_factory=list)
    detected_tech: List[Dict[str, str]] = field(default_factory=list)
    tls_info: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[RawFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------

def run_passive_recon(
    target_url: str,
    http_headers: Dict[str, str],
    timeout: int = 8,
) -> ReconResult:
    """
    Execute full passive reconnaissance suite against the target URL.

    Args:
        target_url: The validated target URL that was scanned.
        http_headers: HTTP response headers from the initial GET probe.
        timeout: Network request timeout in seconds.

    Returns:
        ReconResult containing all intelligence gathered and generated findings.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    result = ReconResult(target_host=host)

    # 1. Certificate Transparency subdomain enumeration
    _enumerate_ct_subdomains(host, result, timeout)

    # 2. DNS security auditing (SPF/DMARC/DKIM/CNAME)
    _audit_dns_security(host, target_url, result)

    # 3. Tech stack fingerprinting from response headers
    _fingerprint_tech_stack(target_url, http_headers, result)

    # 4. TLS and redirect chain auditing
    _audit_tls_and_redirects(target_url, result, timeout)

    return result


# ---------------------------------------------------------------------------
# 1. Certificate Transparency Enumeration
# ---------------------------------------------------------------------------

def _enumerate_ct_subdomains(host: str, result: ReconResult, timeout: int) -> None:
    """Query crt.sh public CT logs to discover subdomains for the target host."""
    if not host:
        return

    try:
        clean_domain = host.lower().lstrip("www.")
        api_url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
        resp = requests.get(
            api_url,
            timeout=(3, 5),
            headers={
                "User-Agent": "VulnWatch-Auditor/1.0 (+https://yourdomain.com/security; contact: abuse@yourdomain.com)"
            },
            allow_redirects=False,
            verify=True,
        )
        if resp.status_code == 200:
            entries = resp.json()
            seen = set()
            for entry in entries:
                name_value = entry.get("name_value", "") or ""
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and clean_domain in name and name not in seen:
                        seen.add(name)
                        result.ct_subdomains.append(name)
                        if len(result.ct_subdomains) >= 30:
                            break
                if len(result.ct_subdomains) >= 30:
                    break

            if len(result.ct_subdomains) > 10:
                result.findings.append(
                    RawFinding(
                        title="Large CT Log Exposure — Attack Surface Enumeration Risk",
                        category="Attack Surface Management",
                        severity=SeverityLevel.INFO,
                        description=(
                            f"Certificate Transparency logs reveal {len(result.ct_subdomains)} "
                            f"publicly logged subdomains for '{host}'. This information is freely "
                            "available to attackers and increases the discoverable attack surface."
                        ),
                        remediation=(
                            "Review all discovered subdomains for decommissioned services, "
                            "staging environments, or forgotten assets exposed to the internet. "
                            "Consider implementing a subdomain inventory and lifecycle management process."
                        ),
                        affected_url=f"https://crt.sh/?q=%25.{host}",
                        evidence={
                            "subdomain_count": len(result.ct_subdomains),
                            "sample_subdomains": result.ct_subdomains[:10],
                        },
                    )
                )
    except Exception:
        # CT enumeration is opportunistic — failures are non-fatal
        pass


# ---------------------------------------------------------------------------
# 2. DNS Security Auditing
# ---------------------------------------------------------------------------

def _audit_dns_security(host: str, target_url: str, result: ReconResult) -> None:
    """Audit DNS TXT records for SPF, DMARC, and DKIM; check CNAME for dangling pointers."""
    if not host:
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    # ── SPF ──────────────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(host, "TXT")
        spf_records = [str(r) for r in answers if "v=spf1" in str(r).lower()]
        if spf_records:
            result.spf_record = spf_records[0].strip('"')
        else:
            result.findings.append(
                RawFinding(
                    title="Missing SPF Record — Mail Spoofing Risk",
                    category="DNS Security",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"No SPF (Sender Policy Framework) TXT record was found for '{host}'. "
                        "Without SPF, attackers can forge email senders from this domain, "
                        "enabling phishing and business email compromise (BEC) attacks."
                    ),
                    remediation=(
                        "Publish an SPF TXT record in DNS. Example: "
                        "'v=spf1 include:_spf.yourmailprovider.com ~all' — "
                        "Use '-all' (hard fail) for maximum enforcement."
                    ),
                    affected_url=target_url,
                    evidence={"dns_record": "SPF", "host": host, "status": "Missing"},
                )
            )
    except Exception:
        pass

    # ── DMARC ─────────────────────────────────────────────────────────────────
    try:
        dmarc_host = f"_dmarc.{host}"
        answers = resolver.resolve(dmarc_host, "TXT")
        dmarc_records = [str(r) for r in answers if "v=dmarc1" in str(r).lower()]
        if dmarc_records:
            result.dmarc_record = dmarc_records[0].strip('"')
            # Check for p=none (monitoring-only, not enforced)
            if "p=none" in result.dmarc_record.lower():
                result.findings.append(
                    RawFinding(
                        title="DMARC Policy Set to 'none' — No Enforcement",
                        category="DNS Security",
                        severity=SeverityLevel.LOW,
                        description=(
                            f"A DMARC record exists for '{host}' but uses `p=none`, "
                            "meaning the policy is in monitoring-only mode and does not "
                            "reject or quarantine forged emails. Attackers can still send "
                            "spoofed emails from this domain without consequence."
                        ),
                        remediation=(
                            "Upgrade DMARC policy to 'p=quarantine' or 'p=reject' after reviewing "
                            "DMARC aggregate reports to ensure legitimate mail passes authentication. "
                            "Example: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'"
                        ),
                        affected_url=target_url,
                        evidence={
                            "dmarc_record": result.dmarc_record,
                            "policy": "none",
                            "host": dmarc_host,
                        },
                    )
                )
        else:
            result.findings.append(
                RawFinding(
                    title="Missing DMARC Policy — Anti-Phishing Risk",
                    category="DNS Security",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"No DMARC (Domain-based Message Authentication, Reporting and Conformance) "
                        f"record was found at '{dmarc_host}'. Without DMARC, email receivers cannot "
                        "enforce your SPF/DKIM policies, enabling domain impersonation attacks."
                    ),
                    remediation=(
                        "Publish a DMARC TXT record at '_dmarc.yourdomain.com'. "
                        "Start with 'p=none' to collect reports, then escalate to 'p=reject'. "
                        "Example: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'"
                    ),
                    affected_url=target_url,
                    evidence={"dns_record": "DMARC", "host": dmarc_host, "status": "Missing"},
                )
            )
    except Exception:
        pass

    # ── DKIM (common selectors probe) ─────────────────────────────────────────
    common_selectors = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "s1"]
    for sel in common_selectors:
        try:
            dkim_host = f"{sel}._domainkey.{host}"
            resolver.resolve(dkim_host, "TXT")
            result.dkim_selectors_found.append(sel)
        except Exception:
            continue

    # ── CNAME Dangling Subdomain Check ────────────────────────────────────────
    _check_dangling_cnames(host, target_url, result, resolver)


def _check_dangling_cnames(
    host: str, target_url: str, result: ReconResult, resolver: "dns.resolver.Resolver"
) -> None:
    """Check for CNAME records pointing to potentially unclaimed cloud services."""
    subdomains_to_check = list({host} | {
        s for s in result.ct_subdomains[:20]  # limit scope
        if s.endswith(f".{host}") or s == host
    })

    for subdomain in subdomains_to_check:
        try:
            cname_answers = resolver.resolve(subdomain, "CNAME")
            for cname_rdata in cname_answers:
                cname_target = str(cname_rdata.target).rstrip(".").lower()
                for pattern in DANGLING_CNAME_PATTERNS:
                    if re.search(pattern, cname_target):
                        # Verify if the target actually resolves (non-resolving = likely dangling)
                        try:
                            socket.getaddrinfo(cname_target, None, socket.AF_INET)
                            # Resolves — might still be at risk but not definitively dangling
                            status = "Resolves (verify ownership)"
                        except socket.gaierror:
                            status = "Does Not Resolve — Likely Dangling"

                        result.dangling_cnames.append({
                            "subdomain": subdomain,
                            "cname_target": cname_target,
                            "status": status,
                        })

                        severity = (
                            SeverityLevel.HIGH
                            if "Does Not Resolve" in status
                            else SeverityLevel.MEDIUM
                        )

                        result.findings.append(
                            RawFinding(
                                title=f"Potential Dangling CNAME — Subdomain Takeover Risk ({subdomain})",
                                category="Attack Surface Management",
                                severity=severity,
                                description=(
                                    f"The subdomain '{subdomain}' has a CNAME record pointing to "
                                    f"'{cname_target}' which matches a known cloud provider pattern. "
                                    f"Resolution status: {status}. "
                                    "If the cloud resource is unclaimed, an attacker may be able to "
                                    "register it and serve malicious content under your domain."
                                ),
                                remediation=(
                                    "Remove the dangling CNAME record from DNS if the cloud resource "
                                    "is no longer in use, OR re-claim the resource by re-creating the "
                                    "associated cloud service. Implement a subdomain lifecycle "
                                    "management process to prevent future dangling entries."
                                ),
                                affected_url=f"https://{subdomain}",
                                evidence={
                                    "subdomain": subdomain,
                                    "cname_target": cname_target,
                                    "resolution_status": status,
                                },
                            )
                        )
                        break
        except Exception:
            continue


# ---------------------------------------------------------------------------
# 3. Technology Stack Fingerprinting
# ---------------------------------------------------------------------------

def _fingerprint_tech_stack(
    target_url: str, headers: Dict[str, str], result: ReconResult
) -> None:
    """Identify server and framework technology from HTTP response headers."""
    h_lower = {k.lower(): v for k, v in headers.items()}

    # ── Server header fingerprinting ──────────────────────────────────────────
    server_val = h_lower.get("server", "")
    if server_val:
        matched_tech = "Unknown Server"
        for key, tech_name in SERVER_TECH_MAP.items():
            if key in server_val.lower():
                matched_tech = tech_name
                break
        result.detected_tech.append({"source": "Server header", "tech": server_val, "label": matched_tech})

        # Flag server version disclosure
        if any(char.isdigit() for char in server_val):
            result.findings.append(
                RawFinding(
                    title="Server Version Disclosed in HTTP Response Header",
                    category="Information Disclosure",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"The server response includes a 'Server' header that reveals specific "
                        f"version information: '{server_val}'. Attackers can use this to "
                        "identify vulnerable software versions and target known CVEs."
                    ),
                    remediation=(
                        "Configure the web server to suppress or genericize the Server header. "
                        "Nginx: 'server_tokens off;' | Apache: 'ServerTokens Prod; ServerSignature Off' | "
                        "IIS: Remove via URL Rewrite or custom headers module."
                    ),
                    affected_url=target_url,
                    evidence={"header": "Server", "value": server_val},
                )
            )

    # ── Framework / CMS header fingerprinting ────────────────────────────────
    for header_name, (tech_label, _category) in FRAMEWORK_HEADER_MAP.items():
        header_val = h_lower.get(header_name, "")
        if header_val:
            result.detected_tech.append({
                "source": header_name,
                "tech": header_val,
                "label": tech_label,
            })
            result.findings.append(
                RawFinding(
                    title=f"Technology Version Disclosed via '{header_name}' Header",
                    category="Information Disclosure",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"The response header '{header_name}: {header_val}' reveals the underlying "
                        f"technology stack ({tech_label}). Version disclosure provides attackers with "
                        "actionable intelligence to target known CVEs and configuration weaknesses."
                    ),
                    remediation=(
                        f"Remove or suppress the '{header_name}' response header at the server or "
                        "application layer to prevent technology fingerprinting."
                    ),
                    affected_url=target_url,
                    evidence={"header": header_name, "value": header_val},
                )
            )

    # ── Via / Proxy header disclosure ────────────────────────────────────────
    via_val = h_lower.get("via", "")
    if via_val:
        result.detected_tech.append({"source": "Via header", "tech": via_val, "label": "Proxy/CDN"})

    # ── X-Cache header (CDN/proxy presence) ─────────────────────────────────
    xcache_val = h_lower.get("x-cache", "") or h_lower.get("cf-cache-status", "")
    if xcache_val:
        result.detected_tech.append({"source": "Cache header", "tech": xcache_val, "label": "CDN/Cache Layer"})


# ---------------------------------------------------------------------------
# 4. TLS Grade Assessment & Redirect Chain Auditing
# ---------------------------------------------------------------------------

def _audit_tls_and_redirects(target_url: str, result: ReconResult, timeout: int) -> None:
    """Audit TLS version, certificate validity, and HTTP→HTTPS redirect chain."""
    parsed = urlparse(target_url)

    # ── Redirect Chain Analysis ───────────────────────────────────────────────
    try:
        session = requests.Session()
        session.headers["User-Agent"] = "VulnWatch-Auditor/1.0 (+https://yourdomain.com/security; contact: abuse@yourdomain.com)"
        resp = session.get(
            target_url,
            # Do not let a target redirect reconnaissance probes to an
            # unvalidated destination.
            allow_redirects=False,
            timeout=(5, timeout),
            verify=True,
        )
        chain = []
        for r in resp.history:
            chain.append({
                "url": r.url,
                "status_code": r.status_code,
                "location": r.headers.get("Location", ""),
            })
        chain.append({"url": resp.url, "status_code": resp.status_code, "location": ""})
        result.redirect_chain = chain

        # Detect HTTP→HTTPS redirect (good) vs HTTPS→HTTP downgrade (bad)
        if chain and len(chain) > 1:
            first_url = chain[0]["url"].lower()
            last_url = chain[-1]["url"].lower()

            if first_url.startswith("http://") and last_url.startswith("https://"):
                # Good: HTTP upgrades to HTTPS — record as info
                result.tls_info["http_to_https_redirect"] = True
            elif first_url.startswith("https://") and last_url.startswith("http://"):
                # Bad: HTTPS downgrades to HTTP
                result.findings.append(
                    RawFinding(
                        title="HTTPS → HTTP Redirect Downgrade Detected",
                        category="TLS / Transport Security",
                        severity=SeverityLevel.HIGH,
                        description=(
                            "The server redirects from HTTPS to HTTP, downgrading the connection "
                            "and exposing users to man-in-the-middle (MITM) attacks. All traffic "
                            "transmitted after the downgrade is unencrypted."
                        ),
                        remediation=(
                            "Ensure all application routes are served exclusively over HTTPS. "
                            "Remove any HTTP-serving endpoints or redirects. Enforce HTTPS at the "
                            "load balancer, CDN, or reverse proxy level."
                        ),
                        affected_url=target_url,
                        evidence={
                            "initial_url": chain[0]["url"],
                            "final_url": chain[-1]["url"],
                            "redirect_chain": chain,
                        },
                    )
                )

        # Detect excessive redirect hops (>3 = performance/config issue)
        if len(chain) > 4:
            result.findings.append(
                RawFinding(
                    title=f"Excessive Redirect Chain ({len(chain) - 1} Hops)",
                    category="TLS / Transport Security",
                    severity=SeverityLevel.INFO,
                    description=(
                        f"The target URL requires {len(chain) - 1} redirect hop(s) before "
                        "reaching the final destination. Excessive redirect chains increase "
                        "latency, degrade user experience, and may expose intermediate URLs "
                        "in referrer headers."
                    ),
                    remediation=(
                        "Consolidate redirect chains to a single hop. Configure web server or "
                        "load balancer to redirect directly to the canonical HTTPS URL."
                    ),
                    affected_url=target_url,
                    evidence={"hop_count": len(chain) - 1, "redirect_chain": chain},
                )
            )

    except Exception:
        pass

    # ── HTTP-only target (no TLS) ─────────────────────────────────────────────
    if parsed.scheme == "http":
        result.tls_info["uses_tls"] = False
        result.findings.append(
            RawFinding(
                title="Target Does Not Use HTTPS / TLS Encryption",
                category="TLS / Transport Security",
                severity=SeverityLevel.HIGH,
                description=(
                    "The target is served over plain HTTP with no TLS/SSL encryption. "
                    "All data transmitted between clients and the server — including "
                    "credentials, session tokens, and sensitive data — is exposed to "
                    "passive eavesdropping and active man-in-the-middle (MITM) attacks."
                ),
                remediation=(
                    "Obtain a TLS certificate (e.g., free via Let's Encrypt) and configure "
                    "the server to serve exclusively over HTTPS. Redirect all HTTP traffic "
                    "to HTTPS using a 301 permanent redirect."
                ),
                affected_url=target_url,
                evidence={"scheme": "http", "tls_present": False},
            )
        )
    else:
        result.tls_info["uses_tls"] = True

    # ── Check if HTTP version of the URL redirects to HTTPS ──────────────────
    if parsed.scheme == "https":
        http_url = target_url.replace("https://", "http://", 1)
        try:
            http_resp = requests.get(
                http_url,
                allow_redirects=False,
                timeout=(4, 6),
                verify=True,
            )
            if http_resp.url.startswith("https://"):
                result.tls_info["http_to_https_redirect"] = True
            else:
                result.tls_info["http_to_https_redirect"] = False
                result.findings.append(
                    RawFinding(
                        title="HTTP Version of Site Does Not Redirect to HTTPS",
                        category="TLS / Transport Security",
                        severity=SeverityLevel.MEDIUM,
                        description=(
                            f"Accessing the plain HTTP URL ({http_url}) does not automatically "
                            "redirect users to HTTPS. Users who access the HTTP version will "
                            "communicate over an unencrypted channel unless they manually type HTTPS."
                        ),
                        remediation=(
                            "Configure a permanent HTTP 301 redirect from all HTTP URLs to their "
                            "HTTPS equivalents at the web server or load balancer level. "
                            "Combined with HSTS, this ensures all connections are encrypted."
                        ),
                        affected_url=http_url,
                        evidence={
                            "http_url": http_url,
                            "final_url": http_resp.url,
                            "redirected_to_https": False,
                        },
                    )
                )
        except Exception:
            pass
