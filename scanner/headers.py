from typing import Dict, List
from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


def audit_headers(target_url: str, headers: Dict[str, str]) -> List[RawFinding]:
    """Audits HTTP response headers for missing or misconfigured security controls."""
    findings: List[RawFinding] = []
    # Case-insensitive headers lookup table
    h_lower = {k.lower(): v for k, v in headers.items()}
    is_https = target_url.lower().startswith("https://")

    # 1. HTTP Strict Transport Security (HSTS)
    if is_https:
        hsts = h_lower.get("strict-transport-security")
        if not hsts:
            findings.append(
                RawFinding(
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    category="Security Headers",
                    severity=SeverityLevel.HIGH,
                    description="The server does not enforce HTTPS via the Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                    affected_url=target_url,
                    evidence={"header": "Strict-Transport-Security", "status": "Missing"},
                )
            )
        else:
            if "max-age" not in hsts.lower():
                findings.append(
                    RawFinding(
                        title="Invalid HSTS Configuration (Missing max-age)",
                        category="Security Headers",
                        severity=SeverityLevel.MEDIUM,
                        description="HSTS header is present but missing the mandatory max-age directive.",
                        remediation="Ensure the HSTS header specifies max-age (e.g. max-age=31536000).",
                        affected_url=target_url,
                        evidence={"header": "Strict-Transport-Security", "value": hsts},
                    )
                )

    # 2. Content Security Policy (CSP)
    csp = h_lower.get("content-security-policy")
    if not csp:
        findings.append(
            RawFinding(
                title="Missing Content Security Policy (CSP)",
                category="Security Headers",
                severity=SeverityLevel.HIGH,
                description="Content Security Policy header is not present. CSP prevents Cross-Site Scripting (XSS) and data injection attacks.",
                remediation="Implement a strong Content-Security-Policy header restricting script execution and resource loading.",
                affected_url=target_url,
                evidence={"header": "Content-Security-Policy", "status": "Missing"},
            )
        )
    else:
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            findings.append(
                RawFinding(
                    title="Weak Content Security Policy Directive Detected",
                    category="Security Headers",
                    severity=SeverityLevel.MEDIUM,
                    description="The CSP header contains 'unsafe-inline' or 'unsafe-eval', which diminishes protection against inline XSS attacks.",
                    remediation="Refactor inline scripts to external files and utilize nonces or hashes instead of unsafe directives.",
                    affected_url=target_url,
                    evidence={"header": "Content-Security-Policy", "value": csp},
                )
            )

    # 3. X-Frame-Options
    xfo = h_lower.get("x-frame-options")
    if not xfo:
        findings.append(
            RawFinding(
                title="Missing X-Frame-Options Header",
                category="Security Headers",
                severity=SeverityLevel.MEDIUM,
                description="The X-Frame-Options header is absent, rendering the application potentially susceptible to Clickjacking framing attacks.",
                remediation="Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' on HTTP responses.",
                affected_url=target_url,
                evidence={"header": "X-Frame-Options", "status": "Missing"},
            )
        )
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(
            RawFinding(
                title="Non-standard X-Frame-Options Header Value",
                category="Security Headers",
                severity=SeverityLevel.LOW,
                description=f"X-Frame-Options set to '{xfo}', which may not properly restrict framing in legacy browsers.",
                remediation="Set X-Frame-Options explicitly to DENY or SAMEORIGIN.",
                affected_url=target_url,
                evidence={"header": "X-Frame-Options", "value": xfo},
            )
        )

    # 4. X-Content-Type-Options
    xcto = h_lower.get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(
            RawFinding(
                title="Missing or Invalid X-Content-Type-Options Header",
                category="Security Headers",
                severity=SeverityLevel.MEDIUM,
                description="Missing 'X-Content-Type-Options: nosniff' header allows browsers to MIME-sniff response content types, potentially executing untrusted assets.",
                remediation="Set 'X-Content-Type-Options: nosniff' header across all responses.",
                affected_url=target_url,
                evidence={
                    "header": "X-Content-Type-Options",
                    "value": xcto if xcto else "Missing",
                },
            )
        )

    # 5. Referrer-Policy
    ref_pol = h_lower.get("referrer-policy")
    if not ref_pol:
        findings.append(
            RawFinding(
                title="Missing Referrer-Policy Header",
                category="Security Headers",
                severity=SeverityLevel.LOW,
                description="No Referrer-Policy header specified. Browsers may send full referrer URLs containing sensitive path parameters.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                affected_url=target_url,
                evidence={"header": "Referrer-Policy", "status": "Missing"},
            )
        )

    # 6. Permissions-Policy
    perm_pol = h_lower.get("permissions-policy") or h_lower.get("feature-policy")
    if not perm_pol:
        findings.append(
            RawFinding(
                title="Missing Permissions-Policy Header",
                category="Security Headers",
                severity=SeverityLevel.INFO,
                description="Permissions-Policy header is missing. Controlling browser features (geolocation, camera, microphone) is recommended.",
                remediation="Define a Permissions-Policy header to restrict access to hardware APIs.",
                affected_url=target_url,
                evidence={"header": "Permissions-Policy", "status": "Missing"},
            )
        )

    # 7. Technology Information Disclosure (Server / X-Powered-By)
    server_header = h_lower.get("server")
    x_powered_by = h_lower.get("x-powered-by")

    if x_powered_by:
        findings.append(
            RawFinding(
                title="Server Technology Information Leakage (X-Powered-By)",
                category="Information Disclosure",
                severity=SeverityLevel.LOW,
                description=f"The server leaks detailed backend technology stack information: '{x_powered_by}'.",
                remediation="Disable or strip X-Powered-By response headers in server configurations.",
                affected_url=target_url,
                evidence={"header": "X-Powered-By", "value": x_powered_by},
            )
        )

    if server_header and any(char.isdigit() for char in server_header):
        findings.append(
            RawFinding(
                title="Server Software Version Disclosure",
                category="Information Disclosure",
                severity=SeverityLevel.INFO,
                description=f"The Server header discloses precise software version numbers: '{server_header}'.",
                remediation="Configure web server to suppress banner version details (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
                affected_url=target_url,
                evidence={"header": "Server", "value": server_header},
            )
        )

    return findings
