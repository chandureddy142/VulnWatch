"""
CORS Configuration & Credential Exposure Analyzer (Enterprise Module)
======================================================================
Passively evaluates CORS headers for:
  - Wildcard origin with credentials exposure
  - Arbitrary Origin reflection (attacker-controlled origin echoed back)
  - Null-origin acceptance (allows sandboxed iframe bypass)
  - Insecure CORS on sensitive API-style endpoints

All checks use the already-captured response headers — the reflection test
makes a single additional HEAD request with a canary Origin value.

CWE-942 / OWASP A01:2021-Broken Access Control
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel

_CANARY_ORIGIN = "https://cors-probe.vulnwatch.internal"
_SENSITIVE_PATH_RE = re.compile(
    r"(/api|/v\d|/graphql|/admin|/auth|/token|/login|/user|/account|/private)",
    re.IGNORECASE,
)


def _probe_reflected_origin(
    url: str, canary: str, timeout: float = 5.0
) -> Optional[str]:
    """
    Send a request with a canary Origin header and return the value of
    Access-Control-Allow-Origin from the response, or None on failure.
    """
    try:
        resp = requests.get(
            url,
            headers={"Origin": canary, "User-Agent": "VulnWatch-CORS-Probe/2.0"},
            timeout=(3, timeout),
            allow_redirects=False,
            verify=True,
        )
        return resp.headers.get("Access-Control-Allow-Origin", "")
    except Exception:
        return None


def audit_cors(
    headers: Dict[str, str],
    target_url: str = "",
    probe_reflection: bool = True,
) -> List[RawFinding]:
    """
    Passive CORS configuration and credential exposure analyzer.

    Args:
        headers: HTTP response headers dict (case-insensitive keys acceptable).
        target_url: The target URL for probe requests and finding context.
        probe_reflection: If True, send one HEAD request to test arbitrary origin reflection.

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    norm = {k.lower(): v for k, v in headers.items()}

    acao = norm.get("access-control-allow-origin", "").strip()
    acac = norm.get("access-control-allow-credentials", "").strip().lower()
    acam = norm.get("access-control-allow-methods", "").strip()
    acah = norm.get("access-control-allow-headers", "").strip()

    if not acao:
        # No CORS headers present — not a finding, just skip
        return findings

    # ── 1. Wildcard + Credentials (browser rejects but signals bad config) ─────
    if acao == "*" and acac == "true":
        findings.append(RawFinding(
            title="CORS: Wildcard Origin with Credentials Permitted",
            category="CORS",
            severity=SeverityLevel.HIGH,
            description=(
                "'Access-Control-Allow-Origin: *' is set simultaneously with "
                "'Access-Control-Allow-Credentials: true'. Browsers reject this combination "
                "per the CORS specification, but its presence signals a deeply misconfigured CORS "
                "policy. Some non-browser HTTP clients may accept both, exposing session credentials "
                "to any cross-origin attacker."
            ),
            remediation=(
                "Never use 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. "
                "Maintain an explicit server-side allowlist of trusted origins and reflect only validated "
                "origins. Use framework-level CORS middleware (Flask-CORS, django-cors-headers, etc.)."
            ),
            affected_url=target_url,
            evidence={
                "acao": acao, "acac": acac, "acam": acam,
                "cwe": "CWE-942",
                "owasp": "A01:2021-Broken Access Control",
            },
        ))

    elif acao == "*":
        # Wildcard without credentials — lower severity, only flag for sensitive paths
        parsed = urlparse(target_url)
        if _SENSITIVE_PATH_RE.search(parsed.path):
            findings.append(RawFinding(
                title="CORS: Wildcard Origin on Sensitive Endpoint",
                category="CORS",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"'Access-Control-Allow-Origin: *' is set on '{target_url}' which appears to be "
                    "a sensitive endpoint (API, auth, or admin path). Any web page on the internet "
                    "can make cross-origin requests to this endpoint and read the response."
                ),
                remediation=(
                    "Restrict CORS to an explicit allowlist of trusted origin domains for sensitive "
                    "endpoints. Use conditional CORS that only reflects the 'Origin' header when it "
                    "matches a pre-approved list."
                ),
                affected_url=target_url,
                evidence={
                    "acao": acao, "path": parsed.path,
                    "cwe": "CWE-942",
                    "owasp": "A01:2021-Broken Access Control",
                },
            ))

    # ── 2. Null Origin Acceptance ──────────────────────────────────────────────
    if acao.strip().lower() == "null":
        findings.append(RawFinding(
            title="CORS: Null Origin Accepted",
            category="CORS",
            severity=SeverityLevel.HIGH,
            description=(
                "The server responds with 'Access-Control-Allow-Origin: null', permitting the "
                "null origin. Sandboxed iframes, file:// URIs, and some redirected requests "
                "carry the null origin, allowing attackers to craft these requests and bypass "
                "same-origin restrictions to read cross-origin responses."
            ),
            remediation=(
                "Never accept the null origin in your CORS policy. Remove 'null' from any "
                "ACAO allowlist. Only accept origins matching your own domain using "
                "server-side validation."
            ),
            affected_url=target_url,
            evidence={
                "acao": acao, "acac": acac,
                "cwe": "CWE-942",
                "owasp": "A01:2021-Broken Access Control",
            },
        ))

    # ── 3. Arbitrary Origin Reflection Probe ──────────────────────────────────
    if probe_reflection and target_url and acao not in ("*", "null", ""):
        try:
            reflected = _probe_reflected_origin(target_url, _CANARY_ORIGIN)
            if reflected and reflected.strip() == _CANARY_ORIGIN:
                findings.append(RawFinding(
                    title="CORS: Arbitrary Origin Reflection (Unvalidated Origin Echoing)",
                    category="CORS",
                    severity=SeverityLevel.CRITICAL,
                    description=(
                        f"The server reflected the attacker-controlled canary origin "
                        f"'{_CANARY_ORIGIN}' in 'Access-Control-Allow-Origin'. This means any "
                        "website can make credentialed cross-origin requests to this target and "
                        "read responses, enabling complete CORS bypass, session hijacking, and "
                        "cross-site data exfiltration."
                    ),
                    remediation=(
                        "Implement strict server-side origin validation: check the 'Origin' request "
                        "header against a static allowlist before echoing it into the ACAO response "
                        "header. Never use a regex match that can be circumvented. "
                        "See OWASP CORS Cheat Sheet for allowlist patterns."
                    ),
                    affected_url=target_url,
                    evidence={
                        "canary_origin": _CANARY_ORIGIN,
                        "reflected_acao": reflected,
                        "acac": acac,
                        "cwe": "CWE-942",
                        "owasp": "A01:2021-Broken Access Control",
                    },
                ))
        except Exception:
            pass

    # ── 4. Overly-broad Allowed Methods ───────────────────────────────────────
    if acam:
        dangerous = [m.strip().upper() for m in acam.split(",")
                     if m.strip().upper() in ("DELETE", "PUT", "PATCH", "TRACE")]
        if dangerous:
            findings.append(RawFinding(
                title=f"CORS: Dangerous HTTP Methods Permitted ({', '.join(dangerous)})",
                category="CORS",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"The CORS policy permits the following potentially dangerous HTTP methods: "
                    f"{', '.join(dangerous)}. Combined with an overly-broad ACAO, this enables "
                    "cross-origin state-changing requests that can modify or delete server-side data."
                ),
                remediation=(
                    "Restrict 'Access-Control-Allow-Methods' to only the HTTP methods required by "
                    "your application (typically GET and POST). Never permit DELETE, PUT, PATCH, or "
                    "TRACE in cross-origin responses unless explicitly required."
                ),
                affected_url=target_url,
                evidence={
                    "acam": acam, "dangerous_methods": dangerous,
                    "cwe": "CWE-16",
                    "owasp": "A05:2021-Security Misconfiguration",
                },
            ))

    return findings
