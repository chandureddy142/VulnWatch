"""
Modern Isolation & Browser Security Headers Analyzer (Enterprise Module)
========================================================================
Inspects advanced HTTP response headers for process-isolation, cross-origin
control, permission policies, network error logging, and CORS misconfiguration.

All analysis is performed on already-captured headers — no new requests made.
"""
from __future__ import annotations

from typing import Dict, List

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


def audit_advanced_headers(headers: Dict[str, str], target_url: str = "") -> List[RawFinding]:
    """
    Audit advanced security and isolation headers.

    Args:
        headers: Case-insensitive HTTP response headers dict.
        target_url: Target URL for finding context.

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    # Normalize headers to lowercase keys for consistent lookup
    norm = {k.lower(): v for k, v in headers.items()}

    # ── 1. Permissions-Policy ──────────────────────────────────────────────────
    pp = norm.get("permissions-policy", "")
    feature_policy = norm.get("feature-policy", "")
    if not pp and not feature_policy:
        findings.append(RawFinding(
            title="Permissions-Policy Header Missing",
            category="Process Isolation & Permissions",
            severity=SeverityLevel.LOW,
            description=(
                "The 'Permissions-Policy' (formerly Feature-Policy) header is absent. "
                "This header controls access to browser features such as camera, microphone, "
                "geolocation, and payment APIs. Without it, embedded third-party scripts can "
                "request sensitive browser permissions."
            ),
            remediation=(
                "Add a 'Permissions-Policy' header restricting sensitive APIs: "
                "'Permissions-Policy: camera=(), microphone=(), geolocation=()'. "
                "Only allow features explicitly required by your application."
            ),
            affected_url=target_url,
            evidence={"header": "Permissions-Policy", "present": False},
        ))
    else:
        effective_pp = pp or feature_policy
        for feature in ["geolocation", "microphone", "camera"]:
            if feature not in effective_pp.lower():
                findings.append(RawFinding(
                    title=f"Permissions-Policy Does Not Restrict '{feature.capitalize()}'",
                    category="Process Isolation & Permissions",
                    severity=SeverityLevel.INFO,
                    description=(
                        f"The Permissions-Policy header does not explicitly restrict '{feature}'. "
                        "Third-party scripts or iframes may be able to request access to this "
                        "browser capability without user awareness."
                    ),
                    remediation=(
                        f"Add '{feature}=()' to the Permissions-Policy header to explicitly deny "
                        "access to this feature unless your application requires it."
                    ),
                    affected_url=target_url,
                    evidence={"feature": feature, "policy_value": effective_pp[:200]},
                ))

    # ── 2. Cross-Origin-Embedder-Policy (COEP) ─────────────────────────────────
    coep = norm.get("cross-origin-embedder-policy", "")
    if not coep:
        findings.append(RawFinding(
            title="Cross-Origin-Embedder-Policy (COEP) Header Missing",
            category="Process Isolation & Permissions",
            severity=SeverityLevel.MEDIUM,
            description=(
                "The 'Cross-Origin-Embedder-Policy' (COEP) header is absent. COEP enables "
                "cross-origin process isolation, which is required to access powerful APIs "
                "like SharedArrayBuffer and high-resolution performance timers that could "
                "otherwise be exploited by Spectre-class side-channel attacks."
            ),
            remediation=(
                "Set 'Cross-Origin-Embedder-Policy: require-corp' to enforce that all "
                "sub-resources explicitly opt-in via CORP headers. "
                "Works in conjunction with COOP to enable process isolation."
            ),
            affected_url=target_url,
            evidence={"header": "Cross-Origin-Embedder-Policy", "present": False},
        ))

    # ── 3. Cross-Origin-Opener-Policy (COOP) ──────────────────────────────────
    coop = norm.get("cross-origin-opener-policy", "")
    if not coop:
        findings.append(RawFinding(
            title="Cross-Origin-Opener-Policy (COOP) Header Missing",
            category="Process Isolation & Permissions",
            severity=SeverityLevel.MEDIUM,
            description=(
                "The 'Cross-Origin-Opener-Policy' (COOP) header is absent. Without COOP, "
                "cross-origin pages opened via window.open() can maintain a reference to "
                "your browsing context, enabling cross-origin information leaks and "
                "XS-Leaks attacks."
            ),
            remediation=(
                "Set 'Cross-Origin-Opener-Policy: same-origin' to sever references between "
                "your browsing context and cross-origin windows. "
                "Use 'same-origin-allow-popups' if your app uses OAuth popups."
            ),
            affected_url=target_url,
            evidence={"header": "Cross-Origin-Opener-Policy", "present": False},
        ))

    # ── 4. Cross-Origin-Resource-Policy (CORP) ─────────────────────────────────
    corp = norm.get("cross-origin-resource-policy", "")
    if not corp:
        findings.append(RawFinding(
            title="Cross-Origin-Resource-Policy (CORP) Header Missing",
            category="Process Isolation & Permissions",
            severity=SeverityLevel.LOW,
            description=(
                "The 'Cross-Origin-Resource-Policy' (CORP) header is absent. Without CORP, "
                "other origins can embed your resources (images, scripts, data) in their "
                "pages, potentially enabling cross-origin information leakage."
            ),
            remediation=(
                "Set 'Cross-Origin-Resource-Policy: same-origin' to prevent cross-origin "
                "embedding of your resources, or 'same-site' for same-eTLD+1 access."
            ),
            affected_url=target_url,
            evidence={"header": "Cross-Origin-Resource-Policy", "present": False},
        ))

    # ── 5. Reporting-Endpoints / NEL ──────────────────────────────────────────
    nel = norm.get("nel", "")
    reporting_endpoints = norm.get("reporting-endpoints", "") or norm.get("report-to", "")
    if not nel and not reporting_endpoints:
        findings.append(RawFinding(
            title="Network Error Logging (NEL) Not Configured",
            category="Process Isolation & Permissions",
            severity=SeverityLevel.INFO,
            description=(
                "Neither 'NEL' nor 'Reporting-Endpoints' headers are configured. "
                "Network Error Logging (NEL) enables browsers to automatically report "
                "DNS failures, TLS errors, and connection drops to a collector endpoint, "
                "improving visibility into real-user network issues."
            ),
            remediation=(
                "Configure NEL and a Reporting-Endpoints header pointing to a report collector. "
                "Example: 'NEL: {\"report_to\": \"default\", \"max_age\": 86400}' + "
                "'Reporting-Endpoints: default=\"https://yoursite.com/report\"'"
            ),
            affected_url=target_url,
            evidence={"nel_present": False, "reporting_endpoints_present": False},
        ))

    # ── 6. CORS Wildcard with Credentials ─────────────────────────────────────
    acao = norm.get("access-control-allow-origin", "")
    acac = norm.get("access-control-allow-credentials", "")
    if acao == "*" and acac.strip().lower() == "true":
        findings.append(RawFinding(
            title="CORS Wildcard Origin with Credentials Allowed",
            category="CORS",
            severity=SeverityLevel.HIGH,
            description=(
                "The response sets 'Access-Control-Allow-Origin: *' alongside "
                "'Access-Control-Allow-Credentials: true'. This combination is technically "
                "rejected by browsers per the CORS spec, but its presence indicates a "
                "misconfigured CORS policy that may accept arbitrary origins in other "
                "variations, enabling cross-site credential theft."
            ),
            remediation=(
                "Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. "
                "Use an explicit allowlist of trusted origins instead of the wildcard. "
                "Validate 'Origin' request headers server-side and reflect only trusted values."
            ),
            affected_url=target_url,
            evidence={"acao": acao, "acac": acac},
        ))
    elif acao == "*":
        findings.append(RawFinding(
            title="CORS Wildcard Origin Permitted",
            category="CORS",
            severity=SeverityLevel.INFO,
            description=(
                "The response includes 'Access-Control-Allow-Origin: *', permitting any "
                "origin to read this resource. For public APIs this is expected, but for "
                "authenticated or sensitive endpoints this is a risk."
            ),
            remediation=(
                "Audit whether all endpoints using 'Access-Control-Allow-Origin: *' are truly "
                "intended to be publicly accessible. For authenticated endpoints, restrict to "
                "an explicit allowlist of trusted origins."
            ),
            affected_url=target_url,
            evidence={"acao": acao},
        ))

    return findings
