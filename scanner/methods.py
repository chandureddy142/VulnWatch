from typing import List, Tuple
from scanner.findings import RawFinding
from scanner.http import HTTPClient
from scanner.severity import SeverityLevel


def audit_http_methods(
    target_url: str, http_client: HTTPClient
) -> Tuple[List[str], List[RawFinding]]:
    """Catalog exposed HTTP verbs via OPTIONS & HEAD probes without issuing payload requests."""
    findings: List[RawFinding] = []
    allowed_methods: List[str] = []

    # Issue controlled OPTIONS probe
    resp = http_client.options(target_url)

    if resp.error:
        # Fallback to HEAD request if OPTIONS is blocked or unsupported
        resp = http_client.head(target_url)

    if resp.headers:
        allow_hdr = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods")
        if allow_hdr:
            allowed_methods = [m.strip().upper() for m in allow_hdr.split(",")]

            # Audit for potentially dangerous or unexpected HTTP methods
            risky_methods = ["TRACE", "TRACK", "CONNECT", "PUT", "DELETE"]
            exposed_risky = [m for m in risky_methods if m in allowed_methods]

            if exposed_risky:
                if "TRACE" in exposed_risky or "TRACK" in exposed_risky:
                    findings.append(
                        RawFinding(
                            title="Cross-Site Tracing (XST) Potential - TRACE/TRACK Enabled",
                            category="HTTP Method Security",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Server advertises support for HTTP TRACE/TRACK methods ({', '.join(exposed_risky)}). TRACE reflects raw requests back to clients and can leak sensitive headers or credentials.",
                            remediation="Disable HTTP TRACE and TRACK methods in web server configuration.",
                            affected_url=target_url,
                            evidence={"allowed_methods": allowed_methods, "risky": exposed_risky},
                        )
                    )
                if "PUT" in exposed_risky or "DELETE" in exposed_risky:
                    findings.append(
                        RawFinding(
                            title="Potentially Dangerous HTTP Methods Exposed (PUT/DELETE)",
                            category="HTTP Method Security",
                            severity=SeverityLevel.LOW,
                            description=f"Server advertises support for REST file modification verbs: {', '.join([m for m in exposed_risky if m in ('PUT', 'DELETE')])}. Ensure access controls strictly restrict unauthorized usage.",
                            remediation="Verify authentication and authorization policies enforce access control on file-modifying HTTP methods.",
                            affected_url=target_url,
                            evidence={"allowed_methods": allowed_methods, "risky": exposed_risky},
                        )
                    )

    return allowed_methods, findings
