from typing import List
from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


def audit_cookies(target_url: str, set_cookie_headers: List[str]) -> List[RawFinding]:
    """Inspects Set-Cookie headers for missing security flags (HttpOnly, Secure, SameSite)."""
    findings: List[RawFinding] = []
    is_https = target_url.lower().startswith("https://")

    if not set_cookie_headers:
        return findings

    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        if not parts or not parts[0]:
            continue

        cookie_kv = parts[0]
        cookie_name = cookie_kv.split("=")[0].strip()
        attributes = [p.lower() for p in parts[1:]]

        has_httponly = "httponly" in attributes
        has_secure = "secure" in attributes
        samesite_attr = next((a for a in attributes if a.startswith("samesite")), None)

        # 1. Missing HttpOnly attribute check
        if not has_httponly:
            findings.append(
                RawFinding(
                    title=f"Cookie Missing HttpOnly Flag ({cookie_name})",
                    category="Cookie Security",
                    severity=SeverityLevel.MEDIUM,
                    description=f"The cookie '{cookie_name}' lacks the HttpOnly attribute, allowing client-side scripts to access cookie data via Document.cookie (increasing XSS session hijacking risk).",
                    remediation=f"Append '; HttpOnly' to the Set-Cookie definition for '{cookie_name}'.",
                    affected_url=target_url,
                    evidence={"cookie": raw_cookie, "missing": "HttpOnly"},
                )
            )

        # 2. Missing Secure attribute check
        if not has_secure and is_https:
            findings.append(
                RawFinding(
                    title=f"Cookie Missing Secure Flag ({cookie_name})",
                    category="Cookie Security",
                    severity=SeverityLevel.MEDIUM,
                    description=f"The cookie '{cookie_name}' was set over HTTPS without the Secure flag, allowing browser transmission over cleartext HTTP.",
                    remediation=f"Append '; Secure' to the Set-Cookie definition for '{cookie_name}'.",
                    affected_url=target_url,
                    evidence={"cookie": raw_cookie, "missing": "Secure"},
                )
            )

        # 3. SameSite attribute check
        if not samesite_attr:
            findings.append(
                RawFinding(
                    title=f"Cookie Missing SameSite Attribute ({cookie_name})",
                    category="Cookie Security",
                    severity=SeverityLevel.LOW,
                    description=f"The cookie '{cookie_name}' does not specify a SameSite attribute, which exposes cross-site requests to CSRF vulnerabilities.",
                    remediation=f"Append '; SameSite=Lax' or '; SameSite=Strict' to the Set-Cookie header for '{cookie_name}'.",
                    affected_url=target_url,
                    evidence={"cookie": raw_cookie, "missing": "SameSite"},
                )
            )
        elif samesite_attr == "samesite=none" and not has_secure:
            findings.append(
                RawFinding(
                    title=f"Insecure SameSite=None Configuration ({cookie_name})",
                    category="Cookie Security",
                    severity=SeverityLevel.HIGH,
                    description=f"Cookie '{cookie_name}' specifies SameSite=None without the Secure flag. Modern browsers reject unencrypted SameSite=None cookies.",
                    remediation=f"Ensure SameSite=None is accompanied by the Secure attribute.",
                    affected_url=target_url,
                    evidence={"cookie": raw_cookie, "invalid": "SameSite=None without Secure"},
                )
            )

    return findings
