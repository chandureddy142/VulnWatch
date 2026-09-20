"""
Compliance & Metadata Analyzer (Enterprise Module)
===================================================
Performs passive compliance metadata inspection:
  - RFC 9116: /.well-known/security.txt (presence & expiry)
  - /robots.txt: disallowed paths exposing internal or sensitive locations

Uses GET requests via the provided HTTP client with strict timeouts.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel

# Patterns in robots.txt Disallow entries that may indicate sensitive paths
_SENSITIVE_DISALLOW_PATTERNS = [
    re.compile(r"^/admin", re.IGNORECASE),
    re.compile(r"^/api", re.IGNORECASE),
    re.compile(r"^/staging", re.IGNORECASE),
    re.compile(r"^/backup", re.IGNORECASE),
    re.compile(r"^/config", re.IGNORECASE),
    re.compile(r"^/\.env", re.IGNORECASE),
    re.compile(r"^/internal", re.IGNORECASE),
    re.compile(r"^/dev", re.IGNORECASE),
    re.compile(r"^/test", re.IGNORECASE),
    re.compile(r"^/debug", re.IGNORECASE),
    re.compile(r"^/phpmyadmin", re.IGNORECASE),
    re.compile(r"^/wp-admin", re.IGNORECASE),
    re.compile(r"^/private", re.IGNORECASE),
    re.compile(r"^/secret", re.IGNORECASE),
]

_EXPIRES_RE = re.compile(r"Expires:\s*(.+)", re.IGNORECASE)
_DISALLOW_RE = re.compile(r"^Disallow:\s*(.+)", re.IGNORECASE | re.MULTILINE)


def _parse_security_txt_expiry(content: str) -> Optional[datetime]:
    """Extract and parse the Expires field from security.txt content."""
    match = _EXPIRES_RE.search(content)
    if not match:
        return None
    raw = match.group(1).strip()
    # Try ISO 8601 datetime
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _safe_get(url: str, timeout: float = 5.0) -> Optional[str]:
    """Fetch a URL and return body text, or None on failure."""
    try:
        headers = {"User-Agent": "VulnWatch-Auditor/2.0 Compliance Probe"}
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        if resp.status_code == 200 and resp.text:
            return resp.text
        return None
    except Exception:
        return None


def audit_metadata(base_url: str) -> List[RawFinding]:
    """
    Passive compliance and metadata inspector.

    Args:
        base_url: Base URL of the target (e.g. 'https://example.com').

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    if not base_url:
        return findings

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # ── 1. RFC 9116 security.txt ──────────────────────────────────────────────
    sec_txt_url = urljoin(origin, "/.well-known/security.txt")
    try:
        sec_txt_content = _safe_get(sec_txt_url)
        if not sec_txt_content:
            # Fallback to legacy location
            sec_txt_content = _safe_get(urljoin(origin, "/security.txt"))

        if not sec_txt_content:
            findings.append(RawFinding(
                title="security.txt Not Found (RFC 9116)",
                category="Compliance & Metadata",
                severity=SeverityLevel.INFO,
                description=(
                    "No 'security.txt' file was found at '/.well-known/security.txt' or '/security.txt'. "
                    "RFC 9116 establishes security.txt as the standard for communicating vulnerability "
                    "disclosure policies. Its absence makes it harder for security researchers to "
                    "responsibly report vulnerabilities."
                ),
                remediation=(
                    "Create a '/.well-known/security.txt' file with fields: Contact, Expires, Policy, "
                    "and optionally Acknowledgments. Use the generator at https://securitytxt.org/"
                ),
                affected_url=sec_txt_url,
                evidence={"security_txt_present": False},
            ))
        else:
            # Check expiry
            expiry = _parse_security_txt_expiry(sec_txt_content)
            if expiry is None:
                findings.append(RawFinding(
                    title="security.txt Missing Expires Field",
                    category="Compliance & Metadata",
                    severity=SeverityLevel.INFO,
                    description=(
                        "A 'security.txt' file was found but it does not contain an 'Expires' field. "
                        "RFC 9116 mandates an expiry date to prevent stale contact information from "
                        "misleading security researchers."
                    ),
                    remediation=(
                        "Add an 'Expires:' field in ISO 8601 format (e.g., '2026-12-31T00:00:00Z') "
                        "to your security.txt file."
                    ),
                    affected_url=sec_txt_url,
                    evidence={"security_txt_present": True, "expires": None},
                ))
            elif expiry < datetime.now(tz=timezone.utc):
                findings.append(RawFinding(
                    title="security.txt Has Expired",
                    category="Compliance & Metadata",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"The 'security.txt' file expired on {expiry.strftime('%Y-%m-%d')}. "
                        "An expired security.txt may confuse security researchers and signals that "
                        "the vulnerability disclosure process may be outdated."
                    ),
                    remediation="Update the 'Expires' date in your security.txt and ensure contact details are current.",
                    affected_url=sec_txt_url,
                    evidence={"security_txt_present": True, "expires": str(expiry), "expired": True},
                ))
            else:
                findings.append(RawFinding(
                    title="security.txt Present and Valid (RFC 9116)",
                    category="Compliance & Metadata",
                    severity=SeverityLevel.INFO,
                    description=(
                        f"A valid 'security.txt' file was found at '{sec_txt_url}' with an expiry of "
                        f"{expiry.strftime('%Y-%m-%d')}. This indicates an active vulnerability "
                        "disclosure program."
                    ),
                    remediation="No action required. Periodically renew the Expires date and verify contact details.",
                    affected_url=sec_txt_url,
                    evidence={"security_txt_present": True, "expires": str(expiry), "expired": False},
                ))
    except Exception:
        pass

    # ── 2. robots.txt Sensitive Path Disclosure ────────────────────────────────
    robots_url = urljoin(origin, "/robots.txt")
    try:
        robots_content = _safe_get(robots_url)
        if robots_content:
            disallow_entries = _DISALLOW_RE.findall(robots_content)
            sensitive_paths = []
            for entry in disallow_entries:
                path = entry.strip()
                for pattern in _SENSITIVE_DISALLOW_PATTERNS:
                    if pattern.match(path):
                        sensitive_paths.append(path)
                        break

            if sensitive_paths:
                findings.append(RawFinding(
                    title=f"Sensitive Paths Disclosed in robots.txt ({len(sensitive_paths)} Found)",
                    category="Compliance & Metadata",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"{len(sensitive_paths)} Disallow entries in '/robots.txt' reference paths "
                        "that may indicate sensitive internal locations: " +
                        ", ".join(sensitive_paths[:10]) + ". "
                        "While robots.txt is not a security mechanism, it publicly advertises "
                        "the existence of these paths to attackers performing reconnaissance."
                    ),
                    remediation=(
                        "Remove sensitive path hints from robots.txt. Protect sensitive endpoints "
                        "with proper authentication and authorization rather than relying on robots.txt. "
                        "Consider using a generic 'Disallow: /' for sensitive directories."
                    ),
                    affected_url=robots_url,
                    evidence={"sensitive_disallows": sensitive_paths[:20], "total_disallows": len(disallow_entries)},
                ))
    except Exception:
        pass

    # ── 3. sitemap.xml Sensitive Endpoint Discovery ─────────────────────────────
    sitemap_url = urljoin(origin, "/sitemap.xml")
    try:
        sitemap_content = _safe_get(sitemap_url)
        if sitemap_content:
            # Look for <loc> tags in sitemap.xml
            loc_matches = re.findall(r"<loc>(.*?)</loc>", sitemap_content, re.IGNORECASE)
            sensitive_sitemap_paths = []
            for loc in loc_matches:
                loc_path = urlparse(loc).path
                for pattern in _SENSITIVE_DISALLOW_PATTERNS:
                    if pattern.match(loc_path):
                        sensitive_sitemap_paths.append(loc)
                        break

            if sensitive_sitemap_paths:
                findings.append(RawFinding(
                    title=f"Sensitive Endpoints Disclosed in sitemap.xml ({len(sensitive_sitemap_paths)} Found)",
                    category="Compliance & Metadata",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"{len(sensitive_sitemap_paths)} entries in '/sitemap.xml' reference sensitive "
                        "endpoints: " + ", ".join(sensitive_sitemap_paths[:10]) + ". "
                        "Exposing administrative, staging, or internal endpoints in XML sitemaps "
                        "aids passive reconnaissance by search engine bots and malicious actors."
                    ),
                    remediation=(
                        "Exclude non-public or administrative URLs from '/sitemap.xml'. Ensure all "
                        "sensitive endpoints enforce strong authentication."
                    ),
                    affected_url=sitemap_url,
                    evidence={"sensitive_sitemap_urls": sensitive_sitemap_paths[:20], "total_urls": len(loc_matches)},
                ))
    except Exception:
        pass

    return findings
