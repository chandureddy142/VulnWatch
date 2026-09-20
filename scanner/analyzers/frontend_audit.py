"""
Frontend & Client-Side Intelligence Analyzer (Enterprise Module)
================================================================
Passively scans HTML content for client-side security risks:
  - Cloud storage endpoint exposure (S3, GCS, Azure Blob)
  - Leaked secrets in HTML comments and inline scripts
  - Subresource Integrity (SRI) attribute gaps on CDN scripts
  - Source map exposure via '//# sourceMappingURL=' comments

All analysis is performed on already-fetched HTML — no new requests made.
"""
from __future__ import annotations

import re
from typing import List, Set

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


# ── Cloud Storage Patterns ─────────────────────────────────────────────────────
_CLOUD_STORAGE_PATTERNS = [
    (re.compile(r'[a-z0-9][a-z0-9.\-]{2,62}\.s3\.amazonaws\.com', re.IGNORECASE), "Amazon S3 Bucket"),
    (re.compile(r'[a-z0-9][a-z0-9.\-]{2,62}\.s3-[a-z0-9-]+\.amazonaws\.com', re.IGNORECASE), "Amazon S3 Bucket (Regional)"),
    (re.compile(r's3\.amazonaws\.com/[a-z0-9][a-z0-9.\-]{2,62}', re.IGNORECASE), "Amazon S3 Bucket (Path-style)"),
    (re.compile(r'storage\.googleapis\.com/[a-z0-9][a-z0-9.\-]{2,62}', re.IGNORECASE), "Google Cloud Storage"),
    (re.compile(r'[a-z0-9][a-z0-9.\-]{2,62}\.blob\.core\.windows\.net', re.IGNORECASE), "Azure Blob Storage"),
    (re.compile(r'[a-z0-9][a-z0-9.\-]{2,62}\.r2\.cloudflarestorage\.com', re.IGNORECASE), "Cloudflare R2 Storage"),
]

# ── Secret / Internal Leak Patterns ───────────────────────────────────────────
_SECRET_PATTERNS = [
    (re.compile(r'api[-_]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', re.IGNORECASE), "API Key"),
    (re.compile(r'(?:secret|token|password|passwd|auth[-_]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-+/=]{16,})', re.IGNORECASE), "Credential / Secret Token"),
    (re.compile(r'(?:private[-_]?key|privatekey)\s*[:=]\s*["\']([A-Za-z0-9_\-+/=]{20,})', re.IGNORECASE), "Private Key Fragment"),
    (re.compile(r'https?://(?:staging|dev|internal|preprod|qa|uat|test)\.[a-z0-9.-]{3,}', re.IGNORECASE), "Internal Staging URL"),
    (re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Private IP (10.x.x.x)"),
    (re.compile(r'\b192\.168\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Private IP (192.168.x.x)"),
    (re.compile(r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Private IP (172.16–31.x.x)"),
]

# ── SRI: CDN Script Pattern ────────────────────────────────────────────────────
_CDN_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>',
    re.IGNORECASE,
)
_SRI_INTEGRITY_RE = re.compile(r'integrity=["\']sha(?:256|384|512)-', re.IGNORECASE)

# ── Source Map Pattern ─────────────────────────────────────────────────────────
_SOURCE_MAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', re.IGNORECASE)

# ── Comment Extractor ──────────────────────────────────────────────────────────
_HTML_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
_INLINE_SCRIPT_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)


def audit_frontend(html_content: str, target_url: str = "") -> List[RawFinding]:
    """
    Passive client-side security intelligence analyzer.

    Args:
        html_content: Raw HTML body content of the target page.
        target_url: Target URL for finding context.

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    if not html_content:
        return findings

    # ── 1. Cloud Storage Exposure ──────────────────────────────────────────────
    detected_buckets: Set[str] = set()
    for pattern, label in _CLOUD_STORAGE_PATTERNS:
        matches = pattern.findall(html_content)
        for match in matches:
            if match not in detected_buckets:
                detected_buckets.add(match)
                findings.append(RawFinding(
                    title=f"Cloud Storage Endpoint Exposed in Page Source ({label})",
                    category="Client-Side Intelligence",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"A {label} URL was found referenced in the page source: '{match}'. "
                        "Publicly-accessible cloud storage buckets can expose sensitive files, "
                        "backups, or configuration artifacts to unauthenticated users."
                    ),
                    remediation=(
                        f"Audit the access policy of '{match}'. Ensure the bucket/container is "
                        "not publicly listed, and sensitive files require authenticated access. "
                        "Enable server-side encryption and access logging."
                    ),
                    affected_url=target_url,
                    evidence={"storage_url": match, "storage_type": label},
                ))

    # ── 2. Leaked Secrets in Comments & Inline Scripts ─────────────────────────
    searchable_zones = []
    # Extract HTML comments
    for comment in _HTML_COMMENT_RE.findall(html_content):
        searchable_zones.append(("HTML Comment", comment))
    # Extract inline scripts
    for script in _INLINE_SCRIPT_RE.findall(html_content):
        searchable_zones.append(("Inline Script", script))

    seen_secrets: Set[str] = set()
    for zone_type, zone_content in searchable_zones:
        for pattern, label in _SECRET_PATTERNS:
            for match in pattern.finditer(zone_content):
                snippet = match.group(0)[:80]
                key = f"{label}:{snippet[:40]}"
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    findings.append(RawFinding(
                        title=f"Potential Leaked {label} in {zone_type}",
                        category="Client-Side Intelligence",
                        severity=SeverityLevel.HIGH if "Key" in label or "Credential" in label else SeverityLevel.MEDIUM,
                        description=(
                            f"A potential {label} was detected in a {zone_type} within the page source. "
                            "Hardcoded credentials, API tokens, private staging URLs, or internal IPs "
                            "in client-side HTML or JavaScript expose them to any user who views the page."
                        ),
                        remediation=(
                            "Remove all credentials, API keys, and internal references from client-facing "
                            "HTML and JavaScript. Use server-side environment variables for secrets and "
                            "dynamic configuration injection. Rotate any exposed credentials immediately."
                        ),
                        affected_url=target_url,
                        evidence={"leak_type": label, "zone": zone_type, "snippet": snippet},
                    ))

    # ── 3. Subresource Integrity (SRI) on CDN Scripts ─────────────────────────
    cdn_scripts = _CDN_SCRIPT_RE.findall(html_content)
    missing_sri_count = 0
    for script_tag in cdn_scripts:
        if not _SRI_INTEGRITY_RE.search(script_tag):
            missing_sri_count += 1

    if missing_sri_count > 0:
        findings.append(RawFinding(
            title=f"Subresource Integrity (SRI) Missing on {missing_sri_count} External Script(s)",
            category="Client-Side Intelligence",
            severity=SeverityLevel.MEDIUM,
            description=(
                f"{missing_sri_count} external CDN <script> tag(s) are loaded without a "
                "'integrity' attribute. Without SRI, a compromised CDN can serve malicious "
                "JavaScript to all visitors of your site."
            ),
            remediation=(
                "Add 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' attributes to "
                "all external <script> and <link> tags. Generate SRI hashes at: "
                "https://www.srihash.org/"
            ),
            affected_url=target_url,
            evidence={"missing_sri_count": missing_sri_count, "cdn_scripts_found": len(cdn_scripts)},
        ))

    # ── 4. Source Map Exposure ─────────────────────────────────────────────────
    source_maps = _SOURCE_MAP_RE.findall(html_content)
    if source_maps:
        findings.append(RawFinding(
            title=f"Source Map Reference Exposed ({len(source_maps)} Found)",
            category="Client-Side Intelligence",
            severity=SeverityLevel.INFO,
            description=(
                f"{len(source_maps)} '//# sourceMappingURL=' comment(s) found in page assets. "
                "Source maps can expose original, unminified source code including comments, "
                "variable names, logic flow, and potentially hardcoded values to any user "
                "who downloads the map files."
            ),
            remediation=(
                "Remove 'sourceMappingURL' references from production JavaScript bundles "
                "or host source maps in a protected internal location. "
                "Configure your bundler (webpack/vite/rollup) to omit source maps in production builds."
            ),
            affected_url=target_url,
            evidence={"source_map_count": len(source_maps), "source_maps": source_maps[:10]},
        ))

    return findings
