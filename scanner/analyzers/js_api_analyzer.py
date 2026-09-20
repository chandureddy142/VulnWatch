"""
Public JS Bundle & API Endpoint Discovery Analyzer (Enterprise Module)
=======================================================================
Fetches up to 3 public JavaScript bundles from the target page and performs
passive static analysis:

  1. Leaked secrets — API key patterns, private tokens, internal IPs
  2. Source map exposure — '//# sourceMappingURL=' markers
  3. Hardcoded API endpoints — /api/v*, /graphql, /swagger, /openapi
  4. OpenAPI / GraphQL / Swagger UI endpoint detection
  5. External CDN SRI gap auditing

Constraints:
  - Max 3 JS files downloaded, 3s timeout per file, 200KB cap per file
  - No execution, no form submission — pure passive static analysis
  - Only fetches files that are direct <script src="..."> references on the page

CWE-200 / OWASP A05:2021-Security Misconfiguration
"""
from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

import requests

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel

# ── Selectors & Limits ────────────────────────────────────────────────────────
MAX_BUNDLES = 3
MAX_BYTES = 200_000  # 200 KB
FETCH_TIMEOUT = (2, 4)  # (connect, read)

# ── Script tag extractor ──────────────────────────────────────────────────────
_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)
_SRI_INTEGRITY_RE = re.compile(r'integrity=["\']sha(?:256|384|512)-', re.IGNORECASE)
_EXTERNAL_URL_RE = re.compile(r'^https?://', re.IGNORECASE)

# ── Secret Patterns ───────────────────────────────────────────────────────────
_SECRET_PATTERNS: List[tuple[re.Pattern, str, str, str]] = [
    # (pattern, label, cwe, owasp)
    (re.compile(r'(?i)api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'), "API Key", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'(?i)(?:secret|token|password|passwd)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{16,})["\']'), "Credential / Secret Token", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'(?i)(?:private[_-]?key|privatekey)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{20,})["\']'), "Private Key Fragment", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "AWS Access Key ID", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'(?i)sk-[A-Za-z0-9]{32,}'), "OpenAI Secret Key", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'(?i)xox[baprs]-[A-Za-z0-9\-]{20,}'), "Slack Token", "CWE-200", "A02:2021-Cryptographic Failures"),
    (re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Internal IP (10.x)", "CWE-200", "A05:2021-Security Misconfiguration"),
    (re.compile(r'\b192\.168\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Internal IP (192.168.x)", "CWE-200", "A05:2021-Security Misconfiguration"),
    (re.compile(r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b'), "RFC1918 Internal IP (172.16-31.x)", "CWE-200", "A05:2021-Security Misconfiguration"),
    (re.compile(r'https?://(?:staging|dev|internal|preprod|qa|uat|test)\.[a-z0-9.\-]{4,}', re.IGNORECASE), "Internal Staging URL", "CWE-200", "A05:2021-Security Misconfiguration"),
]

# ── API Endpoint Patterns ─────────────────────────────────────────────────────
_API_ENDPOINT_PATTERNS = [
    (re.compile(r'["\'](/api/v\d[^"\']*)["\']'), "REST API Endpoint"),
    (re.compile(r'["\'](/graphql[^"\']*)["\']', re.IGNORECASE), "GraphQL Endpoint"),
    (re.compile(r'["\'](/swagger[^"\']*|/api-docs[^"\']*|/openapi[^"\']*)["\']', re.IGNORECASE), "API Documentation Endpoint"),
    (re.compile(r'["\'](/v\d/[^"\']{3,50})["\']'), "Versioned API Path"),
    (re.compile(r'["\']([^"\']*\.well-known[^"\']*)["\']', re.IGNORECASE), "Well-Known Discovery URL"),
]

_SOURCE_MAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', re.IGNORECASE)


def _fetch_js(url: str) -> str | None:
    """Fetch a JS URL with strict size and timeout limits. Returns text or None."""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "VulnWatch-JSAudit/2.0"},
            timeout=FETCH_TIMEOUT,
            verify=True,
            allow_redirects=True,
            stream=True,
        )
        if resp.status_code != 200:
            return None
        # Read up to MAX_BYTES
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=8192):
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BYTES:
                break
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _resolve_script_urls(html: str, base_url: str) -> list[tuple[str, bool]]:
    """
    Extract <script src="..."> URLs from HTML.
    Returns list of (absolute_url, is_external, has_sri) tuples filtered to HTTP/HTTPS.
    """
    results = []
    for match in _SCRIPT_SRC_RE.finditer(html):
        tag_text = match.group(0)
        src = match.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        if not _EXTERNAL_URL_RE.match(src):
            src = urljoin(base_url, src)
        is_external = urlparse(src).netloc != urlparse(base_url).netloc
        has_sri = bool(_SRI_INTEGRITY_RE.search(tag_text))
        results.append((src, is_external, has_sri))
    return results


def audit_js_api(html_content: str, target_url: str = "") -> List[RawFinding]:
    """
    Passive JS bundle and API endpoint discovery analyzer.

    Args:
        html_content: Raw HTML content of the target page.
        target_url: Target base URL for resolving relative script paths.

    Returns:
        List of RawFinding objects.
    """
    findings: List[RawFinding] = []
    if not html_content:
        return findings

    script_refs = _resolve_script_urls(html_content, target_url)

    # ── SRI Gap check (from HTML) ─────────────────────────────────────────────
    missing_sri = [(url, is_ext) for url, is_ext, has_sri in script_refs if is_ext and not has_sri]
    if missing_sri:
        findings.append(RawFinding(
            title=f"Subresource Integrity (SRI) Missing on {len(missing_sri)} External Script(s)",
            category="Client-Side Intelligence",
            severity=SeverityLevel.MEDIUM,
            description=(
                f"{len(missing_sri)} external CDN <script> tag(s) lack an 'integrity' attribute. "
                "Without SRI, a compromised or hijacked CDN can silently serve modified JavaScript "
                "to all page visitors, enabling supply-chain XSS attacks."
            ),
            remediation=(
                "Add 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' to all external "
                "<script> tags. Generate SRI hashes at https://www.srihash.org/ or via "
                "'openssl dgst -sha384 -binary bundle.js | base64 -w0'"
            ),
            affected_url=target_url,
            evidence={
                "missing_sri_scripts": [u for u, _ in missing_sri[:10]],
                "cwe": "CWE-693",
                "owasp": "A08:2021-Software and Data Integrity Failures",
            },
        ))

    # ── Fetch up to MAX_BUNDLES JS files for deep analysis ────────────────────
    # Prefer same-origin JS, then external
    same_origin = [(u, e, s) for u, e, s in script_refs if not e]
    external = [(u, e, s) for u, e, s in script_refs if e]
    candidates = (same_origin + external)[:MAX_BUNDLES]

    all_discovered_endpoints: Set[str] = set()
    seen_secrets: Set[str] = set()
    source_maps_found: List[str] = []
    analyzed_count = 0

    for url, is_external, _ in candidates:
        js_text = _fetch_js(url)
        if not js_text:
            continue
        analyzed_count += 1

        # ── Source Map Markers ─────────────────────────────────────────────
        for sm_match in _SOURCE_MAP_RE.finditer(js_text):
            source_maps_found.append(sm_match.group(1)[:120])

        # ── Secret Pattern Scan ────────────────────────────────────────────
        for pattern, label, cwe, owasp in _SECRET_PATTERNS:
            for m in pattern.finditer(js_text):
                snippet = m.group(0)[:80]
                dedup_key = f"{label}:{snippet[:40]}"
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)
                severity = (
                    SeverityLevel.CRITICAL if "AWS" in label or "OpenAI" in label or "Slack" in label
                    else SeverityLevel.HIGH if "Key" in label or "Credential" in label
                    else SeverityLevel.MEDIUM
                )
                findings.append(RawFinding(
                    title=f"Potential Leaked {label} in JavaScript Bundle",
                    category="Client-Side Intelligence",
                    severity=severity,
                    description=(
                        f"A potential {label} pattern was found in a JavaScript bundle at '{url}'. "
                        "Client-side secrets are exposed to every visitor who loads the page, "
                        "enabling credential theft, unauthorized API access, and data exfiltration."
                    ),
                    remediation=(
                        "Move all secrets to server-side environment variables. Never embed API keys, "
                        "tokens, or passwords in client-side JavaScript. Rotate any exposed credentials "
                        "immediately. Use a secrets scanner in CI/CD (e.g., trufflehog, git-secrets)."
                    ),
                    affected_url=url,
                    evidence={
                        "leak_type": label,
                        "snippet": snippet,
                        "js_url": url,
                        "cwe": cwe,
                        "owasp": owasp,
                    },
                ))
                if len(findings) > 30:  # safety cap
                    break

        # ── API Endpoint Discovery ─────────────────────────────────────────
        for pattern, ep_label in _API_ENDPOINT_PATTERNS:
            for m in pattern.finditer(js_text):
                path = m.group(1)[:100]
                if path not in all_discovered_endpoints:
                    all_discovered_endpoints.add(path)

    # Batch-report discovered API endpoints as a single finding
    if all_discovered_endpoints:
        ep_list = sorted(all_discovered_endpoints)
        sensitive_eps = [
            ep for ep in ep_list
            if any(kw in ep.lower() for kw in ("admin", "token", "secret", "internal", "graphql", "swagger"))
        ]
        findings.append(RawFinding(
            title=f"API Endpoints Discovered in JavaScript Bundles ({len(ep_list)} Found)",
            category="Client-Side Intelligence",
            severity=SeverityLevel.MEDIUM if not sensitive_eps else SeverityLevel.HIGH,
            description=(
                f"{len(ep_list)} API endpoint path(s) were extracted from JavaScript source "
                f"files during static analysis{', including ' + str(len(sensitive_eps)) + ' sensitive endpoint(s)' if sensitive_eps else ''}. "
                "Enumerating internal API routes from client-side JavaScript assists attackers in "
                "mapping attack surface without triggering server-side rate limits."
            ),
            remediation=(
                "Avoid hardcoding internal API paths in client-side bundles. Use opaque API "
                "gateway routing, route through a BFF (Backend For Frontend) proxy, or implement "
                "runtime service discovery to avoid exposing the full API surface."
            ),
            affected_url=target_url,
            evidence={
                "discovered_endpoints": ep_list[:40],
                "sensitive_endpoints": sensitive_eps[:15],
                "js_files_analyzed": analyzed_count,
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
            },
        ))

    # Source map batch finding
    if source_maps_found:
        findings.append(RawFinding(
            title=f"Source Map References Exposed in JavaScript ({len(source_maps_found)} Found)",
            category="Client-Side Intelligence",
            severity=SeverityLevel.LOW,
            description=(
                f"{len(source_maps_found)} '//# sourceMappingURL=' reference(s) found in analyzed "
                "JavaScript bundles. Public source maps expose your original, unminified source code "
                "including variable names, comments, internal logic, and potentially hardcoded values."
            ),
            remediation=(
                "Remove sourceMappingURL references from production builds or restrict source map "
                "hosting to internal networks only. Configure webpack/vite/rollup with "
                "'devtool: false' or serve source maps behind authentication."
            ),
            affected_url=target_url,
            evidence={
                "source_maps": source_maps_found[:10],
                "cwe": "CWE-540",
                "owasp": "A05:2021-Security Misconfiguration",
            },
        ))

    return findings
