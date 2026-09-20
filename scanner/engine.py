from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel as DBSeverityLevel
from scanner.cookies import audit_cookies
from scanner.findings import RawFinding
from scanner.headers import audit_headers
from scanner.http import HTTPClient, HTTPResponseData
from scanner.methods import audit_http_methods
from scanner.recon import run_passive_recon
from scanner.severity import SeverityLevel as ScannerSeverityLevel
from scanner.target import TargetValidationError, validate_target_url

# Advanced analyzer lazy imports (kept here for documentation)
# scanner.analyzers.dns_sec          → audit_dns_sec(domain, subdomains)
# scanner.analyzers.tls_audit        → audit_tls(hostname, port)
# scanner.analyzers.headers_advanced → audit_advanced_headers(headers, target_url)
# scanner.analyzers.frontend_audit   → audit_frontend(html_content, target_url)
# scanner.analyzers.metadata_audit   → audit_metadata(base_url)
# scanner.analyzers.cors_analyzer    → audit_cors(headers, target_url)
# scanner.analyzers.js_api_analyzer  → audit_js_api(html_content, target_url)

SENSITIVE_RESPONSE_HEADER_MARKERS = (
    "token", "secret", "key", "auth", "credential", "cookie", "session",
)

# Canonical names for all advanced enterprise audit modules
ADVANCED_MODULES: Set[str] = {
    "module_advanced_dns",
    "module_tls_deep",
    "module_headers_advanced",
    "module_frontend",
    "module_metadata",
    "module_cors",
    "module_js_api",
}


def redact_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Preserve useful scan evidence without persisting credentials or cookies."""
    return {
        key: "[REDACTED]"
        if any(marker in key.lower() for marker in SENSITIVE_RESPONSE_HEADER_MARKERS)
        else value
        for key, value in headers.items()
    }


def _to_db_severity(sev) -> DBSeverityLevel:
    """Safely convert any severity representation (Enum instance, string, or class type) to DBSeverityLevel."""
    if isinstance(sev, type):
        return DBSeverityLevel.HIGH
    if isinstance(sev, str):
        val = sev.upper()
    elif hasattr(sev, "name") and isinstance(sev.name, str):
        val = sev.name.upper()
    elif hasattr(sev, "value") and isinstance(sev.value, str):
        val = sev.value.upper()
    else:
        val = "HIGH"

    try:
        return DBSeverityLevel[val]
    except KeyError:
        return DBSeverityLevel.HIGH


def cleanup_stale_scans(db=None, max_age_seconds: int = 120) -> int:
    """Mark scans stuck in RUNNING or PENDING longer than max_age_seconds as FAILED."""
    if db is None:
        db = get_session()

    cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
    stale_scans = (
        db.query(Scan)
        .filter(
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING]),
            Scan.started_at <= cutoff,
        )
        .all()
    )

    count = 0
    for scan in stale_scans:
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        count += 1

    if count > 0:
        db.commit()

    return count


class ScanEngine:
    """Coordinates passive security posture and configuration auditing workflows."""

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "VulnWatch-Auditor/1.0 (+https://yourdomain.com/security; contact: abuse@yourdomain.com)",
        allow_localhost: bool = True,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.allow_localhost = allow_localhost
        self.http_client = HTTPClient(timeout=self.timeout, user_agent=self.user_agent)

    def execute_scan(
        self,
        raw_url: str,
        scan_id: Optional[int] = None,
        is_authenticated_user: bool = False,
        active_modules: Optional[Dict[str, bool]] = None,
    ) -> Scan:
        """Executes full passive posture audit against a validated target URL.

        Standard baseline modules run for all tiers (including guests).
        Advanced enterprise modules run ONLY when is_authenticated_user=True AND
        the respective module is toggled on in active_modules.

        Args:
            raw_url: Input target URL string.
            scan_id: Optional existing DB Scan ID to attach results to.
            is_authenticated_user: True if session user is a signed-in Google user (not guest).
            active_modules: Dict of module_name → bool for advanced module selection.

        Returns:
            Updated Scan database model instance.
        """
        db = get_session()
        active_modules = active_modules or {}

        # Step 1: Target URL validation
        try:
            target_url = validate_target_url(
                raw_url, allow_localhost=self.allow_localhost
            )
        except TargetValidationError as e:
            scan = self._get_or_create_scan(db, scan_id, raw_url)
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            db.commit()
            raise ValueError(f"Target validation failed: {str(e)}")

        scan = self._get_or_create_scan(db, scan_id, target_url)
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""
        domain_parts = hostname.split(".")
        apex_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname

        # Advanced telemetry state (populated during run, stored in _advanced key)
        advanced_meta: Dict[str, Any] = {}

        try:
            raw_findings: List[RawFinding] = []

            # Step 2: Initial HTTP GET Discovery Probe
            get_resp: HTTPResponseData = self.http_client.get(target_url)

            if get_resp.error:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                raw_findings.append(
                    RawFinding(
                        title="Target Connection Failure",
                        category="Network Connectivity",
                        severity=ScannerSeverityLevel.HIGH,
                        description=f"Failed to establish connection to target URL: {get_resp.error}",
                        remediation="Verify target host reachability, DNS configuration, and active listening services.",
                        affected_url=target_url,
                        evidence={"error": get_resp.error},
                    )
                )
            else:
                scan.status_code = get_resp.status_code
                scan.response_headers = redact_response_headers(get_resp.headers)

                # ── STANDARD MODULES (all tiers) ──────────────────────────────

                # Step 3: Audit Security Headers
                header_findings = audit_headers(target_url, get_resp.headers)
                raw_findings.extend(header_findings)

                # Step 4: Audit Set-Cookie Attributes
                cookie_findings = audit_cookies(
                    target_url, get_resp.raw_set_cookie_headers
                )
                raw_findings.extend(cookie_findings)

                # Step 5: Audit Exposed HTTP Verbs (OPTIONS/HEAD)
                _, method_findings = audit_http_methods(target_url, self.http_client)
                raw_findings.extend(method_findings)

                # Step 6: Passive Reconnaissance & Attack Surface Mapping
                try:
                    recon_result = run_passive_recon(
                        target_url=target_url,
                        http_headers=get_resp.headers,
                        timeout=max(5, self.timeout),
                    )
                    raw_findings.extend(recon_result.findings)
                    if scan.response_headers is None:
                        scan.response_headers = {}
                    scan.response_headers["_recon"] = {
                        "ct_subdomain_count": len(recon_result.ct_subdomains),
                        "ct_subdomains": recon_result.ct_subdomains[:30],
                        "spf_record": recon_result.spf_record,
                        "dmarc_record": recon_result.dmarc_record,
                        "dkim_selectors_found": recon_result.dkim_selectors_found,
                        "dangling_cnames": recon_result.dangling_cnames,
                        "detected_tech": recon_result.detected_tech,
                        "tls_info": recon_result.tls_info,
                        "redirect_chain": recon_result.redirect_chain,
                    }
                    discovered_subdomains = recon_result.ct_subdomains[:30]
                except Exception:
                    discovered_subdomains = []

                # ── ADVANCED ENTERPRISE MODULES (Google auth only) ─────────────
                if is_authenticated_user:
                    # A. DNSSEC / CAA / DMARC / Dangling CNAMEs
                    if active_modules.get("module_advanced_dns", True):
                        try:
                            from scanner.analyzers.dns_sec import audit_dns_sec
                            dns_findings = audit_dns_sec(
                                domain=apex_domain,
                                subdomains=discovered_subdomains,
                            )
                            raw_findings.extend(dns_findings)
                            advanced_meta["dnssec_checked"] = True
                            # Derive simple status for UI badge
                            dnssec_finding_titles = [f.title for f in dns_findings]
                            advanced_meta["dnssec_status"] = (
                                "Unsigned" if any("DNSSEC Not" in t for t in dnssec_finding_titles) else "Validated"
                            )
                            advanced_meta["caa_configured"] = not any(
                                "CAA" in t for t in dnssec_finding_titles
                            )
                        except Exception:
                            advanced_meta["dnssec_checked"] = False
                            advanced_meta["dnssec_status"] = "Error"

                    # B. Deep TLS Certificate Inspector
                    if active_modules.get("module_tls_deep", True) and hostname:
                        try:
                            from scanner.analyzers.tls_audit import audit_tls
                            tls_findings, cert_sans = audit_tls(hostname=hostname, port=443)
                            raw_findings.extend(tls_findings)
                            advanced_meta["tls_deep_checked"] = True
                            advanced_meta["cert_sans"] = cert_sans[:20]
                        except Exception:
                            advanced_meta["tls_deep_checked"] = False

                    # C. Advanced Process Isolation & Browser Headers
                    if active_modules.get("module_headers_advanced", True):
                        try:
                            from scanner.analyzers.headers_advanced import audit_advanced_headers
                            adv_header_findings = audit_advanced_headers(
                                headers=get_resp.headers,
                                target_url=target_url,
                            )
                            raw_findings.extend(adv_header_findings)
                            advanced_meta["headers_advanced_checked"] = True
                        except Exception:
                            advanced_meta["headers_advanced_checked"] = False

                    # D. Frontend Client-Side Intelligence + JS/API Discovery
                    # Fetch HTML body once; reuse for both frontend_audit and js_api_analyzer
                    html_content = ""
                    if active_modules.get("module_frontend", True) or active_modules.get("module_js_api", True):
                        try:
                            import requests as _req
                            _html_resp = _req.get(
                                target_url,
                                timeout=(4, 8),
                                headers={"User-Agent": self.user_agent},
                                verify=True,
                                allow_redirects=True,
                            )
                            html_content = _html_resp.text[:500_000]  # Cap at 500KB
                        except Exception:
                            html_content = ""

                    if active_modules.get("module_frontend", True) and html_content:
                        try:
                            from scanner.analyzers.frontend_audit import audit_frontend
                            frontend_findings = audit_frontend(
                                html_content=html_content,
                                target_url=target_url,
                            )
                            raw_findings.extend(frontend_findings)
                            cloud_bucket_findings = [f for f in frontend_findings if "Cloud Storage" in f.title]
                            advanced_meta["cloud_buckets_found"] = len(cloud_bucket_findings)
                            advanced_meta["frontend_checked"] = True
                        except Exception:
                            advanced_meta["frontend_checked"] = False
                            advanced_meta["cloud_buckets_found"] = 0

                    # F. JS Bundle & API Endpoint Discovery
                    if active_modules.get("module_js_api", True) and html_content:
                        try:
                            from scanner.analyzers.js_api_analyzer import audit_js_api
                            js_findings = audit_js_api(
                                html_content=html_content,
                                target_url=target_url,
                            )
                            raw_findings.extend(js_findings)
                            api_ep_findings = [f for f in js_findings if "API Endpoints" in f.title]
                            advanced_meta["api_endpoints_found"] = (
                                len(api_ep_findings[0].evidence.get("discovered_endpoints", []))
                                if api_ep_findings else 0
                            )
                            advanced_meta["js_api_checked"] = True
                        except Exception:
                            advanced_meta["js_api_checked"] = False
                            advanced_meta["api_endpoints_found"] = 0

                    # E. Compliance Metadata (security.txt, robots.txt, sitemap.xml)
                    if active_modules.get("module_metadata", True):
                        try:
                            from scanner.analyzers.metadata_audit import audit_metadata
                            meta_findings = audit_metadata(base_url=target_url)
                            raw_findings.extend(meta_findings)
                            sec_txt_findings = [f for f in meta_findings if "security.txt" in f.title]
                            advanced_meta["security_txt_present"] = any(
                                "Present" in f.title or ("security.txt" in f.title and f.evidence.get("security_txt_present"))
                                for f in sec_txt_findings
                            )
                            advanced_meta["metadata_checked"] = True
                        except Exception:
                            advanced_meta["metadata_checked"] = False
                            advanced_meta["security_txt_present"] = None

                    # G. CORS Configuration & Credential Exposure
                    if active_modules.get("module_cors", True):
                        try:
                            from scanner.analyzers.cors_analyzer import audit_cors
                            cors_findings = audit_cors(
                                headers=get_resp.headers,
                                target_url=target_url,
                                probe_reflection=True,
                            )
                            raw_findings.extend(cors_findings)
                            advanced_meta["cors_checked"] = True
                            advanced_meta["cors_issues"] = len(cors_findings)
                        except Exception:
                            advanced_meta["cors_checked"] = False
                            advanced_meta["cors_issues"] = 0

                else:
                    # Guest session — record informational note about locked modules
                    raw_findings.append(RawFinding(
                        title="Advanced Attack Surface Analysis — Sign In Required",
                        category="Infrastructure",
                        severity=ScannerSeverityLevel.INFO,
                        description=(
                            "DNSSEC/CAA audit, deep TLS certificate inspection, process isolation "
                            "header analysis, client-side secret scanning, and compliance metadata "
                            "checks (RFC 9116 security.txt) are enterprise-tier modules available "
                            "exclusively to signed-in Google users."
                        ),
                        remediation=(
                            "Sign in with Google at /auth/login to unlock the full passive VAPT suite "
                            "including DNSSEC, CAA, dangling CNAME detection, TLS certificate expiry "
                            "tracking, SRI auditing, and security.txt compliance checks."
                        ),
                        affected_url=target_url,
                        evidence={"advanced_modules_available": False, "reason": "guest_session"},
                    ))
                    advanced_meta["guest_session"] = True

                # Store advanced telemetry alongside recon metadata
                if scan.response_headers is None:
                    scan.response_headers = {}
                scan.response_headers["_advanced"] = advanced_meta

                scan.status = ScanStatus.COMPLETED

            scan.completed_at = datetime.utcnow()

            # Persist findings
            for rf in raw_findings:
                sev_enum = _to_db_severity(rf.severity)
                db_finding = Finding(
                    scan_id=scan.id,
                    title=rf.title,
                    category=rf.category,
                    severity=sev_enum,
                    description=rf.description,
                    remediation=rf.remediation,
                    affected_url=rf.affected_url,
                    evidence=rf.evidence,
                )
                db.add(db_finding)

            db.commit()
            scan.update_severity_counts()
            db.commit()

        except Exception as err:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            err_finding = Finding(
                scan_id=scan.id,
                title="Scan Execution Failure",
                category="Execution Error",
                severity=DBSeverityLevel.HIGH,
                description=f"Unexpected error during posture audit execution: {str(err)}",
                remediation="Verify target network reachability and host DNS/IP configuration.",
                affected_url=target_url,
                evidence={"error": str(err)},
            )
            db.add(err_finding)
            scan.update_severity_counts()
            db.commit()

        return scan

    def _get_or_create_scan(self, db, scan_id: Optional[int], target_url: str) -> Scan:
        if scan_id:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.target_url = target_url
                return scan
        scan = Scan(target_url=target_url, status=ScanStatus.PENDING)
        db.add(scan)
        db.commit()
        return scan
