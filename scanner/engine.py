from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
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


SENSITIVE_RESPONSE_HEADER_MARKERS = (
    "token", "secret", "key", "auth", "credential", "cookie", "session",
)


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
        # Class object passed directly by accident
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

    def execute_scan(self, raw_url: str, scan_id: Optional[int] = None) -> Scan:
        """Executes full passive posture audit against a validated target URL.

        Args:
            raw_url: Input target URL string.
            scan_id: Optional existing DB Scan ID to attach results to.

        Returns:
            Updated Scan database model instance.
        """
        db = get_session()

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

        try:
            raw_findings: List[RawFinding] = []

            # Step 2: Initial HTTP GET Discovery Probe
            get_resp: HTTPResponseData = self.http_client.get(target_url)

            if get_resp.error:
                # Capture connectivity/TLS failure as an auditing finding
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
                    # Attach recon metadata to scan response_headers for reporting
                    if scan.response_headers is None:
                        scan.response_headers = {}
                    scan.response_headers["_recon"] = {
                        "ct_subdomain_count": len(recon_result.ct_subdomains),
                        "ct_subdomains": recon_result.ct_subdomains[:20],
                        "spf_record": recon_result.spf_record,
                        "dmarc_record": recon_result.dmarc_record,
                        "dkim_selectors_found": recon_result.dkim_selectors_found,
                        "dangling_cnames": recon_result.dangling_cnames,
                        "detected_tech": recon_result.detected_tech,
                        "tls_info": recon_result.tls_info,
                        "redirect_chain": recon_result.redirect_chain,
                    }
                except Exception:
                    pass  # Recon is additive — failures must not abort core scan

                scan.status = ScanStatus.COMPLETED

            scan.completed_at = datetime.utcnow()

            # Step 6: Persist findings into database models
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

            # Update aggregated severity counters
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
