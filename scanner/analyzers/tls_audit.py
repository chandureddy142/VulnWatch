"""
TLS & Certificate Lifecycle Inspector (Enterprise Module)
=========================================================
Performs passive TLS/certificate posture inspection:
  - Certificate expiration window (< 30 days Medium, < 7 days High)
  - Legacy TLS 1.0 / TLS 1.1 protocol probing
  - Subject Alternative Name (SAN) extraction for asset mapping

Uses non-blocking socket connections with strict timeouts — no payloads.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from scanner.findings import RawFinding
from scanner.severity import SeverityLevel


def _fetch_peer_cert(hostname: str, port: int = 443, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    """Open a TLS connection and return the peer certificate dict, or None on failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def _probe_legacy_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> bool:
    """
    Attempt a TLS connection restricting to TLS 1.0/1.1 to detect legacy protocol support.
    Returns True if the server accepts legacy TLS, False if rejected.
    """
    for tls_version in [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except (ssl.SSLError, ConnectionResetError, OSError):
            continue
        except Exception:
            continue
    return False


def _extract_sans(cert: Dict[str, Any]) -> List[str]:
    """Extract Subject Alternative Names from a peer certificate dict."""
    sans = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            sans.append(san_value)
    return sans


def _cert_not_after(cert: Dict[str, Any]) -> Optional[datetime]:
    """Parse the 'notAfter' field from a peer cert dict into a UTC datetime."""
    not_after_str = cert.get("notAfter")
    if not not_after_str:
        return None
    try:
        # Format: 'Jan  1 00:00:00 2025 GMT'
        dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def audit_tls(hostname: str, port: int = 443) -> Tuple[List[RawFinding], List[str]]:
    """
    Passive TLS certificate lifecycle and protocol strength inspector.

    Args:
        hostname: Target hostname (without scheme or port).
        port: Port to connect on (default 443).

    Returns:
        Tuple of (list of RawFinding, list of SANs discovered).
    """
    findings: List[RawFinding] = []
    sans: List[str] = []

    if not hostname or hostname in ("localhost", "127.0.0.1"):
        return findings, sans

    # ── 1. Certificate Expiration ───────────────────────────────────────────────
    cert = _fetch_peer_cert(hostname, port)
    if cert is not None:
        sans = _extract_sans(cert)
        expiry = _cert_not_after(cert)
        if expiry:
            now = datetime.now(tz=timezone.utc)
            days_remaining = (expiry - now).days
            if days_remaining < 0:
                findings.append(RawFinding(
                    title="TLS Certificate Expired",
                    category="TLS / Transport Security",
                    severity=SeverityLevel.CRITICAL,
                    description=(
                        f"The TLS certificate for '{hostname}' has already expired "
                        f"({abs(days_remaining)} days ago). Browsers will display security warnings, "
                        "and API clients will reject connections."
                    ),
                    remediation="Renew the TLS certificate immediately using your CA or Let's Encrypt.",
                    affected_url=f"https://{hostname}:{port}",
                    evidence={"hostname": hostname, "days_remaining": days_remaining, "expiry": str(expiry)},
                ))
            elif days_remaining < 7:
                findings.append(RawFinding(
                    title=f"TLS Certificate Expires in {days_remaining} Days",
                    category="TLS / Transport Security",
                    severity=SeverityLevel.HIGH,
                    description=(
                        f"The TLS certificate for '{hostname}' expires in {days_remaining} day(s) "
                        f"({expiry.strftime('%Y-%m-%d')}). Imminent expiration risks service outage and "
                        "broken HTTPS connections for all clients."
                    ),
                    remediation=(
                        "Renew the TLS certificate urgently. Enable auto-renewal (e.g. certbot renew) "
                        "and configure monitoring alerts for certificates expiring within 30 days."
                    ),
                    affected_url=f"https://{hostname}:{port}",
                    evidence={"hostname": hostname, "days_remaining": days_remaining, "expiry": str(expiry)},
                ))
            elif days_remaining < 30:
                findings.append(RawFinding(
                    title=f"TLS Certificate Expiring Soon ({days_remaining} Days Remaining)",
                    category="TLS / Transport Security",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"The TLS certificate for '{hostname}' expires in {days_remaining} day(s) "
                        f"on {expiry.strftime('%Y-%m-%d')}. Failure to renew will cause HTTPS "
                        "connection failures and browser security warnings."
                    ),
                    remediation=(
                        "Schedule certificate renewal immediately. Enable automated renewal with "
                        "certbot, AWS ACM, or your cloud provider. Set expiry alerts for 45 days."
                    ),
                    affected_url=f"https://{hostname}:{port}",
                    evidence={"hostname": hostname, "days_remaining": days_remaining, "expiry": str(expiry)},
                ))
            else:
                findings.append(RawFinding(
                    title="TLS Certificate Validity",
                    category="TLS / Transport Security",
                    severity=SeverityLevel.INFO,
                    description=f"TLS certificate is valid for {days_remaining} more days (expires {expiry.strftime('%Y-%m-%d')}).",
                    remediation="No action required. Ensure automated renewal is configured before the 30-day threshold.",
                    affected_url=f"https://{hostname}:{port}",
                    evidence={
                        "hostname": hostname,
                        "days_remaining": days_remaining,
                        "expiry": str(expiry),
                        "sans": sans[:20],
                    },
                ))

        # SAN information finding
        if sans:
            findings.append(RawFinding(
                title="TLS Certificate — Subject Alternative Names",
                category="TLS / Transport Security",
                severity=SeverityLevel.INFO,
                description=(
                    f"The TLS certificate for '{hostname}' covers {len(sans)} SAN(s), mapping "
                    "additional hostnames under the same certificate. Review these for unexpected "
                    "or stale entries."
                ),
                remediation="Audit all SANs for decommissioned subdomains or internal host leakage.",
                affected_url=f"https://{hostname}:{port}",
                evidence={"hostname": hostname, "sans": sans[:30], "san_count": len(sans)},
            ))
    else:
        findings.append(RawFinding(
            title="TLS Certificate Could Not Be Retrieved",
            category="TLS / Transport Security",
            severity=SeverityLevel.INFO,
            description=(
                f"The TLS certificate for '{hostname}:{port}' could not be retrieved. "
                "This may indicate the host does not serve HTTPS on this port, has an invalid "
                "certificate, or is behind a firewall."
            ),
            remediation="Verify HTTPS is correctly configured on the target host.",
            affected_url=f"https://{hostname}:{port}",
            evidence={"hostname": hostname, "port": port},
        ))

    # ── 2. Legacy TLS Protocol Probe ───────────────────────────────────────────
    try:
        if _probe_legacy_tls(hostname, port):
            findings.append(RawFinding(
                title="Legacy TLS Protocol Accepted (TLS 1.0 / TLS 1.1)",
                category="TLS / Transport Security",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"The server at '{hostname}:{port}' accepts TLS 1.0 or TLS 1.1 connections. "
                    "These protocols are deprecated (RFC 8996) and contain known vulnerabilities "
                    "including BEAST and POODLE. PCI DSS 4.0 mandates TLS 1.2 as the minimum."
                ),
                remediation=(
                    "Configure the server to reject TLS 1.0 and TLS 1.1 handshakes. "
                    "Enforce a minimum of TLS 1.2 and prefer TLS 1.3. "
                    "In Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'"
                ),
                affected_url=f"https://{hostname}:{port}",
                evidence={"hostname": hostname, "legacy_tls_accepted": True},
            ))
    except Exception:
        pass

    return findings, sans
