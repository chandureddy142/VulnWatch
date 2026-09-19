import pytest
from unittest.mock import MagicMock, patch
from config.config import TestingConfig
from database.db import init_db, shutdown_session
from database.models import ScanStatus, SeverityLevel
from scanner.cookies import audit_cookies
from scanner.engine import ScanEngine, _to_db_severity
from scanner.findings import RawFinding
from scanner.headers import audit_headers
from scanner.http import HTTPClient, HTTPResponseData
from scanner.methods import audit_http_methods
from scanner.severity import SeverityLevel as EnumSeverityLevel
from scanner.target import TargetValidationError, validate_target_url


@pytest.fixture(scope="module")
def db_session():
    session = init_db(TestingConfig.SQLALCHEMY_DATABASE_URI)
    yield session
    shutdown_session()


def test_target_validation():
    # Test valid targets
    assert validate_target_url("https://8.8.8.8") == "https://8.8.8.8/"

    # Test invalid schemes
    with pytest.raises(TargetValidationError):
        validate_target_url("ftp://example.com")

    with pytest.raises(TargetValidationError):
        validate_target_url("file:///etc/passwd")

    # Test localhost restriction when disabled
    with pytest.raises(TargetValidationError):
        validate_target_url("http://127.0.0.1:5000", allow_localhost=False)


def test_header_auditing():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-Frame-Options": "SAMEORIGIN",
    }
    findings = audit_headers("https://example.com", headers)

    titles = [f.title for f in findings]
    assert "Missing Content Security Policy (CSP)" in titles
    assert "Missing HTTP Strict Transport Security (HSTS)" in titles
    assert "Missing or Invalid X-Content-Type-Options Header" in titles
    assert "Server Technology Information Leakage (X-Powered-By)" in titles


def test_cookie_auditing():
    set_cookie_headers = [
        "sessionid=xyz123; Path=/",
        "auth_token=abc456; Path=/; Secure; SameSite=Lax",
    ]
    findings = audit_cookies("https://example.com", set_cookie_headers)

    session_findings = [f for f in findings if "sessionid" in f.title]
    assert len(session_findings) >= 2  # Missing HttpOnly, Secure, SameSite

    auth_findings = [f for f in findings if "auth_token" in f.title]
    # auth_token has Secure and SameSite, but missing HttpOnly
    assert any("HttpOnly" in f.title for f in auth_findings)


def test_http_methods_auditing():
    mock_client = MagicMock(spec=HTTPClient)
    mock_client.options.return_value = HTTPResponseData(
        url="http://example.com",
        status_code=200,
        headers={"Allow": "GET, POST, OPTIONS, TRACE, PUT"},
    )

    methods, findings = audit_http_methods("http://example.com", mock_client)
    assert "TRACE" in methods
    assert "PUT" in methods
    assert any("TRACE" in f.title for f in findings)
    assert any("PUT" in f.title for f in findings)


def test_scan_engine_orchestration(db_session):
    engine = ScanEngine(allow_localhost=False)

    with patch.object(engine.http_client, "get") as mock_get, patch.object(
        engine.http_client, "options"
    ) as mock_options:

        mock_get.return_value = HTTPResponseData(
                url="https://8.8.8.8/",
            status_code=200,
            headers={
                "Server": "Werkzeug/3.0.3",
                "Content-Type": "text/html",
            },
            raw_set_cookie_headers=["tracker_id=100; Path=/"],
        )

        mock_options.return_value = HTTPResponseData(
                url="https://8.8.8.8/",
            status_code=200,
            headers={"Allow": "GET, HEAD, POST, OPTIONS"},
        )

        scan = engine.execute_scan("https://8.8.8.8")

        assert scan.status == ScanStatus.COMPLETED
        assert scan.status_code == 200
        assert len(scan.findings) > 0
        assert scan.high_count >= 1  # e.g., CSP missing


def test_scan_engine_connection_failure(db_session):
    """Test scan execution when target connection fails (get_resp.error is set)."""
    engine = ScanEngine(allow_localhost=False)

    with patch.object(engine.http_client, "get") as mock_get:
        mock_get.return_value = HTTPResponseData(
            url="https://safepass.chandureddy.in/",
            status_code=None,
            error="Connection refused by remote host",
        )

        with patch("scanner.engine.validate_target_url", return_value="https://safepass.chandureddy.in/"):
            scan = engine.execute_scan("https://safepass.chandureddy.in")

        assert scan.status == ScanStatus.FAILED
        assert len(scan.findings) == 1
        f = scan.findings[0]
        assert f.title == "Target Connection Failure"
        assert f.severity == SeverityLevel.HIGH
        assert scan.high_count == 1


def test_to_db_severity_handling():
    """Verify _to_db_severity safely handles enum instances, strings, and class types."""
    assert _to_db_severity(EnumSeverityLevel.CRITICAL) == SeverityLevel.CRITICAL
    assert _to_db_severity(SeverityLevel.LOW) == SeverityLevel.LOW
    assert _to_db_severity("HIGH") == SeverityLevel.HIGH
    assert _to_db_severity("medium") == SeverityLevel.MEDIUM
    assert _to_db_severity("invalid_string") == SeverityLevel.HIGH
    assert _to_db_severity(EnumSeverityLevel) == SeverityLevel.HIGH
    assert _to_db_severity(SeverityLevel) == SeverityLevel.HIGH


def test_cleanup_stale_scans(db_session):
    """Verify cleanup_stale_scans marks old running/pending scans as FAILED."""
    from datetime import datetime, timedelta
    from database.models import Scan
    from scanner.engine import cleanup_stale_scans

    stale_scan = Scan(
        target_url="http://stale.local",
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow() - timedelta(minutes=5),
    )
    db_session.add(stale_scan)
    db_session.commit()

    cleaned = cleanup_stale_scans(db_session, max_age_seconds=120)
    assert cleaned >= 1

    db_session.refresh(stale_scan)
    assert stale_scan.status == ScanStatus.FAILED
    assert stale_scan.completed_at is not None
