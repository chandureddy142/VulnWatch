"""
Tests for scanner/recon.py — Passive Reconnaissance & Attack Surface Mapping module.
All tests use mocking to avoid real network calls.
"""
import pytest
from unittest.mock import MagicMock, patch

from scanner.recon import (
    ReconResult,
    _fingerprint_tech_stack,
    _audit_tls_and_redirects,
    run_passive_recon,
)
from scanner.severity import SeverityLevel


# ──────────────────────────────────────────────────────────────────────────────
# Tech Stack Fingerprinting Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestTechStackFingerprinting:
    def test_server_header_version_disclosure_flagged(self):
        """Server header with version number produces an Info Disclosure finding."""
        result = ReconResult(target_host="example.com")
        headers = {"Server": "nginx/1.22.1", "Content-Type": "text/html"}
        _fingerprint_tech_stack("https://example.com", headers, result)

        assert len(result.detected_tech) >= 1
        assert any("nginx" in t["tech"].lower() for t in result.detected_tech)

        version_findings = [f for f in result.findings if "Version Disclosed" in f.title or "Server" in f.title]
        assert len(version_findings) >= 1
        assert version_findings[0].severity == SeverityLevel.LOW

    def test_framework_header_x_powered_by_flagged(self):
        """X-Powered-By header reveals app framework and is flagged."""
        result = ReconResult(target_host="example.com")
        headers = {"X-Powered-By": "PHP/8.1.0", "Content-Type": "text/html"}
        _fingerprint_tech_stack("https://example.com", headers, result)

        tech_labels = [t["label"] for t in result.detected_tech]
        assert "Application Framework" in tech_labels

        findings = [f for f in result.findings if "x-powered-by" in f.title.lower()]
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW

    def test_no_disclosure_headers_no_findings(self):
        """Clean headers with no version or framework disclosure produce no findings."""
        result = ReconResult(target_host="example.com")
        headers = {"Content-Type": "text/html", "Cache-Control": "no-cache"}
        _fingerprint_tech_stack("https://example.com", headers, result)

        assert result.findings == []
        assert result.detected_tech == []

    def test_server_header_without_version_not_flagged(self):
        """Server header without version number is detected but not flagged."""
        result = ReconResult(target_host="example.com")
        headers = {"Server": "cloudflare"}
        _fingerprint_tech_stack("https://example.com", headers, result)

        # Detected but no version disclosure finding
        assert any("cloudflare" in t["tech"].lower() for t in result.detected_tech)
        version_findings = [f for f in result.findings if "Version" in f.title]
        assert len(version_findings) == 0

    def test_aspnet_version_header_flagged(self):
        """X-AspNet-Version header is detected and flagged as information disclosure."""
        result = ReconResult(target_host="example.com")
        headers = {"X-AspNet-Version": "4.0.30319", "Content-Type": "text/html"}
        _fingerprint_tech_stack("https://example.com", headers, result)

        aspnet_findings = [f for f in result.findings if "x-aspnet-version" in f.title.lower()]
        assert len(aspnet_findings) == 1
        assert aspnet_findings[0].severity == SeverityLevel.LOW


# ──────────────────────────────────────────────────────────────────────────────
# TLS and Redirect Chain Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestTlsAndRedirectAudit:
    def test_http_target_flagged_as_no_tls(self):
        """HTTP target (no TLS) generates a HIGH severity finding."""
        result = ReconResult(target_host="example.com")

        mock_resp = MagicMock()
        mock_resp.url = "http://example.com"
        mock_resp.status_code = 200
        mock_resp.history = []

        with patch("scanner.recon.requests.get", return_value=mock_resp):
            _audit_tls_and_redirects("http://example.com", result, timeout=5)

        assert result.tls_info.get("uses_tls") is False
        tls_findings = [f for f in result.findings if "TLS" in f.title or "HTTPS" in f.title.upper()]
        assert any(f.severity == SeverityLevel.HIGH for f in tls_findings)

    def test_https_target_marked_as_tls_enabled(self):
        """HTTPS target sets tls_info['uses_tls'] = True."""
        result = ReconResult(target_host="example.com")

        # Mock the main request (no redirect)
        mock_resp = MagicMock()
        mock_resp.url = "https://example.com/"
        mock_resp.status_code = 200
        mock_resp.history = []

        # Mock the HTTP version check (redirects to HTTPS)
        mock_http_resp = MagicMock()
        mock_http_resp.url = "https://example.com/"

        with patch("scanner.recon.requests.get", side_effect=[mock_resp, mock_http_resp]):
            _audit_tls_and_redirects("https://example.com", result, timeout=5)

        assert result.tls_info.get("uses_tls") is True

    def test_https_to_http_downgrade_flagged(self):
        """HTTPS → HTTP redirect chain downgrade is flagged as HIGH severity."""
        result = ReconResult(target_host="example.com")

        # Simulate a redirect from HTTPS to HTTP
        mock_redirect = MagicMock()
        mock_redirect.url = "https://example.com"
        mock_redirect.status_code = 301
        mock_redirect.headers = {"Location": "http://example.com/"}

        mock_final = MagicMock()
        mock_final.url = "http://example.com/"  # final URL is HTTP
        mock_final.status_code = 200
        mock_final.history = [mock_redirect]     # one redirect happened

        # For HTTPS target: first call = main request; second = HTTP check (fails to reach HTTPS)
        mock_http_check = MagicMock()
        mock_http_check.url = "http://example.com/"  # stays HTTP

        with patch("scanner.recon.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get.return_value = mock_final
            mock_session_cls.return_value = mock_session

            with patch("scanner.recon.requests.get", return_value=mock_http_check):
                _audit_tls_and_redirects("https://example.com", result, timeout=5)

        downgrade_findings = [
            f for f in result.findings
            if "Downgrade" in f.title or "downgrade" in f.description.lower()
        ]
        assert len(downgrade_findings) >= 1
        assert downgrade_findings[0].severity == SeverityLevel.HIGH

    def test_redirect_chain_is_recorded(self):
        """Multiple redirect hops are recorded in result.redirect_chain."""
        result = ReconResult(target_host="example.com")

        hop1 = MagicMock()
        hop1.url = "http://example.com"
        hop1.status_code = 301
        hop1.headers = {"Location": "https://example.com"}

        final = MagicMock()
        final.url = "https://example.com/"
        final.status_code = 200
        final.history = [hop1]  # one redirect hop recorded by requests

        mock_http = MagicMock()
        mock_http.url = "https://example.com/"

        with patch("scanner.recon.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get.return_value = final
            mock_session_cls.return_value = mock_session

            with patch("scanner.recon.requests.get", return_value=mock_http):
                _audit_tls_and_redirects("https://example.com", result, timeout=5)

        # chain = [hop, final] = 2 entries
        assert len(result.redirect_chain) >= 2

    def test_network_failure_does_not_raise(self):
        """Network errors during TLS audit are silently handled."""
        from requests.exceptions import ConnectionError
        result = ReconResult(target_host="unreachable.example.com")

        with patch("scanner.recon.requests.get", side_effect=ConnectionError("refused")):
            # Should not raise
            _audit_tls_and_redirects("https://unreachable.example.com", result, timeout=2)


# ──────────────────────────────────────────────────────────────────────────────
# run_passive_recon Integration Test
# ──────────────────────────────────────────────────────────────────────────────

class TestRunPassiveRecon:
    def test_returns_recon_result(self):
        """run_passive_recon returns a ReconResult with the correct target host."""
        with (
            patch("scanner.recon.requests.get", side_effect=Exception("no network")),
            patch("scanner.recon.dns.resolver.Resolver"),
        ):
            result = run_passive_recon(
                target_url="https://example.com",
                http_headers={"Server": "nginx/1.22.1"},
                timeout=2,
            )
        assert isinstance(result, ReconResult)
        assert result.target_host == "example.com"

    def test_tech_fingerprinting_runs_within_recon(self):
        """Tech fingerprinting is executed even when network calls fail."""
        with (
            patch("scanner.recon.requests.get", side_effect=Exception("no network")),
            patch("scanner.recon.dns.resolver.Resolver"),
        ):
            result = run_passive_recon(
                target_url="https://example.com",
                http_headers={"X-Powered-By": "Express"},
                timeout=2,
            )
        framework_findings = [f for f in result.findings if "x-powered-by" in f.title.lower()]
        assert len(framework_findings) == 1

    def test_empty_host_does_not_raise(self):
        """Malformed URL with no host does not raise an exception."""
        with (
            patch("scanner.recon.requests.get", side_effect=Exception("no network")),
            patch("scanner.recon.dns.resolver.Resolver"),
        ):
            result = run_passive_recon(
                target_url="http://",
                http_headers={},
                timeout=1,
            )
        assert isinstance(result, ReconResult)
