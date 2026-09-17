import pytest
from scanner.headers import audit_headers
from scanner.severity import SeverityLevel


def test_missing_csp_header():
    headers = {"Server": "Nginx"}
    findings = audit_headers("http://example.com", headers)

    csp_findings = [f for f in findings if f.title == "Missing Content Security Policy (CSP)"]
    assert len(csp_findings) == 1
    assert csp_findings[0].severity == SeverityLevel.HIGH
    assert "Content-Security-Policy" in csp_findings[0].evidence["header"]


def test_hsts_auditing_https():
    # HSTS missing on HTTPS
    headers = {"Content-Type": "text/html"}
    findings = audit_headers("https://secure.example.com", headers)

    hsts_findings = [f for f in findings if "HSTS" in f.title]
    assert len(hsts_findings) == 1
    assert hsts_findings[0].severity == SeverityLevel.HIGH

    # HSTS present but missing max-age
    headers_invalid = {"Strict-Transport-Security": "includeSubDomains"}
    findings_invalid = audit_headers("https://secure.example.com", headers_invalid)
    assert any("Missing max-age" in f.title for f in findings_invalid)


def test_weak_csp_directives():
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval';"
    }
    findings = audit_headers("http://example.com", headers)

    weak_csp = [f for f in findings if "Weak Content Security Policy Directive" in f.title]
    assert len(weak_csp) == 1
    assert weak_csp[0].severity == SeverityLevel.MEDIUM


def test_missing_xframe_options():
    headers = {}
    findings = audit_headers("http://example.com", headers)

    xfo = [f for f in findings if "Missing X-Frame-Options" in f.title]
    assert len(xfo) == 1
    assert xfo[0].severity == SeverityLevel.MEDIUM


def test_server_and_xpowered_by_disclosure():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    }
    findings = audit_headers("http://example.com", headers)

    titles = [f.title for f in findings]
    assert "Server Software Version Disclosure" in titles
    assert "Server Technology Information Leakage (X-Powered-By)" in titles
