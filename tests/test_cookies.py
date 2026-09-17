import pytest
from scanner.cookies import audit_cookies
from scanner.severity import SeverityLevel


def test_missing_httponly_flag():
    raw_cookies = ["session=secret123; Path=/"]
    findings = audit_cookies("http://example.com", raw_cookies)

    httponly_findings = [f for f in findings if "Missing HttpOnly Flag" in f.title]
    assert len(httponly_findings) == 1
    assert httponly_findings[0].severity == SeverityLevel.MEDIUM
    assert httponly_findings[0].evidence["missing"] == "HttpOnly"


def test_missing_secure_flag_over_https():
    raw_cookies = ["auth=token999; Path=/; HttpOnly"]
    findings = audit_cookies("https://secure.example.com", raw_cookies)

    secure_findings = [f for f in findings if "Missing Secure Flag" in f.title]
    assert len(secure_findings) == 1
    assert secure_findings[0].severity == SeverityLevel.MEDIUM


def test_missing_samesite_attribute():
    raw_cookies = ["tracker=abc; Path=/; HttpOnly"]
    findings = audit_cookies("http://example.com", raw_cookies)

    samesite_findings = [f for f in findings if "Missing SameSite Attribute" in f.title]
    assert len(samesite_findings) == 1
    assert samesite_findings[0].severity == SeverityLevel.LOW


def test_invalid_samesite_none_without_secure():
    raw_cookies = ["cross_site=xyz; Path=/; SameSite=None"]
    findings = audit_cookies("http://example.com", raw_cookies)

    invalid_samesite = [f for f in findings if "Insecure SameSite=None" in f.title]
    assert len(invalid_samesite) == 1
    assert invalid_samesite[0].severity == SeverityLevel.HIGH
