import socket

import pytest
from scanner.target import TargetValidationError, validate_target_url


def _public_dns(*_args, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def test_valid_urls(monkeypatch):
    monkeypatch.setattr("scanner.target.socket.getaddrinfo", _public_dns)
    assert validate_target_url("https://example.com/path?q=1") == "https://example.com/path?q=1"


def test_invalid_url_schemes():
    with pytest.raises(TargetValidationError) as exc:
        validate_target_url("ftp://files.example.com")
    assert "Disallowed scheme 'ftp'" in str(exc.value)

    with pytest.raises(TargetValidationError) as exc:
        validate_target_url("file:///etc/passwd")
    assert "Disallowed scheme 'file'" in str(exc.value)


def test_empty_or_malformed_url():
    with pytest.raises(TargetValidationError):
        validate_target_url("")

    with pytest.raises(TargetValidationError):
        validate_target_url("   ")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:5000", "http://10.0.0.1", "http://169.254.169.254",
    "http://100.64.0.1", "http://[fc00::1]", "http://[fe80::1]",
])
def test_non_public_ip_ranges_are_rejected(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, allow_localhost=True)


def test_hostname_resolving_to_private_address_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "scanner.target.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))],
    )
    with pytest.raises(TargetValidationError):
        validate_target_url("https://controlled.example")
