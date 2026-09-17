import pytest
from scanner.target import TargetValidationError, validate_target_url


def test_valid_urls():
    assert validate_target_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080/"
    assert validate_target_url("https://example.com/path?q=1") == "https://example.com/path?q=1"
    assert validate_target_url("localhost:5000") == "http://localhost:5000/"


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


def test_localhost_restriction_toggle():
    # Should succeed when localhost is allowed
    assert validate_target_url("http://127.0.0.1:5000", allow_localhost=True) == "http://127.0.0.1:5000/"

    # Should raise error when localhost scanning is explicitly disabled
    with pytest.raises(TargetValidationError) as exc:
        validate_target_url("http://127.0.0.1:5000", allow_localhost=False)
    assert "Localhost scanning is currently disabled" in str(exc.value)
