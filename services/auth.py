"""Small, shared API-key authentication helpers for privileged routes."""

import hmac
from functools import wraps

from flask import current_app, jsonify, request, session  # <-- added session


def _configured_api_key() -> str:
    """Return the active key without exposing it in an error response."""
    from routes.settings import load_settings

    configured_key = str(current_app.config.get("API_KEY") or "")
    if current_app.config.get("TESTING"):
        return configured_key
    stored_key = str(load_settings().get("api_key") or "")
    return stored_key or configured_key


def _provided_api_key() -> str:
    # 1. Check custom header
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return api_key.strip()

    # 2. Check Authorization Bearer header
    scheme, _, value = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()

    # 3. Check Flask session (logged in via browser)
    session_key = session.get("api_key", "")
    if session_key:
        return str(session_key).strip()

    # 4. Check HTTP cookie
    cookie_key = request.cookies.get("api_key", "")
    if cookie_key:
        return str(cookie_key).strip()

    return ""


def require_api_key(view):
    """Require API key via Header, Session, or Cookie for a view."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = _configured_api_key()
        if not expected:
            return jsonify({"error": "API authentication is not configured."}), 503
        supplied = _provided_api_key()
        if not supplied or not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "Authentication required."}), 401
        return view(*args, **kwargs)

    return wrapped