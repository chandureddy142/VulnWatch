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


def get_user_by_api_key(key: str):
    """Retrieve Google User record matching an API key, or None."""
    if not key or not key.strip():
        return None
    from database.db import get_session
    from database.models import User
    try:
        db = get_session()
        return db.query(User).filter(User.api_key == key.strip()).first()
    except Exception:
        return None


def require_api_key(view):
    """Require API key via Header, Session, or Cookie for a view.
    
    Accepts configured server key OR a valid Google user API key.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        supplied = _provided_api_key()
        if not supplied:
            return jsonify({"error": "Authentication required."}), 401

        # Check DB user API key first
        user = get_user_by_api_key(supplied)
        if user:
            return view(*args, **kwargs)

        expected = _configured_api_key()
        if expected and hmac.compare_digest(supplied, expected):
            return view(*args, **kwargs)

        return jsonify({"error": "Authentication required."}), 401

    return wrapped


def require_api_key_or_browser(view):
    """Flexible auth decorator for scan endpoints reachable from both the browser UI and the API."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        supplied = _provided_api_key()

        if supplied:
            user = get_user_by_api_key(supplied)
            if user:
                return view(*args, **kwargs)

            expected = _configured_api_key()
            if expected and hmac.compare_digest(supplied, expected):
                return view(*args, **kwargs)

            return jsonify({"error": "Authentication required."}), 401

        expected = _configured_api_key()
        if not expected:
            return view(*args, **kwargs)

        return view(*args, **kwargs)

    return wrapped