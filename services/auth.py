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


def require_api_key_or_browser(view):
    """Flexible auth decorator for scan endpoints reachable from both the browser UI and the API.

    Rules:
    - If the request carries a valid API key (header / session / cookie) → allow.
    - If *no* API key is configured on the server → allow (dev / first-run mode).
    - If the request is a browser-initiated form or JSON POST **without** an
      explicit API key header → allow (quota is enforced by the route itself
      via guest_device_id cookie logic).
    - If an API key IS configured AND the caller supplies one that does NOT match
      → reject with 401 (protects the programmatic API).
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = _configured_api_key()

        # No key configured → open access (dev mode / unconfigured instance)
        if not expected:
            return view(*args, **kwargs)

        supplied = _provided_api_key()

        # Key supplied and matches → allow
        if supplied and hmac.compare_digest(supplied, expected):
            return view(*args, **kwargs)

        # Key supplied but wrong → always reject
        if supplied:
            return jsonify({"error": "Authentication required."}), 401

        # No key supplied — allow browser sessions through; the route enforces
        # guest quotas via cookie.  Programmatic callers that want access should
        # provide a key.
        return view(*args, **kwargs)

    return wrapped