import json
import os
import secrets
import uuid
from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session, url_for
from services.auth import require_api_key
from routes.auth import login_required

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")

# Path to persist settings JSON file alongside the config directory
_SETTINGS_FILE = os.path.join(
    os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
    "config",
    "settings.json",
)

_DEFAULTS = {
    "scan_timeout": 10,
    "default_modules": ["headers", "cookies", "methods", "disclosure"],
    "webhook_url": "",
    "api_key": "",
}


def load_settings() -> dict:
    """Load settings from JSON file, returning defaults for any missing keys."""
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            stored = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        stored = {}

    settings = dict(_DEFAULTS)
    settings.update(stored)
    return settings


def save_settings(data: dict) -> None:
    """Persist settings dict to JSON file."""
    os.makedirs(os.path.dirname(_SETTINGS_FILE), exist_ok=True)
    with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


@settings_bp.route("/", methods=["GET"])
@login_required
def settings_page():
    """Render the enterprise settings configuration page (authenticated users only)."""
    settings = load_settings()
    return render_template("settings.html", settings=settings)


@settings_bp.route("/", methods=["POST"])
@login_required
@require_api_key
def save_settings_route():
    """Save updated settings from the settings form (authenticated users only)."""
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()

    settings = load_settings()

    # Validate and update scan timeout
    try:
        timeout = int(data.get("scan_timeout", settings["scan_timeout"]))
        settings["scan_timeout"] = max(1, min(120, timeout))
    except (ValueError, TypeError):
        pass

    # Update webhook URL
    settings["webhook_url"] = str(data.get("webhook_url", "")).strip()

    # Update default modules (multi-value checkboxes)
    if request.is_json:
        modules = data.get("default_modules", settings["default_modules"])
    else:
        modules = request.form.getlist("default_modules")
    if modules:
        settings["default_modules"] = modules

    save_settings(settings)

    # Persist the current API key to session and cookie
    current_key = settings.get("api_key", "")
    if current_key:
        session["api_key"] = current_key

    response = make_response(jsonify({"message": "Settings saved successfully.", "settings": settings}))
    if current_key:
        response.set_cookie(
            "api_key",
            current_key,
            max_age=60 * 60 * 24 * 30,  # 30 days
            httponly=True,
            samesite="Lax",
        )

    return response


@settings_bp.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    """Generate and persist a new random API key (Google authenticated users only)."""
    user_id = session.get("user_id")
    if not user_id or session.get("is_guest"):
        return jsonify({
            "error": "Google Sign-In required",
            "message": "Sign in with Google to generate API keys.",
            "redirect": url_for("auth.login", reason="settings", _external=False),
        }), 403

    from database.db import get_session
    from database.models import User

    db = get_session()
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        user_email = (session.get("user") or {}).get("email") or f"user_{user_id}@example.com"
        user_name = (session.get("user") or {}).get("name") or "User"
        user = User(id=user_id, email=user_email, name=user_name)
        db.add(user)
        db.commit()

    new_key = f"vw_live_{secrets.token_hex(16)}"
    user.api_key = new_key
    db.commit()

    settings = load_settings()
    settings["api_key"] = new_key
    save_settings(settings)
    session["api_key"] = new_key

    response = make_response(jsonify({
        "status": "success",
        "api_key": new_key,
        "key": new_key,
        "message": "API key generated successfully."
    }))
    
    response.set_cookie(
        "api_key",
        new_key,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        samesite="Lax",
    )
    return response


@settings_bp.route("/revoke-api-key", methods=["POST"])
def revoke_api_key():
    """Revoke API key for the current Google authenticated user."""
    user_id = session.get("user_id")
    if not user_id or session.get("is_guest"):
        return jsonify({
            "error": "Google Sign-In required",
            "message": "Sign in with Google to revoke API keys.",
        }), 403

    from database.db import get_session
    from database.models import User

    db = get_session()
    user = db.query(User).filter_by(id=user_id).first()
    if user:
        user.api_key = None
        db.commit()

    settings = load_settings()
    settings["api_key"] = ""
    save_settings(settings)
    session.pop("api_key", None)

    return jsonify({"message": "API key revoked successfully."})