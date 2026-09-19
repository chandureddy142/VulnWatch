import json
import os
import secrets
import uuid
from flask import Blueprint, jsonify, render_template, request
from services.auth import require_api_key

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
def settings_page():
    """Render the enterprise settings configuration page."""
    settings = load_settings()
    return render_template("settings.html", settings=settings)


@settings_bp.route("/", methods=["POST"])
@require_api_key
def save_settings_route():
    """Save updated settings from the settings form."""
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

    if request.is_json:
        return jsonify({"message": "Settings saved successfully.", "settings": settings})

    # Reload page with success feedback via query string (picked up by JS toast)
    return jsonify({"message": "Settings saved successfully.", "settings": settings})


@settings_bp.route("/generate-api-key", methods=["POST"])
def generate_api_key():
    """Generate and persist a new random API key."""
    settings = load_settings()
    new_key = f"wg_{secrets.token_hex(24)}"
    settings["api_key"] = new_key
    save_settings(settings)
    return jsonify({"api_key": new_key})
