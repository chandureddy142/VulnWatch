import os
import uuid
from flask import Flask, jsonify, request
from config.config import config
from database.db import init_db, shutdown_session
from routes.api import api_bp
from routes.dashboard import dashboard_bp
from routes.reports import reports_bp
from routes.scanner import scanner_bp
from routes.settings import settings_bp
from scanner.target import TargetValidationError


def create_app(config_name: str = "default") -> Flask:
    """Application factory for WebGuard Flask web server."""
    app = Flask(__name__)

    # Load configuration
    cfg_class = config.get(config_name, config["default"])
    cfg = cfg_class()
    app.config.from_object(cfg)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config_name == "production",
    )

    # Initialize Database Engine
    init_db(app.config["SQLALCHEMY_DATABASE_URI"])

    # Teardown database session on request context end
    @app.teardown_appcontext
    def cleanup_session(exception=None):
        shutdown_session(exception)

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(settings_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "interest-cohort=()")
        if request.path.startswith(("/api/", "/reports/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Error Handlers
    @app.errorhandler(TargetValidationError)
    def handle_target_validation_error(err):
        return jsonify({"error": "Invalid target."}), 400

    @app.errorhandler(400)
    def handle_bad_request(err):
        return jsonify({"error": "Bad Request"}), 400

    @app.errorhandler(404)
    def handle_not_found(err):
        return jsonify({"error": "Resource Not Found"}), 404

    @app.errorhandler(500)
    def handle_internal_error(err):
        error_id = uuid.uuid4().hex
        app.logger.exception("Unhandled application error id=%s", error_id, exc_info=err)
        return jsonify({"error": "An internal error occurred.", "error_id": error_id}), 500

    return app


if __name__ == "__main__":
    env_name = os.environ.get("FLASK_ENV", "development")
    app = create_app(env_name)
    app.run(
        host=app.config.get("HOST", "127.0.0.1"),
        port=app.config.get("PORT", 5000),
        debug=app.config.get("DEBUG", True),
    )
