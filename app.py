import os
import uuid
from flask import Flask, jsonify, request
from config.config import config
from database.db import init_db, shutdown_session
from routes.api import api_bp
from routes.auth import auth_bp, profile_bp
from routes.dashboard import dashboard_bp
from routes.reports import reports_bp
from routes.scanner import scanner_bp
from routes.schedules import schedules_bp
from routes.search import search_bp
from routes.settings import settings_bp
from scanner.target import TargetValidationError


def create_app(config_name: str = "default") -> Flask:
    """Application factory for WebGuard Flask web server."""
    app = Flask(__name__)

    # Load configuration
    cfg_class = config.get(config_name, config["default"])
    cfg = cfg_class()
    app.config.from_object(cfg)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_timeout": 20,
        "max_overflow": 10,
        "pool_size": 5,
        "connect_args": {
            "sslmode": "require",
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    }

    # Initialize Database Engine
    init_db(
        app.config["SQLALCHEMY_DATABASE_URI"],
        engine_options=app.config.get("SQLALCHEMY_ENGINE_OPTIONS"),
    )

    # Teardown database session on request context end
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        from database.db import db
        if db and db.session is not None:
            db.session.remove()

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(search_bp)

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

    @app.context_processor
    def inject_guest_context():
        """Inject guest-mode quota state into every template context.

        Tier determination:
          Tier 3 (Google): session['user_id'] is set
          Tier 2 (guest):  session['is_guest'] is True OR guest_device_id cookie present
          Tier 1 (anon):   neither of the above
        """
        from flask import request as req, session as sess
        try:
            user_id = sess.get("user_id")
            guest_scan_limit = app.config.get("GUEST_SCAN_LIMIT", 3)

            # Tier 3
            if user_id:
                return {
                    "is_guest": False,
                    "guest_scans_left": guest_scan_limit,
                    "guest_scan_limit": guest_scan_limit,
                }

            # Tier 2: explicit guest session OR returning visitor with cookie
            guest_device_id = (
                req.cookies.get("guest_device_id", "").strip()
                or sess.get("guest_id", "")
                or sess.get("guest_session_id", "")
            )
            is_guest = bool(sess.get("is_guest")) or bool(guest_device_id)

            if is_guest and guest_device_id:
                from database.db import get_session as _gs
                from database.models import Scan as _Scan
                db = _gs()
                used = db.query(_Scan).filter_by(guest_session_id=guest_device_id).count()
                guest_scans_left = max(0, guest_scan_limit - used)
            else:
                guest_scans_left = guest_scan_limit

            return {
                "is_guest": is_guest,
                "guest_scans_left": guest_scans_left,
                "guest_scan_limit": guest_scan_limit,
            }
        except Exception:
            return {
                "is_guest": False,
                "guest_scans_left": 3,
                "guest_scan_limit": 3,
            }

    return app


if __name__ == "__main__":
    env_name = os.environ.get("FLASK_ENV", "development")
    app = create_app(env_name)
    app.run(
        host=app.config.get("HOST", "127.0.0.1"),
        port=app.config.get("PORT", 5000),
        debug=app.config.get("DEBUG", True),
    )
