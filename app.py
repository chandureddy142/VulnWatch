import os
from flask import Flask, jsonify
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
    app.config.from_object(cfg_class)

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

    # Error Handlers
    @app.errorhandler(TargetValidationError)
    def handle_target_validation_error(err):
        return jsonify({"error": "Target Validation Error", "message": str(err)}), 400

    @app.errorhandler(400)
    def handle_bad_request(err):
        return jsonify({"error": "Bad Request", "message": str(err)}), 400

    @app.errorhandler(404)
    def handle_not_found(err):
        return jsonify({"error": "Resource Not Found"}), 404

    @app.errorhandler(500)
    def handle_internal_error(err):
        return jsonify({"error": "Internal Server Error", "message": str(err)}), 500

    return app


if __name__ == "__main__":
    env_name = os.environ.get("FLASK_ENV", "development")
    app = create_app(env_name)
    app.run(
        host=app.config.get("HOST", "127.0.0.1"),
        port=app.config.get("PORT", 5000),
        debug=app.config.get("DEBUG", True),
    )
