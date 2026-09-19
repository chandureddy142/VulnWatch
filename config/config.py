import os


class Config:
    """Base configuration settings for WebGuard."""

    # Server settings (Local-only binding by default for security posture auditing)
    HOST = os.environ.get("WEBGARD_HOST", "127.0.0.1")
    PORT = int(os.environ.get("WEBGARD_PORT", 5000))
    SECRET_KEY = os.environ.get("SECRET_KEY")
    API_KEY = os.environ.get("WEBGUARD_API_KEY")

    # Scan & Auditing Parameters
    SCAN_TIMEOUT = int(os.environ.get("WEBGARD_SCAN_TIMEOUT", 10))  # Seconds per HTTP request
    DEFAULT_CONCURRENCY = int(
        os.environ.get("WEBGARD_CONCURRENCY", 5)
    )  # Safe default max concurrent scans
    USER_AGENT = os.environ.get(
        "WEBGARD_USER_AGENT", "WebGuard-Security-Posture-Auditor/1.0"
    )
    ALLOW_LOCALHOST = True

    # Database Configuration
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'webguard.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Reports Storage Path
    REPORTS_DIR = os.path.join(BASE_DIR, "reports_output")


class DevelopmentConfig(Config):
    DEBUG = True
    ALLOW_LOCALHOST = True
    SECRET_KEY = os.environ.get("SECRET_KEY", "development-only-change-me")


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    ALLOW_LOCALHOST = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SCAN_TIMEOUT = 2
    DEFAULT_CONCURRENCY = 2
    SECRET_KEY = "testing-secret-not-for-production"
    API_KEY = "testing-api-key"


class ProductionConfig(Config):
    DEBUG = False
    ALLOW_LOCALHOST = False

    def __init__(self):
        if not self.SECRET_KEY:
            raise RuntimeError("SECRET_KEY must be set in the environment for production.")
        database_url = os.environ.get("DATABASE_URL")
        if not database_url or database_url.lower().startswith("sqlite"):
            raise RuntimeError(
                "DATABASE_URL must be configured with a non-SQLite production database."
            )


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
