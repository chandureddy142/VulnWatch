from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

Base = declarative_base()
db_session = None
engine = None


def init_db(database_uri: str):
    """Initialize SQLite database engine, session, and create all registered tables."""
    global db_session, engine
    engine = create_engine(
    database_uri,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=300,
)
    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine)
    )
    Base.query = db_session.query_property()

    # Import models to ensure they are registered with Base metadata before creation
    import database.models  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Safe migration: add triage columns to existing findings tables that predate this change.
    # Uses pragma table_info to check for column existence before issuing ALTER TABLE.
    _run_migrations(database_uri)

    return db_session


def _run_migrations(database_uri: str):
    """Apply safe incremental schema migrations for SQLite databases."""
    # Only run for SQLite (in-memory and file-based)
    if not database_uri.startswith("sqlite"):
        return

    with engine.connect() as conn:
        # Check if triage_status column exists in findings table
        result = conn.execute(text("PRAGMA table_info(findings)"))
        columns = {row[1] for row in result}

        if "triage_status" not in columns:
            conn.execute(
                text(
                    "ALTER TABLE findings ADD COLUMN triage_status VARCHAR(20) NOT NULL DEFAULT 'active'"
                )
            )

        if "triage_notes" not in columns:
            conn.execute(
                text("ALTER TABLE findings ADD COLUMN triage_notes TEXT")
            )

        # Check for auth columns on scans table
        result = conn.execute(text("PRAGMA table_info(scans)"))
        scan_columns = {row[1] for row in result}

        if "user_id" not in scan_columns:
            conn.execute(
                text("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
            )

        if "guest_session_id" not in scan_columns:
            conn.execute(
                text("ALTER TABLE scans ADD COLUMN guest_session_id VARCHAR(100)")
            )

        conn.commit()


def get_session():
    """Retrieve the current active thread-local database session."""
    if db_session is None:
        raise RuntimeError("Database has not been initialized. Call init_db() first.")
    return db_session


def shutdown_session(exception=None):
    """Teardown database session at request completion."""
    if db_session is not None:
        db_session.remove()
