from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()
db_session = None
engine = None


def init_db(database_uri: str):
    """Initialize the database engine, session factory, and table schema.

    For PostgreSQL (Render / production): configures connection pooling with
    pre-ping, keepalives, and aggressive recycling to prevent the
    ``SSL error: decryption failed or bad record mac`` that arises when Render's
    NAT/proxy silently drops idle TCP connections.

    For SQLite: uses NullPool (each call gets a fresh connection) which avoids
    WAL-mode locking on multi-threaded Flask dev servers.
    """
    global db_session, engine

    is_postgres = database_uri.startswith(("postgresql", "postgres"))

    if is_postgres:
        # TCP keepalive options for psycopg2 — tell the kernel to send keepalive
        # probes after 60 s idle, then every 10 s, giving up after 5 failures.
        # This keeps the SSL session alive through Render's 90-second proxy timeout.
        connect_args = {
            "sslmode": "require",
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        }
        engine = create_engine(
            database_uri,
            echo=False,
            # Health-check every connection before handing it to the app
            pool_pre_ping=True,
            # Recycle connections before Render's 300-s proxy timeout
            pool_recycle=300,
            pool_timeout=30,
            pool_size=10,
            max_overflow=5,
            connect_args=connect_args,
        )
    else:
        # SQLite — in-memory databases share a single connection (StaticPool)
        # so that test data persists; file-based SQLite uses NullPool to avoid
        # WAL-mode locking issues on multi-threaded Flask dev servers.
        is_memory = ":memory:" in database_uri or database_uri == "sqlite://"
        if is_memory:
            from sqlalchemy.pool import StaticPool
            engine = create_engine(
                database_uri,
                echo=False,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(
                database_uri,
                echo=False,
                pool_pre_ping=True,
                pool_recycle=300,
                poolclass=NullPool,
            )

    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine)
    )
    Base.query = db_session.query_property()

    # Import models to ensure they are registered with Base metadata before creation
    import database.models  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Safe schema migrations (additive only — never drops columns)
    _run_migrations(database_uri)

    return db_session


def _run_migrations(database_uri: str):
    """Apply safe, additive schema migrations (never drops columns or tables).

    Supports both SQLite (PRAGMA-based introspection) and PostgreSQL
    (information_schema-based introspection).
    """
    is_postgres = database_uri.startswith(("postgresql", "postgres"))
    is_sqlite = database_uri.startswith("sqlite")

    with engine.connect() as conn:
        if is_sqlite:
            # ── SQLite: use PRAGMA table_info ──────────────────────────────────
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

        elif is_postgres:
            # ── PostgreSQL: use information_schema ─────────────────────────────
            def _pg_has_column(conn, table, column):
                row = conn.execute(
                    text(
                        "SELECT COUNT(*) FROM information_schema.columns "
                        "WHERE table_name = :t AND column_name = :c"
                    ),
                    {"t": table, "c": column},
                ).scalar()
                return row > 0

            if not _pg_has_column(conn, "findings", "triage_status"):
                conn.execute(
                    text(
                        "ALTER TABLE findings ADD COLUMN triage_status VARCHAR(20) NOT NULL DEFAULT 'active'"
                    )
                )

            if not _pg_has_column(conn, "findings", "triage_notes"):
                conn.execute(text("ALTER TABLE findings ADD COLUMN triage_notes TEXT"))

            if not _pg_has_column(conn, "scans", "user_id"):
                conn.execute(
                    text("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
                )

            if not _pg_has_column(conn, "scans", "guest_session_id"):
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
