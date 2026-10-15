"""Database configuration and portable schema management."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, Text, create_engine, inspect, select, text
from sqlalchemy.engine import Connection, Engine, URL, RowMapping
from sqlalchemy.pool import NullPool

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE = str(PROJECT_ROOT / "database.db")
load_dotenv(PROJECT_ROOT / ".env")


def build_database_url() -> str:
    """Build a SQLAlchemy URL from DATABASE_URL or individual DB_* settings."""
    configured = os.environ.get("DATABASE_URL") or os.environ.get("DATABASE")
    if configured:
        if "://" in configured:
            return configured
        return f"sqlite:///{Path(configured).expanduser().resolve()}"

    db_engine = os.environ.get("DB_ENGINE", "sqlite").lower()
    if db_engine == "sqlite":
        path = Path(os.environ.get("DB_PATH", DEFAULT_DATABASE)).expanduser()
        return f"sqlite:///{path.resolve()}"

    driver = {"postgresql": "postgresql+psycopg", "postgres": "postgresql+psycopg", "mysql": "mysql+pymysql"}.get(
        db_engine
    )
    if not driver:
        raise ValueError("DB_ENGINE must be sqlite, postgresql, or mysql")
    query: dict[str, str] = {}
    for name in ("DB_SSL_CA", "DB_SSL_CERT", "DB_SSL_KEY"):
        if os.environ.get(name):
            query[name[3:].lower()] = os.environ[name]
    if os.environ.get("DB_SSL_MODE") and db_engine in {"postgresql", "postgres"}:
        query["sslmode"] = os.environ["DB_SSL_MODE"]
    url = URL.create(
        drivername=driver,
        username=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        host=os.environ.get("DB_HOST"),
        port=int(os.environ["DB_PORT"]) if os.environ.get("DB_PORT") else None,
        database=os.environ.get("DB_NAME"),
        query=query,
    )
    return url.render_as_string(hide_password=False)


DATABASE_URL = build_database_url()
engine: Engine


def configure_database(url: str | None = None) -> Engine:
    """Configure the shared engine, primarily useful for tests and app startup."""
    global DATABASE_URL, engine
    DATABASE_URL = url or build_database_url()
    is_sqlite = DATABASE_URL.startswith("sqlite")
    engine = create_engine(
        DATABASE_URL,
        future=True,
        pool_pre_ping=True,
        poolclass=NullPool if is_sqlite else None,
        connect_args={"check_same_thread": False, "timeout": 30} if is_sqlite else {},
    )
    return engine


configure_database(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(150), unique=True, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("email", String(320), unique=True, nullable=False),
    Column("created_at", Text, server_default=text("CURRENT_TIMESTAMP")),
)
credentials = Table(
    "credentials",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("site_name", String(255), nullable=False),
    Column("login", String(320)),
    Column("email", String(320)),
    Column("password_encrypted", Text, nullable=False),
    Column("created_at", Text, server_default=text("CURRENT_TIMESTAMP")),
    Column("updated_at", Text, server_default=text("CURRENT_TIMESTAMP")),
)
secure_notes = Table(
    "secure_notes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("title", String(255), nullable=False),
    Column("content_encrypted", Text, nullable=False),
    Column("note_password_hash", Text, nullable=False),
    Column("access_token", String(255), unique=True, nullable=False),
    Column("access_token_expires_at", Text, nullable=False),
    Column("access_token_revoked_at", Text),
    Column("created_at", Text, server_default=text("CURRENT_TIMESTAMP")),
    Column("updated_at", Text, server_default=text("CURRENT_TIMESTAMP")),
)


vaults = Table(
    "vaults",
    metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("wrapped_key", Text, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("crypto_version", Integer, nullable=False),
)
schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", Integer, primary_key=True),
)


def _placeholder_sql(sql: str, params: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(params, (tuple, list)):
        return sql, params or {}
    index = 0

    def replace(_match: re.Match[str]) -> str:
        nonlocal index
        name = f"p{index}"
        index += 1
        return f":{name}"

    return re.sub(r"\?", replace, sql), {f"p{i}": value for i, value in enumerate(params)}


class CursorAdapter:
    """Compatibility adapter for the current routes' cursor-shaped API."""

    def __init__(self, connection: Connection):
        self.connection = connection
        self.result = None
        self.lastrowid = None

    def execute(self, sql: str, params: Any = ()):
        sql, params = _placeholder_sql(sql, params)
        normalized = sql.lstrip().upper()
        if (
            normalized.startswith("INSERT")
            and "RETURNING" not in normalized
            and self.connection.engine.dialect.name in {"postgresql", "sqlite"}
        ):
            sql += " RETURNING id"
        self.result = self.connection.execute(text(sql), params)
        if normalized.startswith("INSERT"):
            if self.result.returns_rows:
                row = self.result.fetchone()
                self.lastrowid = row[0] if row else None
            elif self.connection.engine.dialect.name == "mysql":
                self.lastrowid = self.connection.execute(text("SELECT LAST_INSERT_ID()")).scalar()
            else:
                self.lastrowid = getattr(self.result, "lastrowid", None)
        return self

    def fetchone(self) -> RowMapping | None:
        row = self.result.fetchone()
        return row._mapping if row else None

    def fetchall(self) -> list[RowMapping]:
        return [row._mapping for row in self.result.fetchall()]

    @property
    def rowcount(self) -> int:
        return self.result.rowcount


class ConnectionAdapter:
    def __init__(self, connection: Connection):
        self.connection = connection

    def cursor(self) -> CursorAdapter:
        return CursorAdapter(self.connection)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()


def get_db_connection() -> ConnectionAdapter:
    connection = engine.connect()
    if engine.dialect.name == "sqlite":
        connection.execute(text("PRAGMA busy_timeout = 30000"))
        connection.execute(text("PRAGMA foreign_keys = ON"))
    adapter = ConnectionAdapter(connection)
    from flask import g, has_request_context

    if has_request_context():
        g.setdefault("db_connections", []).append(adapter)
    return adapter


def init_db() -> None:
    """Create the schema and upgrade note-token columns when needed."""
    metadata.create_all(engine)
    inspector = inspect(engine)
    column_names = {column["name"] for column in inspector.get_columns("secure_notes")}
    with engine.begin() as connection:
        if "access_token_expires_at" not in column_names:
            connection.execute(text("ALTER TABLE secure_notes ADD COLUMN access_token_expires_at TIMESTAMP"))
            connection.execute(
                text(
                    "UPDATE secure_notes SET access_token_expires_at = CURRENT_TIMESTAMP WHERE access_token_expires_at IS NULL"
                )
            )
        if "access_token_revoked_at" not in column_names:
            connection.execute(text("ALTER TABLE secure_notes ADD COLUMN access_token_revoked_at TIMESTAMP"))
        if (
            connection.execute(select(schema_migrations.c.version).where(schema_migrations.c.version == 1)).first()
            is None
        ):
            connection.execute(schema_migrations.insert().values(version=1))
    print(f"Database initialized successfully ({engine.dialect.name}).")


if __name__ == "__main__":
    init_db()
