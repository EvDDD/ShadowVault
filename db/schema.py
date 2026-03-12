"""
Database schema and connection management for ShadowVault.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path.home() / ".shadowvault" / "vault.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL DEFAULT 'My Vault',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_auth (
    id              INTEGER PRIMARY KEY,
    vault_id        INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    kek_salt        BLOB    NOT NULL,
    argon2_params   TEXT    NOT NULL,
    verification    BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS key_store (
    id                  INTEGER PRIMARY KEY,
    vault_id            INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    kek_enc_dek         BLOB    NOT NULL,
    recovery_enc_dek    BLOB,
    questions_enc_dek   BLOB
);

CREATE TABLE IF NOT EXISTS vault_entry (
    id              INTEGER PRIMARY KEY,
    vault_id        INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    title           TEXT    NOT NULL,
    url             BLOB,
    username        BLOB,
    enc_password    BLOB    NOT NULL,
    enc_notes       BLOB,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secret_question (
    id          INTEGER PRIMARY KEY,
    vault_id    INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    question    TEXT    NOT NULL,
    answer_hash BLOB    NOT NULL,
    salt        BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS stego_image (
    id          INTEGER PRIMARY KEY,
    vault_id    INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    file_path   TEXT    NOT NULL,
    algorithm   TEXT    DEFAULT 'LSB',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS update_entry_timestamp
    AFTER UPDATE ON vault_entry
BEGIN
    UPDATE vault_entry SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
"""


@contextmanager
def get_connection():
    """
    Context manager that opens a SQLite connection, commits on success,
    rolls back on exception, and ALWAYS closes the connection.

    Using check_same_thread=False so this is safe from worker threads.
    Not using WAL mode to avoid cross-process/cross-session lock issues on Windows.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = DELETE")   # safest for single-process app
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def vault_exists() -> bool:
    if not DB_PATH.exists():
        return False
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM vault").fetchone()
            return row[0] > 0
    except Exception:
        return False


def drop_all():
    """Delete the database file (for reset)."""
    if DB_PATH.exists():
        DB_PATH.unlink()
    # Also remove WAL/SHM files if they exist
    for ext in ("-wal", "-shm", "-journal"):
        p = DB_PATH.parent / (DB_PATH.name + ext)
        if p.exists():
            p.unlink()
