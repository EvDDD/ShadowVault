"""
Database schema and connection management for ShadowVault.

All data lives in an IN-MEMORY SQLite database — no vault.db file is ever
written to disk. The database is serialized/deserialized to/from bytes
for embedding into the steganography image.

Requires Python >= 3.11 for sqlite3.Connection.serialize/deserialize.
"""
import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)

# Directory for stego images (no DB file is stored here)
STEGO_DIR = Path.home() / ".shadowvault"

# Legacy path reference — kept so stego_manager can derive STEGO_DIR.
# No file is ever created at this path.
DB_PATH = STEGO_DIR / "vault.db"

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

-- key_store: RSA-based DEK protection for master-password path
-- recovery paths (recovery key / secret questions) use symmetric envelopes
CREATE TABLE IF NOT EXISTS key_store (
    id                  INTEGER PRIMARY KEY,
    vault_id            INTEGER NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    kek_enc_rsa_priv    BLOB    NOT NULL,   -- AES-GCM(KEK, RSA_private_key_bytes)
    rsa_enc_dek         BLOB    NOT NULL,   -- RSA_encrypt(pub_key, DEK)
    recovery_enc_dek    BLOB,               -- AES-GCM(recovery_KEK, DEK)
    questions_enc_dek   BLOB                -- AES-GCM(questions_KEK, DEK)
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


# ── Shared in-memory connection ──────────────────────────────────

_conn: sqlite3.Connection | None = None


def _ensure_conn() -> sqlite3.Connection:
    """Return the shared in-memory connection, creating it if needed."""
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(":memory:", check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA foreign_keys = ON")
        log.info("Created new in-memory SQLite connection")
    return _conn


@contextmanager
def get_connection():
    """
    Yield the shared in-memory connection.
    Commits on success, rolls back on error.
    Never closes the connection (data lives only in memory).
    """
    conn = _ensure_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ── Serialization (for steganography) ────────────────────────────

def load_db_from_bytes(data: bytes) -> None:
    """
    Load a serialized SQLite database into the in-memory connection.
    Replaces ALL existing data in memory.
    """
    conn = _ensure_conn()
    conn.deserialize(data)
    # Re-apply connection settings after deserialize
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    log.info("Loaded %d bytes into in-memory database", len(data))


def dump_db_to_bytes() -> bytes:
    """
    Serialize the in-memory database to bytes.
    Used for embedding into the stego image.
    """
    conn = _ensure_conn()
    data = conn.serialize()
    log.info("Serialized in-memory database: %d bytes", len(data))
    return data


# ── Schema management ────────────────────────────────────────────

def _migrate(conn):
    """
    Auto-migration: if key_store has the old schema (kek_enc_dek column from
    pre-RSA version), drop all tables and recreate cleanly.
    Old data is cryptographically incompatible — new code uses RSA wrapping.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(key_store)")}
    if not cols:
        return  # table not created yet
    if "kek_enc_rsa_priv" in cols:
        return  # already on new schema

    # Old schema detected — wipe all tables so SCHEMA can recreate them fresh
    conn.executescript("""
        PRAGMA foreign_keys = OFF;
        DROP TABLE IF EXISTS stego_image;
        DROP TABLE IF EXISTS secret_question;
        DROP TABLE IF EXISTS vault_entry;
        DROP TABLE IF EXISTS key_store;
        DROP TABLE IF EXISTS user_auth;
        DROP TABLE IF EXISTS vault;
        PRAGMA foreign_keys = ON;
    """)


def init_db():
    """Initialize schema in the in-memory database."""
    conn = _ensure_conn()
    _migrate(conn)         # upgrade old schema if present
    conn.executescript(SCHEMA)
    conn.commit()
    log.info("In-memory database schema initialized")


def vault_exists() -> bool:
    """Check if any vault exists in the in-memory database."""
    try:
        conn = _ensure_conn()
        row = conn.execute("SELECT COUNT(*) FROM vault").fetchone()
        return row[0] > 0
    except Exception:
        return False


def close_db():
    """Close the in-memory connection (destroys all data)."""
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None
        log.info("In-memory database connection closed")


def drop_all():
    """
    Reset the in-memory database and clean up any legacy files on disk.
    """
    close_db()
    # Remove any leftover file-based DB from previous versions
    for f in [DB_PATH] + [DB_PATH.parent / (DB_PATH.name + ext)
                          for ext in ("-wal", "-shm", "-journal")]:
        if f.exists():
            f.unlink()
