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


@contextmanager
def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = DELETE")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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
    with get_connection() as conn:
        _migrate(conn)       # upgrade old schema if present
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
    if DB_PATH.exists():
        DB_PATH.unlink()
    for ext in ("-wal", "-shm", "-journal"):
        p = DB_PATH.parent / (DB_PATH.name + ext)
        if p.exists():
            p.unlink()
