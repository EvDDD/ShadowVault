"""
Vault CRUD operations for ShadowVault.
All sensitive fields are encrypted with the session DEK before storage.

Recovery functions (unlock_with_recovery_key, change_master_password, etc.)
live in core.recovery and are re-exported here for convenience.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from db.schema import get_connection
from core.crypto import (
    encrypt_field, decrypt_field,
    wrap_dek, unwrap_dek,
    derive_kek, make_verification, verify_kek,
    generate_dek, generate_salt, generate_recovery_key,
    argon2_params_to_json,
)
from cryptography.exceptions import InvalidTag

# Re-export recovery API so existing UI imports keep working unchanged
from core.recovery import (                             # noqa: F401
    unlock_with_recovery_key,
    unlock_with_secret_questions,
    has_secret_questions,
    save_secret_questions,
    get_secret_questions,
    change_master_password,
    store_recovery_key,
)


@dataclass
class VaultEntry:
    id:         Optional[int]
    vault_id:   int
    title:      str
    url:        str = ""
    username:   str = ""
    password:   str = ""
    notes:      str = ""
    created_at: str = ""
    updated_at: str = ""


# ── Vault lifecycle ──────────────────────────────────────────────

def create_vault(master_password: str, vault_name: str = "My Vault") -> tuple[bytes, str]:
    """
    Initialise a new vault.
    Returns (dek, recovery_key_display).
    """
    dek = generate_dek()
    kek_salt = generate_salt()
    kek = derive_kek(master_password, kek_salt)
    verification = make_verification(kek)
    kek_enc_dek = wrap_dek(kek, dek)

    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO vault (name) VALUES (?)", (vault_name,)
        )
        vault_id = cur.lastrowid
        conn.execute(
            "INSERT INTO user_auth (vault_id, kek_salt, argon2_params, verification) VALUES (?,?,?,?)",
            (vault_id, kek_salt, argon2_params_to_json(), verification),
        )
        conn.execute(
            "INSERT INTO key_store (vault_id, kek_enc_dek) VALUES (?,?)",
            (vault_id, kek_enc_dek),
        )

    # Delegate recovery key generation to recovery module
    recovery_display = store_recovery_key(vault_id, dek)
    return dek, recovery_display


def unlock_vault(master_password: str) -> Optional[bytes]:
    """
    Verify master password and return DEK on success, None on failure.
    """
    with get_connection() as conn:
        auth = conn.execute(
            "SELECT kek_salt, argon2_params, verification FROM user_auth LIMIT 1"
        ).fetchone()
        if not auth:
            return None

        kek = derive_kek(master_password, bytes(auth["kek_salt"]))
        if not verify_kek(kek, bytes(auth["verification"])):
            return None

        ks = conn.execute(
            "SELECT kek_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        if not ks:
            return None

        try:
            dek = unwrap_dek(kek, bytes(ks["kek_enc_dek"]))
        except (InvalidTag, Exception):
            return None

    return dek






# ── Entry CRUD ───────────────────────────────────────────────────

def _get_vault_id() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not row:
            raise RuntimeError("No vault found.")
        return row["id"]


def add_entry(dek: bytes, entry: VaultEntry) -> int:
    vid = _get_vault_id()
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO vault_entry
               (vault_id, title, url, username, enc_password, enc_notes)
               VALUES (?,?,?,?,?,?)""",
            (
                vid,
                entry.title,
                encrypt_field(dek, entry.url)      if entry.url      else None,
                encrypt_field(dek, entry.username)  if entry.username else None,
                encrypt_field(dek, entry.password),
                encrypt_field(dek, entry.notes)    if entry.notes    else None,
            ),
        )
        return cur.lastrowid


def update_entry(dek: bytes, entry: VaultEntry) -> None:
    with get_connection() as conn:
        conn.execute(
            """UPDATE vault_entry SET
               title=?, url=?, username=?, enc_password=?, enc_notes=?
               WHERE id=?""",
            (
                entry.title,
                encrypt_field(dek, entry.url)      if entry.url      else None,
                encrypt_field(dek, entry.username)  if entry.username else None,
                encrypt_field(dek, entry.password),
                encrypt_field(dek, entry.notes)    if entry.notes    else None,
                entry.id,
            ),
        )


def delete_entry(entry_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM vault_entry WHERE id=?", (entry_id,))


def get_all_entries(dek: bytes, search: str = "") -> list[VaultEntry]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM vault_entry ORDER BY title COLLATE NOCASE"
        ).fetchall()

    entries = []
    for row in rows:
        try:
            e = VaultEntry(
                id=row["id"],
                vault_id=row["vault_id"],
                title=row["title"],
                url=      decrypt_field(dek, bytes(row["url"]))      if row["url"]      else "",
                username= decrypt_field(dek, bytes(row["username"])) if row["username"] else "",
                password= decrypt_field(dek, bytes(row["enc_password"])),
                notes=    decrypt_field(dek, bytes(row["enc_notes"])) if row["enc_notes"] else "",
                created_at=row["created_at"] or "",
                updated_at=row["updated_at"] or "",
            )
        except Exception:
            continue   # skip corrupted entries

        if search:
            q = search.lower()
            if not any(q in (e.title + e.url + e.username + e.notes).lower()):
                continue
        entries.append(e)
    return entries


def get_entry(dek: bytes, entry_id: int) -> Optional[VaultEntry]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM vault_entry WHERE id=?", (entry_id,)
        ).fetchone()
    if not row:
        return None
    return VaultEntry(
        id=row["id"],
        vault_id=row["vault_id"],
        title=row["title"],
        url=      decrypt_field(dek, bytes(row["url"]))      if row["url"]      else "",
        username= decrypt_field(dek, bytes(row["username"])) if row["username"] else "",
        password= decrypt_field(dek, bytes(row["enc_password"])),
        notes=    decrypt_field(dek, bytes(row["enc_notes"])) if row["enc_notes"] else "",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def get_vault_name() -> str:
    with get_connection() as conn:
        row = conn.execute("SELECT name FROM vault LIMIT 1").fetchone()
        return row["name"] if row else "My Vault"
