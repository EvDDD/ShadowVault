"""
Vault CRUD operations for ShadowVault.
All sensitive fields are encrypted with the session DEK before storage.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from db.schema import get_connection
from core.crypto import (
    encrypt_field, decrypt_field,
    wrap_dek, unwrap_dek,
    derive_kek, make_verification, verify_kek,
    generate_dek, generate_salt, generate_recovery_key,
    argon2_params_to_json, parse_recovery_key,
    aes_encrypt, aes_decrypt,
)
from cryptography.exceptions import InvalidTag


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

    recovery_raw, recovery_display = generate_recovery_key()
    rec_salt = generate_salt()
    rec_kek = derive_kek(recovery_raw, rec_salt)
    recovery_enc_dek = wrap_dek(rec_kek, dek)

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
            "INSERT INTO key_store (vault_id, kek_enc_dek, recovery_enc_dek) VALUES (?,?,?)",
            (vault_id, kek_enc_dek,
             rec_salt + recovery_enc_dek),   # prepend salt so we can re-derive
        )

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


def unlock_with_recovery_key(recovery_display: str) -> Optional[bytes]:
    """Try to unlock the vault using the emergency recovery key."""
    try:
        recovery_raw = parse_recovery_key(recovery_display)
    except ValueError:
        return None

    with get_connection() as conn:
        ks = conn.execute(
            "SELECT recovery_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        if not ks or not ks["recovery_enc_dek"]:
            return None

        blob = bytes(ks["recovery_enc_dek"])
        rec_salt, enc_dek = blob[:16], blob[16:]

        rec_kek = derive_kek(recovery_raw, rec_salt)
        try:
            dek = unwrap_dek(rec_kek, enc_dek)
        except (InvalidTag, Exception):
            return None

    return dek


def change_master_password(old_dek: bytes, new_password: str) -> bool:
    """Re-wrap DEK with a new master password KEK."""
    new_kek_salt = generate_salt()
    new_kek = derive_kek(new_password, new_kek_salt)
    new_kek_enc_dek = wrap_dek(new_kek, old_dek)
    new_verification = make_verification(new_kek)

    with get_connection() as conn:
        vault = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not vault:
            return False
        vid = vault["id"]
        conn.execute(
            "UPDATE user_auth SET kek_salt=?, verification=? WHERE vault_id=?",
            (new_kek_salt, new_verification, vid),
        )
        conn.execute(
            "UPDATE key_store SET kek_enc_dek=? WHERE vault_id=?",
            (new_kek_enc_dek, vid),
        )
    return True


# ── Secret questions ─────────────────────────────────────────────

def save_secret_questions(dek: bytes, questions_answers: list[tuple[str, str]]) -> bool:
    """
    Hash answers and store questions. Also create a questions-based DEK envelope.
    questions_answers: list of (question, answer) pairs (min 3).
    """
    combined = "|".join(a.strip().lower() for _, a in questions_answers).encode()
    q_salt = generate_salt()
    q_kek = derive_kek(combined, q_salt)
    q_enc_dek = wrap_dek(q_kek, dek)

    with get_connection() as conn:
        vault = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not vault:
            return False
        vid = vault["id"]

        conn.execute("DELETE FROM secret_question WHERE vault_id=?", (vid,))
        for q, a in questions_answers:
            a_salt = generate_salt()
            a_hash = derive_kek(a.strip().lower(), a_salt)   # reuse Argon2id
            conn.execute(
                "INSERT INTO secret_question (vault_id, question, answer_hash, salt) VALUES (?,?,?,?)",
                (vid, q, a_hash, a_salt),
            )
        conn.execute(
            "UPDATE key_store SET questions_enc_dek=? WHERE vault_id=?",
            (q_salt + q_enc_dek, vid),
        )
    return True


def get_secret_questions() -> list[str]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT question FROM secret_question ORDER BY id"
        ).fetchall()
    return [r["question"] for r in rows]


def unlock_with_secret_questions(answers: list[str]) -> Optional[bytes]:
    """Try to unlock vault using secret question answers."""
    combined = "|".join(a.strip().lower() for a in answers).encode()

    with get_connection() as conn:
        ks = conn.execute(
            "SELECT questions_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        if not ks or not ks["questions_enc_dek"]:
            return None

        blob = bytes(ks["questions_enc_dek"])
        q_salt, enc_dek = blob[:16], blob[16:]
        q_kek = derive_kek(combined, q_salt)
        try:
            return unwrap_dek(q_kek, enc_dek)
        except (InvalidTag, Exception):
            return None


def has_secret_questions() -> bool:
    with get_connection() as conn:
        ks = conn.execute(
            "SELECT questions_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        return bool(ks and ks["questions_enc_dek"])


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
