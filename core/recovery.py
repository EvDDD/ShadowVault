"""
Recovery module for ShadowVault.

Handles all master password recovery flows:
  1. Emergency Recovery Key  — 128-bit random key generated at vault creation
  2. Secret Questions        — user-defined Q&A, answers hashed with Argon2id/PBKDF2
  3. Change Master Password  — re-wrap DEK under a new KEK without touching vault data

This module intentionally has NO knowledge of vault entries or CRUD.
It only deals with the Key Store layer (KEK/DEK envelopes).
"""
from __future__ import annotations
from typing import Optional

from cryptography.exceptions import InvalidTag

from db.schema import get_connection
from core.crypto import (
    derive_kek, make_verification, verify_kek,
    wrap_dek, unwrap_dek,
    generate_salt, generate_recovery_key, parse_recovery_key,
    argon2_params_to_json,
    SALT_LEN,
)


# ── Recovery Key ─────────────────────────────────────────────────

def store_recovery_key(vault_id: int, dek: bytes) -> str:
    """
    Generate a new Emergency Recovery Key, wrap the DEK with it,
    and persist to key_store. Returns the display string for the user.
    """
    recovery_raw, recovery_display = generate_recovery_key()
    rec_salt = generate_salt()
    rec_kek  = derive_kek(recovery_raw, rec_salt)
    blob     = rec_salt + wrap_dek(rec_kek, dek)   # [salt(32) | enc_dek]

    with get_connection() as conn:
        conn.execute(
            "UPDATE key_store SET recovery_enc_dek=? WHERE vault_id=?",
            (blob, vault_id),
        )
    return recovery_display


def unlock_with_recovery_key(recovery_display: str) -> Optional[bytes]:
    """
    Attempt to unwrap the DEK using an Emergency Recovery Key.
    Returns the DEK on success, None on failure.
    """
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

    blob     = bytes(ks["recovery_enc_dek"])
    rec_salt = blob[:SALT_LEN]
    enc_dek  = blob[SALT_LEN:]

    try:
        return unwrap_dek(derive_kek(recovery_raw, rec_salt), enc_dek)
    except (InvalidTag, Exception):
        return None


def has_recovery_key() -> bool:
    """Return True if a recovery key envelope exists in key_store."""
    with get_connection() as conn:
        ks = conn.execute(
            "SELECT recovery_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
    return bool(ks and ks["recovery_enc_dek"])


# ── Secret Questions ─────────────────────────────────────────────

def save_secret_questions(dek: bytes, questions_answers: list[tuple[str, str]]) -> bool:
    """
    Hash each answer individually (Argon2id/PBKDF2 + salt) for storage,
    and create a combined-answer KEK envelope wrapping the DEK.

    questions_answers: list of (question_text, answer_text), minimum 3 pairs.
    Returns True on success.
    """
    if len(questions_answers) < 3:
        raise ValueError("At least 3 secret questions are required.")

    # Combined key: concatenate all answers (lowercased, stripped) with separator
    combined = "|".join(a.strip().lower() for _, a in questions_answers).encode("utf-8")
    q_salt   = generate_salt()
    q_kek    = derive_kek(combined, q_salt)
    blob     = q_salt + wrap_dek(q_kek, dek)   # [salt(32) | enc_dek]

    with get_connection() as conn:
        vault = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not vault:
            return False
        vid = vault["id"]

        # Replace existing questions
        conn.execute("DELETE FROM secret_question WHERE vault_id=?", (vid,))
        for q_text, a_text in questions_answers:
            a_salt = generate_salt()
            # Store individual answer hashes for optional per-answer verification
            a_hash = derive_kek(a_text.strip().lower().encode("utf-8"), a_salt)
            conn.execute(
                """INSERT INTO secret_question
                   (vault_id, question, answer_hash, salt)
                   VALUES (?, ?, ?, ?)""",
                (vid, q_text, a_hash, a_salt),
            )

        conn.execute(
            "UPDATE key_store SET questions_enc_dek=? WHERE vault_id=?",
            (blob, vid),
        )
    return True


def get_secret_questions() -> list[str]:
    """Return the list of stored question texts, in insertion order."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT question FROM secret_question ORDER BY id"
        ).fetchall()
    return [r["question"] for r in rows]


def unlock_with_secret_questions(answers: list[str]) -> Optional[bytes]:
    """
    Attempt to unwrap the DEK using secret question answers.
    All answers must be provided in the same order as stored.
    Returns the DEK on success, None on failure.
    """
    combined = "|".join(a.strip().lower() for a in answers).encode("utf-8")

    with get_connection() as conn:
        ks = conn.execute(
            "SELECT questions_enc_dek FROM key_store LIMIT 1"
        ).fetchone()

    if not ks or not ks["questions_enc_dek"]:
        return None

    blob    = bytes(ks["questions_enc_dek"])
    q_salt  = blob[:SALT_LEN]
    enc_dek = blob[SALT_LEN:]

    try:
        return unwrap_dek(derive_kek(combined, q_salt), enc_dek)
    except (InvalidTag, Exception):
        return None


def has_secret_questions() -> bool:
    """Return True if a secret-questions envelope exists."""
    with get_connection() as conn:
        ks = conn.execute(
            "SELECT questions_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
    return bool(ks and ks["questions_enc_dek"])


# ── Change / Reset Master Password ───────────────────────────────

def change_master_password(dek: bytes, new_password: str) -> bool:
    """
    Re-wrap the DEK under a new master-password KEK.
    The DEK itself never changes, so all vault entries remain intact.
    Returns True on success.
    """
    new_salt         = generate_salt()
    new_kek          = derive_kek(new_password, new_salt)
    new_kek_enc_dek  = wrap_dek(new_kek, dek)
    new_verification = make_verification(new_kek)

    with get_connection() as conn:
        vault = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not vault:
            return False
        vid = vault["id"]
        conn.execute(
            "UPDATE user_auth SET kek_salt=?, argon2_params=?, verification=? WHERE vault_id=?",
            (new_salt, argon2_params_to_json(), new_verification, vid),
        )
        conn.execute(
            "UPDATE key_store SET kek_enc_dek=? WHERE vault_id=?",
            (new_kek_enc_dek, vid),
        )
    return True
