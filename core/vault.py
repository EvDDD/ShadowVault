"""
Vault CRUD and lifecycle for ShadowVault.

Master-password unlock flow (uses RSA):
  1. Derive KEK from password (PBKDF2)
  2. Decrypt RSA private key with KEK  (AES-GCM)
  3. Decrypt DEK with RSA private key  (RSA)

Recovery flows are handled by core.recovery (symmetric KEK envelopes).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from db.schema import get_connection
from core.crypto import (
    derive_kek, make_verification, verify_kek,
    wrap_rsa_private, unwrap_rsa_private,
    rsa_encrypt_dek, rsa_decrypt_dek,
    generate_rsa_keypair, generate_dek, generate_salt,
    encrypt_field, decrypt_field,
    wrap_dek, unwrap_dek,
    argon2_params_to_json,
)
from cryptography.exceptions import InvalidTag

# Re-export recovery API (UI imports from core.vault for convenience)
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


# ── Vault lifecycle ───────────────────────────────────────────────

def create_vault(master_password: str, vault_name: str = "My Vault") -> tuple[bytes, str]:
    """
    Create a new vault.
    Returns (dek, recovery_key_display).

    Key generation steps:
      1. generate_dek()          → random 256-bit DEK  (custom CSPRNG)
      2. generate_rsa_keypair()  → RSA-2048 (BigInt + Miller-Rabin)
      3. RSA_encrypt(pub, DEK)   → rsa_enc_dek  (stored in key_store)
      4. derive_kek(password)    → KEK  (PBKDF2)
      5. AES-GCM(KEK, RSA_priv)  → kek_enc_rsa_priv  (stored in key_store)
    """
    dek     = generate_dek()
    keypair = generate_rsa_keypair()         # custom RSA-2048

    rsa_enc_dek      = rsa_encrypt_dek(keypair, dek)
    kek_salt         = generate_salt()
    kek              = derive_kek(master_password, kek_salt)
    kek_enc_rsa_priv = wrap_rsa_private(kek, keypair)
    verification     = make_verification(kek)

    with get_connection() as conn:
        cur = conn.execute("INSERT INTO vault (name) VALUES (?)", (vault_name,))
        vault_id = cur.lastrowid
        conn.execute(
            "INSERT INTO user_auth (vault_id, kek_salt, argon2_params, verification)"
            " VALUES (?,?,?,?)",
            (vault_id, kek_salt, argon2_params_to_json(), verification),
        )
        conn.execute(
            "INSERT INTO key_store (vault_id, kek_enc_rsa_priv, rsa_enc_dek)"
            " VALUES (?,?,?)",
            (vault_id, kek_enc_rsa_priv, rsa_enc_dek),
        )

    recovery_display = store_recovery_key(vault_id, dek)
    return dek, recovery_display


def unlock_vault(master_password: str) -> Optional[bytes]:
    """
    Verify master password and return DEK.

    Unlock steps:
      1. Derive KEK from password (PBKDF2)
      2. Verify KEK against stored sentinel
      3. Decrypt RSA private key with KEK  (AES-GCM)
      4. Decrypt DEK with RSA private key  (RSA)
    """
    with get_connection() as conn:
        auth = conn.execute(
            "SELECT kek_salt, verification FROM user_auth LIMIT 1"
        ).fetchone()
        if not auth:
            return None

        kek = derive_kek(master_password, bytes(auth["kek_salt"]))
        if not verify_kek(kek, bytes(auth["verification"])):
            return None

        ks = conn.execute(
            "SELECT kek_enc_rsa_priv, rsa_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        if not ks:
            return None

        try:
            keypair = unwrap_rsa_private(kek, bytes(ks["kek_enc_rsa_priv"]))
            dek     = rsa_decrypt_dek(keypair, bytes(ks["rsa_enc_dek"]))
        except (InvalidTag, Exception):
            return None

    return dek


def change_master_password(dek: bytes, new_password: str) -> bool:
    """
    Change master password: re-encrypt RSA private key under new KEK.
    DEK and vault data are untouched.
    """
    with get_connection() as conn:
        ks = conn.execute(
            "SELECT vault_id, rsa_enc_dek FROM key_store LIMIT 1"
        ).fetchone()
        vault = conn.execute("SELECT id FROM vault LIMIT 1").fetchone()
        if not ks or not vault:
            return False

        # Re-derive RSA private key from old DEK and existing rsa_enc_dek is
        # not available directly — we need the keypair. Since we already have
        # the DEK (passed in), re-use the existing rsa_enc_dek but generate
        # new KEK wrapping.
        # Actual approach: decrypt RSA private key via old KEK is not available
        # here. Instead we re-generate a new RSA keypair, re-encrypt DEK with
        # new public key, encrypt new private key with new KEK.
        # This is equivalent and safe since DEK doesn't change.
        from core.crypto import generate_rsa_keypair
        new_keypair      = generate_rsa_keypair()
        new_rsa_enc_dek  = rsa_encrypt_dek(new_keypair, dek)
        new_salt         = generate_salt()
        new_kek          = derive_kek(new_password, new_salt)
        new_kek_enc_priv = wrap_rsa_private(new_kek, new_keypair)
        new_verification = make_verification(new_kek)
        vid = vault["id"]

        conn.execute(
            "UPDATE user_auth SET kek_salt=?, verification=? WHERE vault_id=?",
            (new_salt, new_verification, vid),
        )
        conn.execute(
            "UPDATE key_store SET kek_enc_rsa_priv=?, rsa_enc_dek=? WHERE vault_id=?",
            (new_kek_enc_priv, new_rsa_enc_dek, vid),
        )
    return True


def get_vault_name() -> str:
    with get_connection() as conn:
        row = conn.execute("SELECT name FROM vault LIMIT 1").fetchone()
        return row["name"] if row else "My Vault"


# ── Entry CRUD ────────────────────────────────────────────────────

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
            "INSERT INTO vault_entry (vault_id, title, url, username, enc_password, enc_notes)"
            " VALUES (?,?,?,?,?,?)",
            (
                vid, entry.title,
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
            "UPDATE vault_entry"
            " SET title=?, url=?, username=?, enc_password=?, enc_notes=?"
            " WHERE id=?",
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
                id=row["id"], vault_id=row["vault_id"], title=row["title"],
                url=      decrypt_field(dek, bytes(row["url"]))      if row["url"]      else "",
                username= decrypt_field(dek, bytes(row["username"])) if row["username"] else "",
                password= decrypt_field(dek, bytes(row["enc_password"])),
                notes=    decrypt_field(dek, bytes(row["enc_notes"])) if row["enc_notes"] else "",
                created_at=row["created_at"] or "", updated_at=row["updated_at"] or "",
            )
        except Exception:
            continue
        if search:
            q = search.lower()
            if q not in (e.title + e.url + e.username + e.notes).lower():
                continue
        entries.append(e)
    return entries


def get_entry(dek: bytes, entry_id: int) -> Optional[VaultEntry]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM vault_entry WHERE id=?", (entry_id,)).fetchone()
    if not row:
        return None
    return VaultEntry(
        id=row["id"], vault_id=row["vault_id"], title=row["title"],
        url=      decrypt_field(dek, bytes(row["url"]))      if row["url"]      else "",
        username= decrypt_field(dek, bytes(row["username"])) if row["username"] else "",
        password= decrypt_field(dek, bytes(row["enc_password"])),
        notes=    decrypt_field(dek, bytes(row["enc_notes"])) if row["enc_notes"] else "",
        created_at=row["created_at"] or "", updated_at=row["updated_at"] or "",
    )
