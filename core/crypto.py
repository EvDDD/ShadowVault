"""
Cryptographic core for ShadowVault.

Architecture:
  Master Password ──PBKDF2-SHA256──► KEK ──AES-256-GCM──► [encrypted DEK stored in DB]
  DEK ──AES-256-GCM──► Vault Data

Note: argon2-cffi is preferred but falls back to PBKDF2-SHA256 (600k iterations)
      if not available in the current environment.
"""
import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    _USE_ARGON2 = True
except ImportError:
    _USE_ARGON2 = False

# ── Parameters ───────────────────────────────────────────────────
PBKDF2_ITERATIONS   = 600_000
PBKDF2_SALT_LEN     = 32
PBKDF2_HASH_LEN     = 32

ARGON2_TIME_COST    = 3
ARGON2_MEMORY_COST  = 65536
ARGON2_PARALLELISM  = 2
ARGON2_HASH_LEN     = 32
ARGON2_SALT_LEN     = 32

GCM_NONCE_LEN = 12
DEK_LEN       = 32

SALT_LEN = ARGON2_SALT_LEN if _USE_ARGON2 else PBKDF2_SALT_LEN

_VERIFICATION_PLAINTEXT = b"SHADOWVAULT_OK_v1"


def generate_salt(length: int = SALT_LEN) -> bytes:
    return os.urandom(length)


def generate_dek() -> bytes:
    return os.urandom(DEK_LEN)


def generate_recovery_key() -> tuple[bytes, str]:
    raw = os.urandom(16)
    hex_str = raw.hex().upper()
    display = "-".join(hex_str[i:i+8] for i in range(0, 32, 8))
    return raw, display


def parse_recovery_key(display: str) -> bytes:
    clean = display.replace("-", "").replace(" ", "").upper()
    if len(clean) != 32:
        raise ValueError("Recovery key must be 32 hex characters.")
    return bytes.fromhex(clean)


def derive_kek(password: str | bytes, salt: bytes) -> bytes:
    """Derive KEK from password using Argon2id (or PBKDF2 fallback)."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if _USE_ARGON2:
        return hash_secret_raw(
            secret=password, salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Argon2Type.ID,
        )
    else:
        return hashlib.pbkdf2_hmac(
            "sha256", password, salt, PBKDF2_ITERATIONS, dklen=PBKDF2_HASH_LEN
        )


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(GCM_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ct = data[:GCM_NONCE_LEN], data[GCM_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)


def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    return aes_encrypt(kek, dek)


def unwrap_dek(kek: bytes, envelope: bytes) -> bytes:
    return aes_decrypt(kek, envelope)


def encrypt_field(dek: bytes, plaintext: str) -> bytes:
    return aes_encrypt(dek, plaintext.encode("utf-8"))


def decrypt_field(dek: bytes, ciphertext: bytes) -> str:
    return aes_decrypt(dek, ciphertext).decode("utf-8")


def make_verification(kek: bytes) -> bytes:
    return aes_encrypt(kek, _VERIFICATION_PLAINTEXT)


def verify_kek(kek: bytes, verification: bytes) -> bool:
    try:
        return aes_decrypt(kek, verification) == _VERIFICATION_PLAINTEXT
    except Exception:
        return False


def get_kdf_params() -> dict:
    if _USE_ARGON2:
        return {"kdf": "argon2id", "time_cost": ARGON2_TIME_COST,
                "memory_cost": ARGON2_MEMORY_COST, "parallelism": ARGON2_PARALLELISM}
    return {"kdf": "pbkdf2-sha256", "iterations": PBKDF2_ITERATIONS}


def argon2_params_to_json() -> str:
    return json.dumps(get_kdf_params())
