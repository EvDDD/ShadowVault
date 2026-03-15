"""
Cryptographic core for ShadowVault.

Key generation (CSPRNG, primes, RSA): core.keygen  [self-implemented]
Symmetric encryption (AES-256-GCM):   cryptography  [library — safe from backdoor]
KDF (PBKDF2-SHA256):                  hashlib       [stdlib]

Architecture:
  Master Password ──PBKDF2──► KEK ──AES-GCM──► [RSA Private Key]
  RSA Private Key  ──RSA decrypt──►  DEK
  RSA Public Key   ──RSA encrypt──►  [encrypted DEK]  (stored in key_store)
  DEK ──AES-GCM──► Vault entries
"""
import os
import json
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from core.keygen import CSPRNG, RSAKeyPair, generate_rsa, get_rng

# ── Parameters ───────────────────────────────────────────────────
PBKDF2_ITERATIONS   = 600_000
PBKDF2_SALT_LEN     = 32
PBKDF2_HASH_LEN     = 32

GCM_NONCE_LEN       = 12
DEK_LEN             = 32    # 256-bit AES key
RSA_BITS            = 2048

SALT_LEN            = PBKDF2_SALT_LEN

_VERIFICATION_PLAINTEXT = b"SHADOWVAULT_OK_v2"


# ── Helpers: random bytes ─────────────────────────────────────────

def generate_salt(length: int = SALT_LEN) -> bytes:
    """Generate random salt using our custom CSPRNG."""
    return get_rng().random_bytes(length)


def generate_dek() -> bytes:
    """Generate a fresh 256-bit Data Encryption Key using custom CSPRNG."""
    return get_rng().random_bytes(DEK_LEN)


def generate_recovery_key() -> tuple[bytes, str]:
    """
    Generate a 128-bit recovery key using custom CSPRNG.
    Returns (raw_bytes, user-friendly display string).
    """
    raw     = get_rng().random_bytes(16)
    hex_str = raw.hex().upper()
    display = "-".join(hex_str[i:i+8] for i in range(0, 32, 8))
    return raw, display


def parse_recovery_key(display: str) -> bytes:
    clean = display.replace("-", "").replace(" ", "").upper()
    if len(clean) != 32:
        raise ValueError("Recovery key must be 32 hex characters (128 bits).")
    return bytes.fromhex(clean)


# ── RSA key generation ────────────────────────────────────────────

def generate_rsa_keypair() -> RSAKeyPair:
    """Generate an RSA-2048 key pair using the self-implemented keygen module."""
    return generate_rsa(bits=RSA_BITS, rng=get_rng())


def rsa_encrypt_dek(keypair: RSAKeyPair, dek: bytes) -> bytes:
    """Encrypt DEK with RSA public key → ciphertext bytes."""
    return keypair.encrypt_bytes(dek)


def rsa_decrypt_dek(keypair: RSAKeyPair, ciphertext: bytes) -> bytes:
    """Decrypt DEK from RSA ciphertext using private key."""
    return keypair.decrypt_bytes(ciphertext, msg_len=DEK_LEN)


# ── KDF (PBKDF2 — stdlib hashlib) ────────────────────────────────

def derive_kek(password: str | bytes, salt: bytes) -> bytes:
    """Derive KEK from master password using PBKDF2-SHA256."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256", password, salt, PBKDF2_ITERATIONS, dklen=PBKDF2_HASH_LEN
    )


def argon2_params_to_json() -> str:
    return json.dumps({"kdf": "pbkdf2-sha256", "iterations": PBKDF2_ITERATIONS})


# ── AES-256-GCM (cryptography library) ───────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Output = nonce(12) || ciphertext+tag."""
    nonce = get_rng().random_bytes(GCM_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM blob. Raises InvalidTag on wrong key."""
    nonce, ct = data[:GCM_NONCE_LEN], data[GCM_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ── KEK wraps RSA private key ─────────────────────────────────────

def wrap_rsa_private(kek: bytes, keypair: RSAKeyPair) -> bytes:
    """Encrypt RSA private key bytes with AES-GCM(KEK)."""
    return aes_encrypt(kek, keypair.private_to_bytes())


def unwrap_rsa_private(kek: bytes, blob: bytes) -> RSAKeyPair:
    """Decrypt RSA private key blob → RSAKeyPair. Raises InvalidTag on wrong KEK."""
    return RSAKeyPair.private_from_bytes(aes_decrypt(kek, blob))


# ── Vault field encryption ────────────────────────────────────────

def encrypt_field(dek: bytes, plaintext: str) -> bytes:
    return aes_encrypt(dek, plaintext.encode("utf-8"))


def decrypt_field(dek: bytes, ciphertext: bytes) -> str:
    return aes_decrypt(dek, ciphertext).decode("utf-8")


# ── KEK verification token ────────────────────────────────────────

def make_verification(kek: bytes) -> bytes:
    return aes_encrypt(kek, _VERIFICATION_PLAINTEXT)


def verify_kek(kek: bytes, verification: bytes) -> bool:
    try:
        return aes_decrypt(kek, verification) == _VERIFICATION_PLAINTEXT
    except Exception:
        return False


# ── Symmetric DEK wrapping (used by recovery paths) ──────────────

def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    """Wrap DEK with a symmetric KEK (used for recovery key / secret question envelopes)."""
    return aes_encrypt(kek, dek)


def unwrap_dek(kek: bytes, envelope: bytes) -> bytes:
    """Unwrap DEK from symmetric KEK envelope."""
    return aes_decrypt(kek, envelope)
