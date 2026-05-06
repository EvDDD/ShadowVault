"""
Test Suite — Crypto (TC-CR-001 → TC-CR-008)
Kiểm thử các hàm mã hóa cốt lõi: PBKDF2, AES-GCM, RSA wrap/unwrap, verify.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.exceptions import InvalidTag
from core.crypto import (
    derive_kek, generate_salt, generate_dek,
    aes_encrypt, aes_decrypt,
    encrypt_field, decrypt_field,
    wrap_rsa_private, unwrap_rsa_private,
    rsa_encrypt_dek, rsa_decrypt_dek,
    make_verification, verify_kek,
    generate_rsa_keypair,
    wrap_dek, unwrap_dek,
)


class TestDeriveKEK:
    """TC-CR-001, TC-CR-002: derive_kek"""

    def test_deterministic(self):
        """TC-CR-001: cùng password + salt → cùng KEK"""
        salt = generate_salt()
        kek1 = derive_kek("MyStr0ng!Pass", salt)
        kek2 = derive_kek("MyStr0ng!Pass", salt)
        assert len(kek1) == 32
        assert kek1 == kek2

    def test_different_password(self):
        """TC-CR-002: khác password → khác KEK"""
        salt = generate_salt()
        kek1 = derive_kek("Pass1", salt)
        kek2 = derive_kek("Pass2", salt)
        assert kek1 != kek2

    def test_different_salt(self):
        kek1 = derive_kek("SamePass", generate_salt())
        kek2 = derive_kek("SamePass", generate_salt())
        assert kek1 != kek2


class TestAESGCM:
    """TC-CR-003 → TC-CR-005: AES-256-GCM"""

    def setup_method(self):
        self.key = generate_dek()

    def test_encrypt_decrypt_roundtrip(self):
        """TC-CR-003: encrypt → decrypt roundtrip"""
        plaintext = b"Hello ShadowVault"
        blob = aes_encrypt(self.key, plaintext)
        result = aes_decrypt(self.key, blob)
        assert result == plaintext

    def test_blob_structure(self):
        """TC-CR-003: blob = nonce(12) + ciphertext + tag(16)"""
        plaintext = b"test"
        blob = aes_encrypt(self.key, plaintext)
        assert len(blob) == 12 + len(plaintext) + 16

    def test_wrong_key_raises(self):
        """TC-CR-004: sai key → InvalidTag"""
        blob = aes_encrypt(self.key, b"secret")
        wrong_key = generate_dek()
        with pytest.raises(InvalidTag):
            aes_decrypt(wrong_key, blob)

    def test_tampered_data_raises(self):
        """TC-CR-005: dữ liệu bị sửa → InvalidTag"""
        blob = aes_encrypt(self.key, b"secret")
        tampered = bytearray(blob)
        tampered[20] ^= 0xFF  # flip a byte
        with pytest.raises(InvalidTag):
            aes_decrypt(self.key, bytes(tampered))

    def test_empty_plaintext(self):
        blob = aes_encrypt(self.key, b"")
        assert aes_decrypt(self.key, blob) == b""


class TestRSAWrap:
    """TC-CR-006, TC-CR-007: RSA wrap/unwrap"""

    def setup_method(self):
        self.kek = generate_dek()
        self.keypair = generate_rsa_keypair()

    def test_wrap_unwrap_rsa_private(self):
        """TC-CR-006: wrap → unwrap RSA private key"""
        blob = wrap_rsa_private(self.kek, self.keypair)
        kp2 = unwrap_rsa_private(self.kek, blob)
        assert kp2.n.to_int() == self.keypair.n.to_int()
        assert kp2.d.to_int() == self.keypair.d.to_int()

    def test_wrap_wrong_kek(self):
        """TC-CR-006: sai KEK → InvalidTag"""
        blob = wrap_rsa_private(self.kek, self.keypair)
        wrong_kek = generate_dek()
        with pytest.raises(InvalidTag):
            unwrap_rsa_private(wrong_kek, blob)

    def test_rsa_encrypt_decrypt_dek(self):
        """TC-CR-007: RSA encrypt/decrypt DEK roundtrip"""
        dek = generate_dek()
        enc = rsa_encrypt_dek(self.keypair, dek)
        dec = rsa_decrypt_dek(self.keypair, enc)
        assert dec == dek


class TestVerification:
    """TC-CR-008: verify_kek đúng/sai"""

    def test_verify_correct(self):
        kek = generate_dek()
        token = make_verification(kek)
        assert verify_kek(kek, token) is True

    def test_verify_wrong_kek(self):
        kek = generate_dek()
        token = make_verification(kek)
        wrong_kek = generate_dek()
        assert verify_kek(wrong_kek, token) is False


class TestFieldEncryption:
    """Encrypt/decrypt field roundtrip"""

    def test_field_roundtrip(self):
        dek = generate_dek()
        text = "my_secret_password"
        cipher = encrypt_field(dek, text)
        assert decrypt_field(dek, cipher) == text

    def test_field_wrong_dek(self):
        dek1 = generate_dek()
        dek2 = generate_dek()
        cipher = encrypt_field(dek1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_field(dek2, cipher)
