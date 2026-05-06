"""
Test Suite — Integration Tests (TC-IT-001 → TC-IT-018)
Kiểm thử luồng dữ liệu xuyên suốt giữa các module.
"""
import gzip
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image
from cryptography.exceptions import InvalidTag
from db.schema import init_db, close_db, get_connection, dump_db_to_bytes, load_db_from_bytes
from core.crypto import (
    derive_kek, generate_salt, generate_dek, generate_rsa_keypair,
    wrap_rsa_private, unwrap_rsa_private, rsa_encrypt_dek, rsa_decrypt_dek,
    encrypt_field, decrypt_field,
)
from core.keygen import CSPRNG, generate_rsa, miller_rabin
from core.vault import (
    create_vault, unlock_vault, add_entry, get_all_entries,
    VaultEntry,
)
import core.vault as _vault_mod
from core.recovery import (
    unlock_with_recovery_key, save_secret_questions,
    unlock_with_secret_questions,
)
from core.password_gen import generate_password, check_all_health
from core.steganography import hide, unhide


@pytest.fixture(autouse=True)
def fresh_db():
    close_db()
    init_db()
    yield
    close_db()


# ── 3.1 Luồng mã hóa đa tầng ───────────────────────────────────

class TestEncryptionChain:
    """TC-IT-001: Password → KEK → RSA → DEK → Entry"""

    def test_full_chain(self):
        salt = generate_salt()
        dek = generate_dek()
        kek = derive_kek("TestPassword!", salt)
        keypair = generate_rsa_keypair()

        blob = wrap_rsa_private(kek, keypair)
        keypair2 = unwrap_rsa_private(kek, blob)
        assert keypair2.d.to_int() == keypair.d.to_int()

        enc_dek = rsa_encrypt_dek(keypair2, dek)
        dek2 = rsa_decrypt_dek(keypair2, enc_dek)
        assert dek2 == dek

        cipher = encrypt_field(dek2, "secret")
        assert decrypt_field(dek2, cipher) == "secret"


class TestCreateUnlockEntries:
    """TC-IT-002: Tạo vault → Unlock → Truy xuất entry"""

    def test_full_flow(self):
        dek, _, vid = create_vault("Pass123!")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Google", password="gpass"), vid)
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Facebook", password="fpass"), vid)

        dek2 = unlock_vault("Pass123!", vid)
        assert dek2 == dek

        entries = get_all_entries(dek2, vault_id=vid)
        assert len(entries) == 2
        titles = {e.title for e in entries}
        assert "Google" in titles
        assert "Facebook" in titles


class TestChangePasswordIntegration:
    """TC-IT-003: Đổi password → Unlock → Entries còn nguyên"""

    def test_change_and_verify(self):
        dek, _, vid = create_vault("OldPass")
        for i in range(3):
            add_entry(dek, VaultEntry(id=None, vault_id=vid,
                                      title=f"Entry{i}", password=f"p{i}"), vid)

        _vault_mod.change_master_password(dek, "NewPass!", vid)
        dek2 = unlock_vault("NewPass!", vid)
        assert dek2 == dek

        entries = get_all_entries(dek2, vault_id=vid)
        assert len(entries) == 3


class TestWrongKEKFails:
    """TC-IT-011: Sai KEK → Không thể unwrap RSA"""

    def test_wrong_kek_raises(self):
        salt = generate_salt()
        kek = derive_kek("Pass1", salt)
        keypair = generate_rsa_keypair()
        blob = wrap_rsa_private(kek, keypair)

        wrong_kek = derive_kek("Pass2", salt)
        with pytest.raises(InvalidTag):
            unwrap_rsa_private(wrong_kek, blob)


class TestWrongDEKFails:
    """TC-IT-012: Encrypt field → Decrypt với DEK khác → Fail"""

    def test_cross_dek(self):
        dek1 = generate_dek()
        dek2 = generate_dek()
        cipher = encrypt_field(dek1, "password123")
        with pytest.raises(InvalidTag):
            decrypt_field(dek2, cipher)


class TestBigIntRSACryptoEndToEnd:
    """TC-IT-013: BigInt RSA → Crypto wrap end-to-end"""

    def test_e2e(self):
        rng = CSPRNG()
        kp = generate_rsa(512, rng)
        assert miller_rabin(kp.p, rng) is True
        assert miller_rabin(kp.q, rng) is True

        from core.bigint import BigInt
        msg = BigInt(42)
        assert kp.decrypt(kp.encrypt(msg)).to_int() == 42

        kek = generate_dek()
        blob = wrap_rsa_private(kek, kp)
        kp2 = unwrap_rsa_private(kek, blob)
        assert kp2.n.to_int() == kp.n.to_int()


# ── 3.2 Luồng Recovery ──────────────────────────────────────────

class TestRecoveryUnlockEntries:
    """TC-IT-004: Recovery key → Truy xuất entries"""

    def test_recovery_flow(self):
        dek, recovery, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Test", password="pw"), vid)

        dek2 = unlock_with_recovery_key(recovery, vid)
        assert dek2 == dek
        entries = get_all_entries(dek2, vault_id=vid)
        assert len(entries) == 1


class TestRecoveryThenChangePassword:
    """TC-IT-005: Recovery key → Đổi password"""

    def test_recovery_then_change(self):
        dek, recovery, vid = create_vault("OldPass")
        dek2 = unlock_with_recovery_key(recovery, vid)
        assert dek2 == dek
        result = _vault_mod.change_master_password(dek2, "BrandNewPass!", vid)
        assert result is True
        dek3 = unlock_vault("BrandNewPass!", vid)
        assert dek3 is not None, "unlock_vault returned None after change_master_password"
        assert dek3 == dek


class TestSecretQuestionsIntegration:
    """TC-IT-006: Secret questions → DEK → Entries"""

    def test_sq_flow(self):
        dek, _, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Test", password="pw"), vid)
        qa = [("Q1", "A1"), ("Q2", "A2"), ("Q3", "A3")]
        save_secret_questions(dek, qa, vid)

        dek2 = unlock_with_secret_questions(["A1", "A2", "A3"], vid)
        assert dek2 == dek
        assert len(get_all_entries(dek2, vault_id=vid)) == 1


class TestSecretQuestionsThenChangePassword:
    """TC-IT-014: Secret questions → Đổi password → Entries persist"""

    def test_sq_change_password(self):
        dek, _, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="T", password="p"), vid)
        qa = [("Q1", "A1"), ("Q2", "A2"), ("Q3", "A3")]
        save_secret_questions(dek, qa, vid)

        dek2 = unlock_with_secret_questions(["A1", "A2", "A3"], vid)
        result = _vault_mod.change_master_password(dek2, "NewPass!", vid)
        assert result is True
        dek3 = unlock_vault("NewPass!", vid)
        assert dek3 is not None, "unlock_vault returned None after SQ change_master_password"
        assert dek3 == dek
        assert len(get_all_entries(dek3, vault_id=vid)) == 1


class TestRecoveryKeyAfterPasswordChange:
    """TC-IT-015: Đổi password → Recovery key cũ vẫn hoạt động"""

    def test_recovery_persists(self):
        dek, recovery, vid = create_vault("OldPass")
        _vault_mod.change_master_password(dek, "NewPass", vid)
        dek2 = unlock_with_recovery_key(recovery, vid)
        assert dek2 == dek


# ── 3.3 Luồng Steganography ─────────────────────────────────────

class TestStegoDBRoundtrip:
    """TC-IT-007: DB → Serialize → Gzip → Hide → Unhide → Decompress → Load"""

    def test_full_stego_pipeline(self, tmp_path):
        dek, _, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Test", password="pw"), vid)

        data = dump_db_to_bytes()
        compressed = gzip.compress(data)

        cover = str(tmp_path / "cover.png")
        Image.new("RGB", (200, 200), (100, 150, 200)).save(cover, "PNG")
        stego = str(tmp_path / "stego.png")

        hide(cover, compressed, stego)
        payload = unhide(stego)
        decompressed = gzip.decompress(payload)

        close_db()
        load_db_from_bytes(decompressed)
        init_db()

        dek2 = unlock_vault("Pass", vid)
        assert dek2 is not None, "unlock_vault returned None after stego roundtrip"
        entries = get_all_entries(dek2, vault_id=vid)
        assert len(entries) == 1
        assert entries[0].title == "Test"


# ── 3.4 Password Health ─────────────────────────────────────────

class TestHealthCheckIntegration:
    """TC-IT-010: Thêm entries → Health check phát hiện vấn đề"""

    def test_health_issues(self):
        dek, _, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="A", password="123456"), vid)
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="B", password="StrongP@ss99!"), vid)
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="C", password="123456"), vid)

        entries = get_all_entries(dek, vault_id=vid)
        issues = check_all_health(entries)

        weak = [i for i in issues if i.issue_type == "weak"]
        dup = [i for i in issues if i.issue_type == "duplicate"]
        assert len(weak) >= 1  # "123456" is weak
        assert len(dup) >= 2   # A and C duplicate


class TestGeneratedPasswordHealthy:
    """TC-IT-017: Sinh password → Health check PASS"""

    def test_generated_is_strong(self):
        dek, _, vid = create_vault("Pass")
        pw = generate_password(length=20, use_upper=True, use_lower=True,
                               use_digits=True, use_symbols=True)
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Gen", password=pw), vid)
        entries = get_all_entries(dek, vault_id=vid)
        issues = check_all_health(entries)
        dup = [i for i in issues if i.issue_type == "duplicate"]
        assert len(dup) == 0


class TestGzipCompression:
    """TC-IT-018: Gzip compression giảm kích thước DB"""

    def test_compression(self):
        dek, _, vid = create_vault("Pass")
        for i in range(10):
            add_entry(dek, VaultEntry(id=None, vault_id=vid,
                                      title=f"E{i}", password=f"pass{i}"), vid)
        data = dump_db_to_bytes()
        compressed = gzip.compress(data, compresslevel=9)
        assert len(compressed) < len(data)
