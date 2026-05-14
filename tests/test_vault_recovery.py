"""
Test Suite — Vault (TC-VT-001 → TC-VT-010) + Recovery (TC-RC-001 → TC-RC-008)
Kiểm thử quản lý vault, CRUD entries, đổi password, và khôi phục.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.schema import init_db, close_db, get_connection
from core.vault import (
    create_vault, unlock_vault, add_entry, get_entry,
    get_all_entries, update_entry, delete_entry, delete_vault,
    change_master_password, VaultEntry,
)
from core.recovery import (
    unlock_with_recovery_key, save_secret_questions,
    unlock_with_secret_questions, has_secret_questions,
)


@pytest.fixture(autouse=True)
def fresh_db():
    close_db()
    init_db()
    yield
    close_db()


# ── Vault Tests ──────────────────────────────────────────────────

class TestCreateVault:
    """TC-VT-001: Tạo vault thành công"""

    def test_create(self):
        dek, recovery, vid = create_vault("Test@1234", "Test Vault")
        assert len(dek) == 32
        assert "-" in recovery  # format XXXXXXXX-XXXXXXXX-...
        assert vid > 0


class TestUnlockVault:
    """TC-VT-002, TC-VT-003: Unlock vault đúng/sai password"""

    def test_unlock_correct(self):
        """TC-VT-002"""
        dek, _, vid = create_vault("Test@1234")
        dek2 = unlock_vault("Test@1234", vid)
        assert dek2 == dek

    def test_unlock_wrong_password(self):
        """TC-VT-003"""
        _, _, vid = create_vault("Test@1234")
        assert unlock_vault("WrongPassword!", vid) is None


class TestEntries:
    """TC-VT-004 → TC-VT-007: CRUD entries"""

    def setup_method(self):
        close_db()
        init_db()
        self.dek, _, self.vid = create_vault("Pass123!")

    def test_add_and_get(self):
        """TC-VT-004"""
        entry = VaultEntry(id=None, vault_id=self.vid, title="Google",
                           url="google.com", username="user@gmail.com",
                           password="secret123", notes="test")
        eid = add_entry(self.dek, entry, self.vid)
        e = get_entry(self.dek, eid)
        assert e.title == "Google"
        assert e.url == "google.com"
        assert e.password == "secret123"

    def test_update_entry(self):
        """TC-VT-005"""
        entry = VaultEntry(id=None, vault_id=self.vid, title="Test",
                           password="old_pass")
        eid = add_entry(self.dek, entry, self.vid)

        updated = VaultEntry(id=eid, vault_id=self.vid, title="Test",
                             password="new_pass")
        update_entry(self.dek, updated)

        e = get_entry(self.dek, eid)
        assert e.password == "new_pass"

    def test_delete_entry(self):
        """TC-VT-006"""
        entry = VaultEntry(id=None, vault_id=self.vid, title="Del",
                           password="pass")
        eid = add_entry(self.dek, entry, self.vid)
        delete_entry(eid)
        assert get_entry(self.dek, eid) is None

    def test_search_entries(self):
        """TC-VT-007"""
        for t in ["Google", "Facebook", "Gmail"]:
            add_entry(self.dek, VaultEntry(id=None, vault_id=self.vid,
                                           title=t, password="p"), self.vid)
        results = get_all_entries(self.dek, search="goo", vault_id=self.vid)
        assert len(results) == 1
        assert results[0].title == "Google"


class TestChangeMasterPassword:
    """TC-VT-008: Đổi master password"""

    def test_change_password(self):
        dek, _, vid = create_vault("OldPass")
        result = change_master_password(dek, "NewPass!", vid)
        assert result is True
        assert unlock_vault("OldPass", vid) is None
        dek2 = unlock_vault("NewPass!", vid)
        assert dek2 == dek  # DEK không đổi


class TestDeleteVault:
    """TC-VT-009: Xóa vault cascade"""

    def test_cascade(self):
        dek, _, vid = create_vault("Pass")
        for i in range(3):
            add_entry(dek, VaultEntry(id=None, vault_id=vid,
                                      title=f"E{i}", password="p"), vid)
        delete_vault(vid)
        with get_connection() as conn:
            assert conn.execute("SELECT COUNT(*) FROM vault_entry WHERE vault_id=?", (vid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM user_auth WHERE vault_id=?", (vid,)).fetchone()[0] == 0


class TestEncryptedStorage:
    """TC-VT-010: Entry fields được mã hóa trong DB"""

    def test_fields_encrypted(self):
        dek, _, vid = create_vault("Pass")
        add_entry(dek, VaultEntry(id=None, vault_id=vid, title="Test",
                                  password="MySecret"), vid)
        with get_connection() as conn:
            row = conn.execute("SELECT enc_password FROM vault_entry LIMIT 1").fetchone()
            raw = bytes(row["enc_password"])
            assert raw != b"MySecret"
            assert len(raw) > 0


# ── Recovery Tests ───────────────────────────────────────────────

class TestRecoveryKey:
    """TC-RC-001 → TC-RC-003"""

    def test_recovery_key_works(self):
        """TC-RC-001"""
        dek, recovery, vid = create_vault("Pass")
        dek2 = unlock_with_recovery_key(recovery, vid)
        assert dek2 == dek

    def test_wrong_recovery_key(self):
        """TC-RC-002"""
        _, _, vid = create_vault("Pass")
        assert unlock_with_recovery_key("AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD", vid) is None

    def test_invalid_format(self):
        """TC-RC-003"""
        _, _, vid = create_vault("Pass")
        assert unlock_with_recovery_key("invalid-key", vid) is None


class TestSecretQuestions:
    """TC-RC-004 → TC-RC-008"""

    def setup_method(self):
        close_db()
        init_db()
        self.dek, _, self.vid = create_vault("Pass")
        self.qa = [("Thành phố?", "Hanoi"), ("Trường?", "HUST"), ("Pet?", "Dog")]

    def test_save_and_unlock(self):
        """TC-RC-004"""
        assert save_secret_questions(self.dek, self.qa, self.vid) is True
        dek2 = unlock_with_secret_questions(["Hanoi", "HUST", "Dog"], self.vid)
        assert dek2 == self.dek

    def test_wrong_answer(self):
        """TC-RC-005"""
        save_secret_questions(self.dek, self.qa, self.vid)
        assert unlock_with_secret_questions(["Hanoi", "WRONG", "Dog"], self.vid) is None

    def test_case_insensitive(self):
        """TC-RC-006"""
        save_secret_questions(self.dek, self.qa, self.vid)
        dek2 = unlock_with_secret_questions(["hAnOi", "hust", "DOG"], self.vid)
        assert dek2 == self.dek

    def test_less_than_3_raises(self):
        """TC-RC-007"""
        with pytest.raises(ValueError):
            save_secret_questions(self.dek, [("Q1", "A1"), ("Q2", "A2")], self.vid)

    def test_has_secret_questions(self):
        """TC-RC-008"""
        assert has_secret_questions(self.vid) is False
        save_secret_questions(self.dek, self.qa, self.vid)
        assert has_secret_questions(self.vid) is True

    def test_save_more_than_3_questions(self):
        """TC-RC-009: Save and unlock with 5 custom questions"""
        qa5 = [
            ("Thành phố?", "Hanoi"),
            ("Trường?", "HUST"),
            ("Pet?", "Dog"),
            ("Màu yêu thích?", "Blue"),
            ("Món ăn?", "Pho"),
        ]
        assert save_secret_questions(self.dek, qa5, self.vid) is True
        dek2 = unlock_with_secret_questions(
            ["Hanoi", "HUST", "Dog", "Blue", "Pho"], self.vid
        )
        assert dek2 == self.dek

    def test_more_than_3_wrong_answer(self):
        """TC-RC-010: 5 questions, 1 wrong answer → fails"""
        qa5 = [
            ("Thành phố?", "Hanoi"),
            ("Trường?", "HUST"),
            ("Pet?", "Dog"),
            ("Màu yêu thích?", "Blue"),
            ("Món ăn?", "Pho"),
        ]
        save_secret_questions(self.dek, qa5, self.vid)
        assert unlock_with_secret_questions(
            ["Hanoi", "HUST", "Dog", "Blue", "WRONG"], self.vid
        ) is None
