"""
Test Suite — Schema / DB (TC-DB-001 → TC-DB-004)
Kiểm thử CSDL in-memory: serialize, deserialize, cascade, lifecycle.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.schema import init_db, close_db, get_connection, vault_exists, dump_db_to_bytes, load_db_from_bytes


@pytest.fixture(autouse=True)
def fresh_db():
    """Mỗi test bắt đầu với DB mới."""
    close_db()
    init_db()
    yield
    close_db()


class TestSerializeDeserialize:
    """TC-DB-001: Serialize → Deserialize roundtrip"""

    def test_roundtrip(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO vault (name) VALUES ('Test')")
            conn.execute(
                "INSERT INTO user_auth (vault_id, kek_salt, argon2_params, verification)"
                " VALUES (1, X'AA', '{}', X'BB')"
            )

        data = dump_db_to_bytes()
        assert len(data) > 0

        close_db()
        init_db()
        load_db_from_bytes(data)

        with get_connection() as conn:
            row = conn.execute("SELECT name FROM vault WHERE id=1").fetchone()
            assert row["name"] == "Test"


class TestCascadeDelete:
    """TC-DB-002: Foreign key cascade delete"""

    def test_delete_vault_cascades(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO vault (name) VALUES ('V1')")
            conn.execute(
                "INSERT INTO user_auth (vault_id, kek_salt, argon2_params, verification)"
                " VALUES (1, X'AA', '{}', X'BB')"
            )
            conn.execute(
                "INSERT INTO key_store (vault_id, kek_enc_rsa_priv, rsa_enc_dek)"
                " VALUES (1, X'CC', X'DD')"
            )
            conn.execute(
                "INSERT INTO vault_entry (vault_id, title, enc_password)"
                " VALUES (1, 'Entry1', X'EE')"
            )

        with get_connection() as conn:
            conn.execute("DELETE FROM vault WHERE id=1")

        with get_connection() as conn:
            assert conn.execute("SELECT COUNT(*) FROM user_auth WHERE vault_id=1").fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM key_store WHERE vault_id=1").fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM vault_entry WHERE vault_id=1").fetchone()[0] == 0


class TestVaultExists:
    """TC-DB-003: vault_exists kiểm tra đúng trạng thái"""

    def test_no_vault(self):
        assert vault_exists() is False

    def test_has_vault(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO vault (name) VALUES ('V1')")
        assert vault_exists() is True


class TestCloseDB:
    """TC-DB-004: close_db hủy toàn bộ dữ liệu"""

    def test_close_destroys_data(self):
        with get_connection() as conn:
            conn.execute("INSERT INTO vault (name) VALUES ('V1')")
        assert vault_exists() is True

        close_db()
        init_db()
        assert vault_exists() is False
