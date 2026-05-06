"""
Test Suite — Password Gen & Health Check (TC-PG-001 → TC-PG-006)
"""
import pytest
import string
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.password_gen import (
    generate_password, check_strength, check_all_health,
    CHARSET_SYMBOLS,
)


class TestGeneratePassword:
    """TC-PG-001 → TC-PG-003"""

    def test_correct_length(self):
        """TC-PG-001: sinh đúng độ dài"""
        pw = generate_password(length=20)
        assert len(pw) == 20

    def test_various_lengths(self):
        for length in [8, 16, 32, 64]:
            assert len(generate_password(length=length)) == length

    def test_contains_all_types(self):
        """TC-PG-002: chứa đủ loại ký tự"""
        pw = generate_password(
            length=20, use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True
        )
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in CHARSET_SYMBOLS for c in pw)

    def test_exclude_ambiguous(self):
        """TC-PG-003: loại ký tự nhầm lẫn"""
        ambiguous = set("lO01I")
        for _ in range(50):
            pw = generate_password(length=30, exclude_ambiguous=True)
            assert not ambiguous.intersection(pw), f"Found ambiguous char in: {pw}"

    def test_only_lowercase(self):
        pw = generate_password(length=20, use_upper=False, use_digits=False, use_symbols=False)
        assert all(c in string.ascii_lowercase for c in pw)

    def test_uniqueness(self):
        passwords = {generate_password(length=20) for _ in range(10)}
        assert len(passwords) == 10  # tất cả đều khác nhau


class TestCheckStrength:
    """TC-PG-004, TC-PG-005"""

    def test_weak_password(self):
        """TC-PG-004: mật khẩu yếu"""
        result = check_strength("123456")
        assert result.score <= 1

    def test_strong_password(self):
        """TC-PG-005: mật khẩu mạnh"""
        result = check_strength("kX9!mN#pQ2@wZ7&vR4")
        assert result.score >= 3

    def test_empty_password(self):
        result = check_strength("a")
        assert result.score <= 1

    def test_result_has_all_fields(self):
        result = check_strength("test123")
        assert hasattr(result, 'score')
        assert hasattr(result, 'label')
        assert hasattr(result, 'entropy')
        assert hasattr(result, 'crack_time')
        assert hasattr(result, 'color')


class TestCheckAllHealth:
    """TC-PG-006: phát hiện mật khẩu trùng lặp và yếu"""

    class FakeEntry:
        def __init__(self, id, title, password):
            self.id = id
            self.title = title
            self.password = password

    def test_detect_duplicates(self):
        entries = [
            self.FakeEntry(1, "Site A", "abc123"),
            self.FakeEntry(2, "Site B", "StrongP@ss99!xyz"),
            self.FakeEntry(3, "Site C", "abc123"),
        ]
        issues = check_all_health(entries)
        dup_issues = [i for i in issues if i.issue_type == "duplicate"]
        dup_ids = {i.entry_id for i in dup_issues}
        assert 1 in dup_ids
        assert 3 in dup_ids

    def test_detect_weak(self):
        entries = [
            self.FakeEntry(1, "Site A", "123"),
        ]
        issues = check_all_health(entries)
        weak_issues = [i for i in issues if i.issue_type == "weak"]
        assert len(weak_issues) >= 1

    def test_no_issues_for_strong_unique(self):
        entries = [
            self.FakeEntry(1, "A", generate_password(length=20)),
            self.FakeEntry(2, "B", generate_password(length=20)),
        ]
        issues = check_all_health(entries)
        # Có thể không có issue nào (hoặc rất ít)
        dup = [i for i in issues if i.issue_type == "duplicate"]
        assert len(dup) == 0
