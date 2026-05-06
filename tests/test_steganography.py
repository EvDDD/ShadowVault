"""
Test Suite — Steganography (TC-ST-001 → TC-ST-004)
Kiểm thử nhúng/trích xuất LSB.
"""
import pytest
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image
from core.steganography import hide, unhide, peek_magic, estimate_capacity


@pytest.fixture
def cover_image(tmp_path):
    """Tạo ảnh cover PNG 100x100 để test."""
    path = str(tmp_path / "cover.png")
    img = Image.new("RGB", (100, 100), color=(128, 200, 50))
    img.save(path, format="PNG")
    return path


@pytest.fixture
def small_image(tmp_path):
    """Ảnh nhỏ 10x10 cho test capacity."""
    path = str(tmp_path / "small.png")
    img = Image.new("RGB", (10, 10), color=(100, 100, 100))
    img.save(path, format="PNG")
    return path


class TestHideUnhide:
    """TC-ST-001: hide → unhide roundtrip"""

    def test_basic_roundtrip(self, cover_image, tmp_path):
        payload = b"secret data 12345"
        output = str(tmp_path / "stego.png")
        hide(cover_image, payload, output)
        result = unhide(output)
        assert result == payload

    def test_binary_payload(self, cover_image, tmp_path):
        payload = bytes(range(256))
        output = str(tmp_path / "stego.png")
        hide(cover_image, payload, output)
        assert unhide(output) == payload

    def test_empty_payload(self, cover_image, tmp_path):
        output = str(tmp_path / "stego.png")
        hide(cover_image, b"", output)
        assert unhide(output) == b""


class TestCapacity:
    """TC-ST-002: Payload quá lớn → báo lỗi"""

    def test_payload_too_large(self, small_image, tmp_path):
        cap = estimate_capacity(small_image)
        payload = b"X" * (cap + 100)
        output = str(tmp_path / "stego.png")
        with pytest.raises(ValueError):
            hide(small_image, payload, output)


class TestPeekMagic:
    """TC-ST-003: peek_magic nhận diện ảnh stego"""

    def test_stego_image(self, cover_image, tmp_path):
        output = str(tmp_path / "stego.png")
        hide(cover_image, b"test", output)
        assert peek_magic(output) is True

    def test_normal_image(self, cover_image):
        assert peek_magic(cover_image) is False

    def test_nonexistent_file(self):
        assert peek_magic("nonexistent.png") is False


class TestImageSize:
    """TC-ST-004: Ảnh stego không thay đổi kích thước pixel"""

    def test_size_unchanged(self, cover_image, tmp_path):
        output = str(tmp_path / "stego.png")
        hide(cover_image, b"payload data", output)
        original = Image.open(cover_image)
        stego = Image.open(output)
        assert original.size == stego.size
