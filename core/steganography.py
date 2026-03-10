"""
LSB Steganography module for ShadowVault.
Embeds an encrypted database file into a PNG cover image using
Least Significant Bit substitution.

Format of embedded data:
  [4 bytes: payload length as big-endian uint32] [N bytes: payload]
"""
from __future__ import annotations
import struct
from pathlib import Path
from PIL import Image


_MAGIC = b"SVLT"   # 4-byte magic header inside payload
_MAX_PAYLOAD_MB = 10


def _image_capacity_bytes(img: Image.Image) -> int:
    """Max bytes storable in image (1 bit per channel, 3 channels)."""
    w, h = img.size
    # We use 3 channels (RGB), 1 LSB each → 3 bits per pixel → 3/8 bytes per pixel
    return (w * h * 3) // 8


def hide(cover_path: str, payload: bytes, output_path: str) -> None:
    """
    Embed payload bytes into a cover PNG image.
    Raises ValueError if image is too small or payload exceeds limit.
    """
    if len(payload) > _MAX_PAYLOAD_MB * 1024 * 1024:
        raise ValueError(f"Payload exceeds {_MAX_PAYLOAD_MB} MB limit.")

    img = Image.open(cover_path).convert("RGB")
    cap = _image_capacity_bytes(img)

    full_payload = _MAGIC + struct.pack(">I", len(payload)) + payload
    if len(full_payload) > cap:
        raise ValueError(
            f"Image too small. Need {len(full_payload)} bytes capacity, "
            f"but image only holds {cap} bytes."
        )

    pixels = list(img.getdata())
    bits = _bytes_to_bits(full_payload)

    new_pixels = []
    bit_idx = 0
    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(bits):
            r = (r & 0xFE) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            g = (g & 0xFE) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            b = (b & 0xFE) | bits[bit_idx]; bit_idx += 1
        new_pixels.append((r, g, b))

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(output_path, format="PNG", compress_level=1)


def unhide(stego_path: str) -> bytes:
    """
    Extract embedded payload from a stego PNG image.
    Raises ValueError if no valid payload found.
    """
    img = Image.open(stego_path).convert("RGB")
    pixels = list(img.getdata())

    # Extract all LSBs
    bits = []
    for r, g, b in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    raw = _bits_to_bytes(bits)

    # Validate magic + read length
    magic_size = len(_MAGIC)
    if len(raw) < magic_size + 4:
        raise ValueError("Image does not contain a valid ShadowVault payload.")

    if raw[:magic_size] != _MAGIC:
        raise ValueError("Magic header not found. Image was not created by ShadowVault.")

    length = struct.unpack(">I", raw[magic_size:magic_size + 4])[0]
    payload_start = magic_size + 4
    payload_end   = payload_start + length

    if payload_end > len(raw):
        raise ValueError("Payload length exceeds image data. Image may be corrupted.")

    return raw[payload_start:payload_end]


# ── Helpers ──────────────────────────────────────────────────────

def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def estimate_capacity(image_path: str) -> int:
    """Return the byte capacity of an image for embedding."""
    img = Image.open(image_path).convert("RGB")
    return _image_capacity_bytes(img) - len(_MAGIC) - 4


def image_size_ok(image_path: str, payload_size: int) -> bool:
    """Check if image is large enough to hold payload."""
    return estimate_capacity(image_path) >= payload_size
