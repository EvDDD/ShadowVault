"""
Steganography Lifecycle Manager for ShadowVault.

Integrates LSB steganography with in-memory SQLite storage.
The vault database NEVER exists as a file on disk.

Storage layout:
    ~/.shadowvault/
    ├── beach.png          # could be a decoy (normal image)
    ├── sunset.png         # could be a decoy (normal image)
    └── vacation.png       # THE stego image (has magic header in LSB)
                           # looks identical to a normal photo

The stego image is identified by scanning all PNGs for the magic
header "SVLT" embedded in the LSB bits. No config file needed.
"""
from __future__ import annotations
import gzip
import logging
from pathlib import Path

from core.steganography import hide, unhide, estimate_capacity, peek_magic

log = logging.getLogger(__name__)

STEGO_DIR = Path.home() / ".shadowvault"


class StegoManager:
    """Manages the stego image lifecycle: extract, embed, change cover."""

    # ── Find the stego image by scanning for magic header ────────

    @staticmethod
    def find_stego_image() -> Path | None:
        """
        Scan STEGO_DIR for a PNG that contains the ShadowVault magic header.
        Returns the path if found, None otherwise.
        """
        STEGO_DIR.mkdir(parents=True, exist_ok=True)
        for png_file in sorted(STEGO_DIR.glob("*.png")):
            if peek_magic(str(png_file)):
                log.info("Found stego image: %s", png_file.name)
                return png_file
        return None

    @classmethod
    def has_stego(cls) -> bool:
        """True if a stego image with valid magic header exists."""
        return cls.find_stego_image() is not None

    # ── Setup ────────────────────────────────────────────────────

    @staticmethod
    def setup_cover(source_image_path: str) -> Path:
        """
        Copy the user-selected image into STEGO_DIR, keeping the
        original filename. Converts to RGB PNG for LSB compatibility.
        Returns the destination path.
        """
        STEGO_DIR.mkdir(parents=True, exist_ok=True)
        src = Path(source_image_path)
        # Keep original filename but ensure .png extension
        dest_name = src.stem + ".png"
        dest_path = STEGO_DIR / dest_name

        # Avoid name collision with existing files
        counter = 1
        while dest_path.exists():
            dest_path = STEGO_DIR / f"{src.stem}_{counter}.png"
            counter += 1

        from PIL import Image
        img = Image.open(source_image_path).convert("RGB")
        img.save(str(dest_path), format="PNG", compress_level=1)
        log.info("Cover image saved: %s → %s", src.name, dest_path.name)
        return dest_path

    # ── Extract (startup) ────────────────────────────────────────

    @classmethod
    def extract_db(cls) -> None:
        """
        Find the stego image, extract the compressed DB from it,
        and load directly into the in-memory SQLite connection.
        NO file is written to disk.
        """
        stego_path = cls.find_stego_image()
        if stego_path is None:
            raise FileNotFoundError("No stego image found in " + str(STEGO_DIR))

        raw_payload = unhide(str(stego_path))
        db_bytes = gzip.decompress(raw_payload)

        from db.schema import load_db_from_bytes
        load_db_from_bytes(db_bytes)
        log.info("Extracted DB from %s → RAM (%d → %d bytes)",
                 stego_path.name, len(raw_payload), len(db_bytes))

    # ── Embed (shutdown) ─────────────────────────────────────────

    @classmethod
    def embed_db(cls) -> None:
        """
        Serialize the in-memory DB, compress it, and embed into the
        current stego image (overwriting its LSBs with new data).
        """
        stego_path = cls.find_stego_image()
        if stego_path is None:
            raise FileNotFoundError("No stego image found to embed into")

        from db.schema import dump_db_to_bytes
        db_bytes = dump_db_to_bytes()
        compressed = gzip.compress(db_bytes, compresslevel=9)

        cap = estimate_capacity(str(stego_path))
        if cap < len(compressed):
            raise ValueError(
                f"Image too small. Need {len(compressed):,} bytes "
                f"but image can hold {cap:,} bytes."
            )

        # Embed into the stego image itself (overwrite LSBs)
        hide(str(stego_path), compressed, str(stego_path))
        log.info("Embedded DB into %s (%d → %d bytes compressed)",
                 stego_path.name, len(db_bytes), len(compressed))

    @classmethod
    def first_embed(cls, cover_path: str) -> None:
        """
        First-time embed: copy user's image and embed DB into it.
        Used when creating the very first vault.
        """
        dest = cls.setup_cover(cover_path)

        from db.schema import dump_db_to_bytes
        db_bytes = dump_db_to_bytes()
        compressed = gzip.compress(db_bytes, compresslevel=9)

        cap = estimate_capacity(str(dest))
        if cap < len(compressed):
            dest.unlink()  # clean up the copied image
            raise ValueError(
                f"Image too small. Need {len(compressed):,} bytes "
                f"but image can hold {cap:,} bytes."
            )

        hide(str(dest), compressed, str(dest))
        log.info("First embed into %s (%d → %d bytes compressed)",
                 dest.name, len(db_bytes), len(compressed))

    # ── Change cover ─────────────────────────────────────────────

    @classmethod
    def change_cover(cls, new_image_path: str) -> None:
        """
        Replace the stego image with a new cover image + re-embed DB.
        1. Copy new image into STEGO_DIR (original filename)
        2. Embed DB into the new image
        3. Delete old stego image
        """
        old_stego = cls.find_stego_image()

        # Copy new image
        dest = cls.setup_cover(new_image_path)

        # Embed DB into new image
        from db.schema import dump_db_to_bytes
        db_bytes = dump_db_to_bytes()
        compressed = gzip.compress(db_bytes, compresslevel=9)

        cap = estimate_capacity(str(dest))
        if cap < len(compressed):
            dest.unlink()
            raise ValueError(
                f"New image too small. Need {len(compressed):,} bytes "
                f"but image can hold {cap:,} bytes."
            )

        hide(str(dest), compressed, str(dest))
        log.info("Re-embedded DB into new image: %s", dest.name)

        # Delete old stego image (if different from new)
        if old_stego and old_stego != dest and old_stego.exists():
            old_stego.unlink()
            log.info("Deleted old stego image: %s", old_stego.name)

    # ── Cleanup ──────────────────────────────────────────────────

    @classmethod
    def delete_all(cls) -> None:
        """Delete the stego image (used when last vault is deleted)."""
        stego = cls.find_stego_image()
        if stego and stego.exists():
            stego.unlink()
            log.info("Deleted stego image: %s", stego.name)

    # ── Info ──────────────────────────────────────────────────────

    @classmethod
    def stego_info(cls) -> dict:
        """Return info about the current stego setup."""
        stego = cls.find_stego_image()
        info = {
            "has_stego": stego is not None,
            "stego_path": str(stego) if stego else "",
            "stego_name": stego.name if stego else "",
            "stego_size": stego.stat().st_size if stego else 0,
            "capacity": 0,
        }
        if stego:
            try:
                info["capacity"] = estimate_capacity(str(stego))
            except Exception:
                pass
        return info
