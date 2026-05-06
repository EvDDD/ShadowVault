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
import random
from pathlib import Path

from PIL import Image

from core.steganography import hide, unhide, estimate_capacity, peek_magic

log = logging.getLogger(__name__)

STEGO_DIR = Path.home() / ".shadowvault"

# Realistic decoy filenames — look like normal personal photos
_DECOY_NAMES = [
    "sunset", "beach", "vacation", "family_dinner", "birthday",
    "garden", "coffee_shop", "mountain_view", "city_night",
    "weekend_trip", "pet_photo", "graduation", "park_walk",
    "lake_view", "rooftop", "flowers", "rainy_day",
]


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

    # ── Decoy images ─────────────────────────────────────────────

    @staticmethod
    def populate_decoys(
        count: int = 10,
        exclude_name: str | None = None,
    ) -> list[Path]:
        """
        Generate realistic-looking decoy PNG images in STEGO_DIR.

        Each decoy is a procedurally generated gradient/noise image with
        randomized dimensions, colors, and patterns so they don't all
        look identical. The filenames come from _DECOY_NAMES.

        Args:
            count:        How many decoy images to create (default 10).
            exclude_name: Stem name to skip (the real stego image name).

        Returns:
            List of paths to created decoy images.
        """
        STEGO_DIR.mkdir(parents=True, exist_ok=True)

        # Pick random names from the pool, skipping the stego image name
        available = [n for n in _DECOY_NAMES if n != exclude_name]
        random.shuffle(available)
        names_to_use = available[:count]

        created: list[Path] = []
        for name in names_to_use:
            dest = STEGO_DIR / f"{name}.png"
            if dest.exists():
                continue  # don't overwrite existing files

            try:
                img = _download_decoy_image()
                img.save(str(dest), format="PNG", compress_level=6)
                created.append(dest)
                log.info("Created decoy image: %s", dest.name)
            except Exception as e:
                log.warning("Download failed for %s, trying fallback: %s",
                            name, e)
                try:
                    img = _generate_fallback_image()
                    img.save(str(dest), format="PNG", compress_level=6)
                    created.append(dest)
                    log.info("Created fallback decoy: %s", dest.name)
                except Exception as e2:
                    log.warning("Fallback also failed for %s: %s", name, e2)

        log.info("Populated %d decoy images in %s", len(created), STEGO_DIR)
        return created

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

# ── Decoy image helpers (module-level) ───────────────────────────

def _download_decoy_image() -> Image.Image:
    """
    Download a random real photograph from Lorem Picsum.

    Uses https://picsum.photos/{w}/{h} which returns a random
    high-quality photo each time. No API key required.
    The response is a JPEG — we convert to RGB PIL Image.
    """
    import io
    import urllib.request

    w = random.randint(800, 1400)
    h = random.randint(600, 1100)
    url = f"https://picsum.photos/{w}/{h}"

    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; ShadowVault/1.0)"
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = resp.read()

    img = Image.open(io.BytesIO(data)).convert("RGB")
    log.debug("Downloaded decoy %dx%d from picsum.photos", img.size[0], img.size[1])
    return img


def _generate_fallback_image() -> Image.Image:
    """
    Offline fallback: generate a gradient + noise image using numpy.
    Used when picsum.photos is unreachable.
    """
    import numpy as np

    w = random.randint(600, 1400)
    h = random.randint(600, 1400)

    c1 = np.array([random.randint(0, 255) for _ in range(3)], dtype=np.float64)
    c2 = np.array([random.randint(0, 255) for _ in range(3)], dtype=np.float64)

    direction = random.randint(0, 2)
    if direction == 0:
        t = np.linspace(0, 1, w, dtype=np.float64)[np.newaxis, :]
        t = np.broadcast_to(t, (h, w))
    elif direction == 1:
        t = np.linspace(0, 1, h, dtype=np.float64)[:, np.newaxis]
        t = np.broadcast_to(t, (h, w))
    else:
        ys = np.arange(h, dtype=np.float64)[:, np.newaxis]
        xs = np.arange(w, dtype=np.float64)[np.newaxis, :]
        t = (xs + ys) / max(w + h - 2, 1)

    base = (1 - t)[..., np.newaxis] * c1 + t[..., np.newaxis] * c2

    noise_amp = random.randint(15, 40)
    noise = np.random.randint(-noise_amp, noise_amp + 1, size=(h, w, 3))

    result = np.clip(base + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(result, "RGB")
