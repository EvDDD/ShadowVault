"""
ShadowVault — Personal Password Manager
Entry point.

Usage:
    python main.py
    (or double-click main.py on Windows)

Storage: The vault database lives entirely in RAM (in-memory SQLite).
On startup it is extracted from a steganography PNG image; on shutdown
it is serialized, compressed, and re-embedded into the image.
No database file is ever written to disk.
"""
import sys
import os
import logging

# Add project root to path so imports work when run from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon

from ui.styles import DARK_STYLESHEET
from db.schema import init_db
from core.stego_manager import StegoManager

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def main():
    # Must be set BEFORE creating QApplication
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("ShadowVault")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("ShadowVault")

    # Apply dark theme
    app.setStyleSheet(DARK_STYLESHEET)
    app.setFont(QFont("Segoe UI", 10))

    # ── Stego lifecycle: load DB from image into RAM ─────────────
    stego = StegoManager()

    if stego.has_stego():
        try:
            stego.extract_db()   # stego image → decompress → RAM
        except Exception as e:
            QMessageBox.critical(
                None, "Fatal Error",
                f"Failed to extract vault from stego image:\n{e}"
            )
            return 1

    # Ensure DB schema exists (in-memory)
    try:
        init_db()
    except Exception as e:
        QMessageBox.critical(None, "Fatal Error", f"Failed to initialise database:\n{e}")
        return 1

    # ── Embed DB back into image on shutdown ─────────────────────
    def on_quit():
        try:
            if stego.has_stego():
                stego.embed_db()   # RAM → compress → stego image
        except Exception as e:
            logging.error("Failed to embed DB on quit: %s", e)

    app.aboutToQuit.connect(on_quit)

    # ── Show login / create dialog ───────────────────────────────
    from ui.login_dialog import LoginDialog

    first_time = not stego.has_stego()
    login = LoginDialog(first_time=first_time)

    result_holder = {"dek": None, "recovery": "", "vault_id": None}

    def on_unlocked(dek: bytes, recovery: str, vault_id: int):
        result_holder["dek"] = dek
        result_holder["recovery"] = recovery
        result_holder["vault_id"] = vault_id

    login.unlocked.connect(on_unlocked)

    if login.exec() != LoginDialog.DialogCode.Accepted or result_holder["dek"] is None:
        return 0

    # Launch main window
    from ui.main_window import MainWindow
    window = MainWindow(
        dek=result_holder["dek"],
        recovery_key=result_holder["recovery"],
        vault_id=result_holder["vault_id"],
    )
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
