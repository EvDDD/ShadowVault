"""
ShadowVault — Personal Password Manager
Entry point.

Usage:
    python main.py
    (or double-click main.py on Windows)
"""
import sys
import os

# Add project root to path so imports work when run from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon

from ui.styles import DARK_STYLESHEET
from db.schema import init_db


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ShadowVault")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("ShadowVault")

    # High DPI support
    app.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # Apply dark theme
    app.setStyleSheet(DARK_STYLESHEET)
    app.setFont(QFont("Segoe UI", 10))

    # Ensure DB schema exists
    try:
        init_db()
    except Exception as e:
        QMessageBox.critical(None, "Fatal Error", f"Failed to initialise database:\n{e}")
        return 1

    # Show login / create dialog
    from ui.login_dialog import LoginDialog
    login = LoginDialog()

    result_holder = {"dek": None, "recovery": ""}

    def on_unlocked(dek: bytes, recovery: str):
        result_holder["dek"] = dek
        result_holder["recovery"] = recovery

    login.unlocked.connect(on_unlocked)

    if login.exec() != LoginDialog.DialogCode.Accepted or result_holder["dek"] is None:
        return 0

    # Launch main window
    from ui.main_window import MainWindow
    window = MainWindow(
        dek=result_holder["dek"],
        recovery_key=result_holder["recovery"],
    )
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
