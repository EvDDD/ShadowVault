"""
Login / Create Vault dialog for ShadowVault.
Runs KDF synchronously — PBKDF2/Argon2 takes <1s which is acceptable for login.
Using QThread previously introduced subtle SQLite threading issues on Windows.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QFrame, QApplication,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QCursor

from db.schema import vault_exists, init_db
from core.vault import create_vault, unlock_vault


class LoginDialog(QDialog):
    unlocked = pyqtSignal(bytes, str)   # dek, recovery_display

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ShadowVault")
        self.setFixedSize(420, 520)
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.MSWindowsFixedSizeDialogHint
        )
        self._build_ui()

    # ── Build ─────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        hdr = QFrame()
        hdr.setStyleSheet("background:#161b22; border-bottom:1px solid #30363d;")
        hdr.setFixedHeight(118)
        hl = QVBoxLayout(hdr)
        hl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logo = QLabel("🔒")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFont(QFont("Segoe UI Emoji", 30))
        logo.setStyleSheet("background:transparent; color:#58a6ff;")

        title = QLabel("ShadowVault")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("background:transparent; color:#58a6ff;")

        sub = QLabel("Personal Password Manager")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("background:transparent; color:#8b949e; font-size:12px;")

        hl.addWidget(logo)
        hl.addWidget(title)
        hl.addWidget(sub)
        layout.addWidget(hdr)

        # Body
        body = QWidget()
        body.setStyleSheet("background:#0d1117;")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(28, 20, 28, 20)
        bl.setSpacing(12)

        self.tabs = QTabWidget()
        if vault_exists():
            self.tabs.addTab(self._unlock_tab(), "Unlock Vault")
            self.tabs.addTab(self._create_tab(), "New Vault")
        else:
            self.tabs.addTab(self._create_tab(), "Create Vault")

        bl.addWidget(self.tabs)
        layout.addWidget(body, 1)

    # ── Unlock tab ────────────────────────────────────────────────

    def _unlock_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:transparent;")
        l = QVBoxLayout(w)
        l.setSpacing(10)
        l.setContentsMargins(0, 14, 0, 0)

        l.addWidget(self._lbl("Master Password"))
        self.unlock_pw = self._field("Enter your master password", pw=True)
        self.unlock_pw.returnPressed.connect(self._do_unlock)
        l.addWidget(self.unlock_pw)

        self.unlock_err = QLabel("")
        self.unlock_err.setStyleSheet("color:#f85149; font-size:12px;")
        self.unlock_err.setWordWrap(True)
        l.addWidget(self.unlock_err)

        l.addStretch()

        self.btn_unlock = QPushButton("Unlock Vault")
        self.btn_unlock.setObjectName("btnPrimary")
        self.btn_unlock.setFixedHeight(40)
        self.btn_unlock.clicked.connect(self._do_unlock)
        l.addWidget(self.btn_unlock)

        sep = QLabel("Forgot your password?")
        sep.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sep.setStyleSheet("color:#8b949e; font-size:12px;")
        l.addWidget(sep)

        btn_rec = QPushButton("Recover with Emergency Key")
        btn_rec.setObjectName("btnSecondary")
        btn_rec.setFixedHeight(36)
        btn_rec.clicked.connect(self._open_recovery)
        l.addWidget(btn_rec)
        return w

    def _do_unlock(self):
        pw = self.unlock_pw.text()
        if not pw:
            self.unlock_err.setText("Please enter your master password.")
            return

        self.btn_unlock.setEnabled(False)
        self.btn_unlock.setText("Verifying…")
        self.unlock_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()

        try:
            dek = unlock_vault(pw)
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_unlock.setEnabled(True)
            self.btn_unlock.setText("Unlock Vault")

        if dek is None:
            self.unlock_err.setText("❌  Incorrect master password. Please try again.")
            self.unlock_pw.clear()
            self.unlock_pw.setFocus()
        else:
            self.unlocked.emit(dek, "")
            self.accept()

    # ── Create tab ────────────────────────────────────────────────

    def _create_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:transparent;")
        l = QVBoxLayout(w)
        l.setSpacing(10)
        l.setContentsMargins(0, 14, 0, 0)

        l.addWidget(self._lbl("Vault Name (optional)"))
        self.vault_name = self._field("My Vault")
        l.addWidget(self.vault_name)

        l.addWidget(self._lbl("Master Password"))
        self.create_pw = self._field("Create a strong master password", pw=True)
        l.addWidget(self.create_pw)

        l.addWidget(self._lbl("Confirm Password"))
        self.create_pw2 = self._field("Confirm master password", pw=True)
        self.create_pw2.returnPressed.connect(self._do_create)
        l.addWidget(self.create_pw2)

        self.create_err = QLabel("")
        self.create_err.setStyleSheet("color:#f85149; font-size:12px;")
        self.create_err.setWordWrap(True)
        l.addWidget(self.create_err)

        notice = QLabel("⚠  A Recovery Key will be generated — save it somewhere safe.")
        notice.setWordWrap(True)
        notice.setStyleSheet(
            "color:#d29922; font-size:11px; background:#d2992211;"
            "border:1px solid #d2992244; border-radius:4px; padding:6px 8px;"
        )
        l.addWidget(notice)
        l.addStretch()

        self.btn_create = QPushButton("Create Vault")
        self.btn_create.setObjectName("btnPrimary")
        self.btn_create.setFixedHeight(40)
        self.btn_create.clicked.connect(self._do_create)
        l.addWidget(self.btn_create)
        return w

    def _do_create(self):
        name = self.vault_name.text().strip() or "My Vault"
        pw   = self.create_pw.text()
        pw2  = self.create_pw2.text()

        if not pw:
            self.create_err.setText("Master password cannot be empty.")
            return
        if len(pw) < 8:
            self.create_err.setText("Password must be at least 8 characters.")
            return
        if pw != pw2:
            self.create_err.setText("Passwords do not match.")
            return

        self.btn_create.setEnabled(False)
        self.btn_create.setText("Creating vault…")
        self.create_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()

        try:
            init_db()
            dek, recovery = create_vault(pw, name)
        except Exception as e:
            self.create_err.setText(f"Error: {e}")
            return
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_create.setEnabled(True)
            self.btn_create.setText("Create Vault")

        self.unlocked.emit(dek, recovery)
        self.accept()

    # ── Recovery ──────────────────────────────────────────────────

    def _open_recovery(self):
        from ui.recovery_dialog import RecoveryDialog
        dlg = RecoveryDialog(self)

        def on_recovered(dek: bytes):
            self.unlocked.emit(dek, "")
            self.accept()

        dlg.recovered.connect(on_recovered)
        dlg.exec()

    # ── Helpers ──────────────────────────────────────────────────

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600;")
        return l

    def _field(self, placeholder: str, pw: bool = False) -> QLineEdit:
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setFixedHeight(36)
        if pw:
            e.setEchoMode(QLineEdit.EchoMode.Password)
        return e
