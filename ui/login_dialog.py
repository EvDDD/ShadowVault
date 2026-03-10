"""
Login / Create Vault dialog for ShadowVault.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QMessageBox, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

from db.schema import vault_exists, init_db
from core.vault import create_vault, unlock_vault


class LoginDialog(QDialog):
    """
    Shown on startup. Has two tabs:
      - Unlock (if vault exists)
      - Create New Vault
    """

    # Emits (dek: bytes, recovery_display: str | None)
    unlocked = pyqtSignal(bytes, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ShadowVault")
        self.setFixedSize(420, 500)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.MSWindowsFixedSizeDialogHint)

        self._dek: bytes | None = None
        self._recovery: str = ""

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Header ──────────────────────────────────────────────
        header = QFrame()
        header.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #30363d;")
        header.setFixedHeight(120)
        hlayout = QVBoxLayout(header)
        hlayout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logo = QLabel("🔒")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFont(QFont("Segoe UI Emoji", 32))
        logo.setStyleSheet("background: transparent; color: #58a6ff;")

        title = QLabel("ShadowVault")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("background: transparent; color: #58a6ff;")

        sub = QLabel("Personal Password Manager")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("background: transparent; color: #8b949e; font-size: 12px;")

        hlayout.addWidget(logo)
        hlayout.addWidget(title)
        hlayout.addWidget(sub)
        layout.addWidget(header)

        # ── Body ────────────────────────────────────────────────
        body = QWidget()
        body.setStyleSheet("background-color: #0d1117;")
        blayout = QVBoxLayout(body)
        blayout.setContentsMargins(32, 24, 32, 24)
        blayout.setSpacing(16)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: none; }")

        if vault_exists():
            self.tabs.addTab(self._build_unlock_tab(), "Unlock Vault")
            self.tabs.addTab(self._build_create_tab(), "New Vault")
        else:
            self.tabs.addTab(self._build_create_tab(), "Create Vault")

        blayout.addWidget(self.tabs)
        layout.addWidget(body, 1)

    def _field(self, placeholder: str, password: bool = False) -> QLineEdit:
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        if password:
            e.setEchoMode(QLineEdit.EchoMode.Password)
        e.setFixedHeight(38)
        return e

    def _build_unlock_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        lbl = QLabel("Master Password")
        lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.unlock_pw = self._field("Enter your master password", password=True)
        self.unlock_pw.returnPressed.connect(self._do_unlock)

        self.unlock_error = QLabel("")
        self.unlock_error.setStyleSheet("color: #f85149; font-size: 12px;")

        btn = QPushButton("Unlock Vault")
        btn.setObjectName("btnPrimary")
        btn.setFixedHeight(40)
        btn.clicked.connect(self._do_unlock)

        sep = QLabel("Forgot your password?")
        sep.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sep.setStyleSheet("color: #8b949e; font-size: 12px;")

        recovery_btn = QPushButton("Recover with Emergency Key")
        recovery_btn.setObjectName("btnSecondary")
        recovery_btn.setFixedHeight(36)
        recovery_btn.clicked.connect(self._open_recovery)

        layout.addWidget(lbl)
        layout.addWidget(self.unlock_pw)
        layout.addWidget(self.unlock_error)
        layout.addStretch()
        layout.addWidget(btn)
        layout.addWidget(sep)
        layout.addWidget(recovery_btn)
        return w

    def _build_create_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        lbl1 = QLabel("Vault Name (optional)")
        lbl1.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.vault_name = self._field("My Vault")

        lbl2 = QLabel("Master Password")
        lbl2.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.create_pw = self._field("Create a strong master password", password=True)

        lbl3 = QLabel("Confirm Password")
        lbl3.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.create_pw2 = self._field("Confirm master password", password=True)
        self.create_pw2.returnPressed.connect(self._do_create)

        self.create_error = QLabel("")
        self.create_error.setStyleSheet("color: #f85149; font-size: 12px;")
        self.create_error.setWordWrap(True)

        btn = QPushButton("Create Vault")
        btn.setObjectName("btnPrimary")
        btn.setFixedHeight(40)
        btn.clicked.connect(self._do_create)

        notice = QLabel("⚠  A Recovery Key will be generated. Store it safely.")
        notice.setWordWrap(True)
        notice.setStyleSheet(
            "color: #d29922; font-size: 11px; background: #d2992211; "
            "border: 1px solid #d2992244; border-radius: 4px; padding: 6px 8px;"
        )

        layout.addWidget(lbl1)
        layout.addWidget(self.vault_name)
        layout.addWidget(lbl2)
        layout.addWidget(self.create_pw)
        layout.addWidget(lbl3)
        layout.addWidget(self.create_pw2)
        layout.addWidget(self.create_error)
        layout.addStretch()
        layout.addWidget(notice)
        layout.addWidget(btn)
        return w

    def _do_unlock(self):
        pw = self.unlock_pw.text()
        if not pw:
            self.unlock_error.setText("Please enter your master password.")
            return
        self.unlock_error.setText("Verifying…")
        dek = unlock_vault(pw)
        if dek is None:
            self.unlock_error.setText("Incorrect master password.")
            self.unlock_pw.clear()
        else:
            self.unlocked.emit(dek, "")
            self.accept()

    def _do_create(self):
        name = self.vault_name.text().strip() or "My Vault"
        pw   = self.create_pw.text()
        pw2  = self.create_pw2.text()

        if not pw:
            self.create_error.setText("Master password cannot be empty.")
            return
        if len(pw) < 8:
            self.create_error.setText("Password must be at least 8 characters.")
            return
        if pw != pw2:
            self.create_error.setText("Passwords do not match.")
            return

        try:
            init_db()
            dek, recovery = create_vault(pw, name)
        except Exception as e:
            self.create_error.setText(f"Error: {e}")
            return

        self.unlocked.emit(dek, recovery)
        self.accept()

    def _open_recovery(self):
        from ui.recovery_dialog import RecoveryDialog
        dlg = RecoveryDialog(self)
        dlg.recovered.connect(lambda dek: (self.unlocked.emit(dek, ""), self.accept()))
        dlg.exec()
