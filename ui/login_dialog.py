"""
Login / Create Vault dialog for ShadowVault.
Runs KDF synchronously — PBKDF2/Argon2 takes <1s which is acceptable for login.
Using QThread previously introduced subtle SQLite threading issues on Windows.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QFrame, QApplication,
    QComboBox, QFileDialog,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QCursor

from db.schema import vault_exists, init_db
from core.vault import create_vault, unlock_vault, get_all_vaults
from core.stego_manager import StegoManager


class LoginDialog(QDialog):
    unlocked = pyqtSignal(bytes, str, int)   # dek, recovery_display, vault_id

    def __init__(self, parent=None, first_time: bool = False):
        super().__init__(parent)
        self._first_time = first_time  # True = no cover image exists yet
        self.setWindowTitle("ShadowVault")
        self.setFixedSize(420, 580 if first_time else 520)
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

        # Vault selector
        vaults = get_all_vaults()
        if len(vaults) > 1:
            l.addWidget(self._lbl("Select Vault"))
            self.vault_combo = QComboBox()
            self.vault_combo.setFixedHeight(36)
            self.vault_combo.setStyleSheet(
                "QComboBox { background: #21262d; color: #e6edf3; border: 1px solid #30363d;"
                "           border-radius: 6px; padding: 4px 12px; font-size: 13px; }"
                "QComboBox:hover { border-color: #58a6ff; }"
                "QComboBox::drop-down { border: none; width: 30px; }"
                "QComboBox::down-arrow { image: none; border-left: 5px solid transparent;"
                "           border-right: 5px solid transparent; border-top: 6px solid #8b949e;"
                "           margin-right: 8px; }"
                "QComboBox QAbstractItemView { background: #21262d; color: #e6edf3;"
                "           border: 1px solid #30363d; selection-background-color: #1f6feb;"
                "           selection-color: #ffffff; padding: 4px; }"
            )
            for v in vaults:
                self.vault_combo.addItem(v["name"], v["id"])
            l.addWidget(self.vault_combo)
        else:
            self.vault_combo = None

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

    def _get_selected_vault_id(self) -> int:
        """Return the vault_id selected in the combo, or the only vault's id."""
        if self.vault_combo is not None:
            return self.vault_combo.currentData()
        vaults = get_all_vaults()
        return vaults[0]["id"] if vaults else 1

    def _do_unlock(self):
        pw = self.unlock_pw.text()
        if not pw:
            self.unlock_err.setText("Please enter your master password.")
            return

        vault_id = self._get_selected_vault_id()

        self.btn_unlock.setEnabled(False)
        self.btn_unlock.setText("Verifying…")
        self.unlock_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()

        try:
            dek = unlock_vault(pw, vault_id)
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_unlock.setEnabled(True)
            self.btn_unlock.setText("Unlock Vault")

        if dek is None:
            self.unlock_err.setText("❌  Incorrect master password. Please try again.")
            self.unlock_pw.clear()
            self.unlock_pw.setFocus()
        else:
            self.unlocked.emit(dek, "", vault_id)
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

        # ── Cover image picker (only for first vault — no cover exists yet) ──
        self._cover_image_path = None
        if self._first_time:
            l.addWidget(self._lbl("Cover Image for Steganography *"))
            cover_row = QHBoxLayout()
            self.cover_input = QLineEdit()
            self.cover_input.setPlaceholderText("Select a PNG image…")
            self.cover_input.setReadOnly(True)
            self.cover_input.setFixedHeight(36)
            cover_row.addWidget(self.cover_input)
            browse_btn = QPushButton("Browse")
            browse_btn.setFixedHeight(36)
            browse_btn.setFixedWidth(80)
            browse_btn.clicked.connect(self._pick_cover_image)
            cover_row.addWidget(browse_btn)
            l.addLayout(cover_row)

            self.cover_info = QLabel("")
            self.cover_info.setStyleSheet("color:#8b949e; font-size:11px;")
            self.cover_info.setWordWrap(True)
            l.addWidget(self.cover_info)

            cover_hint = QLabel(
                "🖼  Your vault data will be hidden inside this image using\n"
                "     LSB steganography. Choose a large PNG for more capacity."
            )
            cover_hint.setWordWrap(True)
            cover_hint.setStyleSheet(
                "color:#58a6ff; font-size:11px; background:#58a6ff11;"
                "border:1px solid #58a6ff44; border-radius:4px; padding:6px 8px;"
            )
            l.addWidget(cover_hint)
        else:
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

    def _pick_cover_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "",
            "PNG Images (*.png);;All Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if path:
            self._cover_image_path = path
            self.cover_input.setText(path)
            try:
                from core.steganography import estimate_capacity
                cap = estimate_capacity(path)
                cap_kb = cap / 1024
                self.cover_info.setText(
                    f"✓  Capacity: {cap_kb:,.1f} KB available for vault data"
                )
                self.cover_info.setStyleSheet("color:#3fb950; font-size:11px;")
            except Exception as e:
                self.cover_info.setText(f"⚠  Error reading image: {e}")
                self.cover_info.setStyleSheet("color:#f85149; font-size:11px;")

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

        # Require cover image on first-time setup
        if self._first_time and not self._cover_image_path:
            self.create_err.setText("Please select a cover image for steganography.")
            return

        self.btn_create.setEnabled(False)
        self.btn_create.setText("Creating vault…")
        self.create_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()

        try:
            init_db()
            dek, recovery, vault_id = create_vault(pw, name)

            # First-time: copy image with original name + embed DB
            if self._first_time and self._cover_image_path:
                StegoManager.first_embed(self._cover_image_path)
        except Exception as e:
            self.create_err.setText(f"Error: {e}")
            return
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_create.setEnabled(True)
            self.btn_create.setText("Create Vault")

        self.unlocked.emit(dek, recovery, vault_id)
        self.accept()

    # ── Recovery ──────────────────────────────────────────────────

    def _open_recovery(self):
        import logging
        from ui.recovery_dialog import RecoveryDialog
        vault_id = self._get_selected_vault_id()
        logging.info("Opening recovery dialog for vault_id=%s", vault_id)
        dlg = RecoveryDialog(self, vault_id=vault_id)

        def on_recovered(dek: bytes):
            self.unlocked.emit(dek, "", vault_id)
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
