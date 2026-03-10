"""
Main Application Window for ShadowVault.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QListWidget, QListWidgetItem,
    QStackedWidget, QFrame, QDialog, QMessageBox,
    QInputDialog, QLineEdit, QSplitter,
)
from PyQt6.QtCore import Qt, QSize, pyqtSlot
from PyQt6.QtGui import QFont, QIcon, QAction

from core.vault import (
    get_vault_name, get_entry, add_entry, update_entry,
    change_master_password, has_secret_questions,
)
from ui.vault_view import VaultView
from ui.health_view import HealthView
from ui.entry_dialog import EntryDialog
from ui.stego_dialog import StegoDialog
from ui.recovery_dialog import SetQuestionsDialog

_NAV = [
    ("vault",   "🔐",  "Vault"),
    ("health",  "🛡",  "Health Check"),
    ("stego",   "🖼",  "Steganography"),
    ("settings","⚙",  "Settings"),
]


class MainWindow(QMainWindow):
    def __init__(self, dek: bytes, recovery_key: str = ""):
        super().__init__()
        self._dek = dek
        self._vault_name = get_vault_name()

        self.setWindowTitle(f"ShadowVault — {self._vault_name}")
        self.setMinimumSize(960, 640)
        self.resize(1100, 700)

        self._build_ui()
        self._build_menu()

        # Load vault
        self.vault_view.set_dek(dek)
        self.vault_view.refresh()
        self.health_view.set_entries(self.vault_view.get_entries())

        # Show recovery key if just created
        if recovery_key:
            self._show_recovery_key(recovery_key)

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet(
            "QFrame { background: #161b22; border-right: 1px solid #21262d; }"
        )
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        # Vault name header
        vault_hdr = QFrame()
        vault_hdr.setFixedHeight(58)
        vault_hdr.setStyleSheet("background: #0d1117; border-bottom: 1px solid #21262d;")
        vhl = QHBoxLayout(vault_hdr)
        vhl.setContentsMargins(14, 0, 14, 0)
        icon_lbl = QLabel("🔒")
        icon_lbl.setStyleSheet("font-size: 18px; background: transparent;")
        name_lbl = QLabel(self._vault_name)
        name_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        name_lbl.setStyleSheet("color: #e6edf3; background: transparent;")
        vhl.addWidget(icon_lbl)
        vhl.addWidget(name_lbl, 1)
        sl.addWidget(vault_hdr)

        # Nav items
        sl.addSpacing(8)
        self.nav = QListWidget()
        self.nav.setStyleSheet("QListWidget { background: transparent; border: none; }")
        self.nav.setFixedHeight(len(_NAV) * 48 + 16)
        for key, icon, label in _NAV:
            item = QListWidgetItem(f"  {icon}  {label}")
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(200, 44))
            item.setFont(QFont("Segoe UI", 11))
            self.nav.addItem(item)
        self.nav.setCurrentRow(0)
        self.nav.currentRowChanged.connect(self._nav_changed)
        sl.addWidget(self.nav)
        sl.addStretch()

        # Lock button
        lock_btn = QPushButton("  🔓  Lock Vault")
        lock_btn.setStyleSheet(
            "QPushButton { background: transparent; color: #8b949e; border: none; "
            "font-size: 12px; padding: 10px 14px; text-align: left; }"
            "QPushButton:hover { background: #21262d; color: #e6edf3; }"
        )
        lock_btn.clicked.connect(self._lock)
        sl.addWidget(lock_btn)
        sl.addSpacing(8)

        root.addWidget(sidebar)

        # ── Main content ─────────────────────────────────────────
        self.stack = QStackedWidget()

        # 1. Vault View
        self.vault_view = VaultView()
        self.vault_view.add_requested.connect(self._new_entry)
        self.vault_view.edit_requested.connect(self._edit_entry)
        self.stack.addWidget(self.vault_view)

        # 2. Health View
        self.health_view = HealthView()
        self.health_view.entry_selected.connect(self._edit_entry)
        self.stack.addWidget(self.health_view)

        # 3. Stego (placeholder — opens dialog)
        stego_placeholder = self._page_placeholder(
            "🖼", "Steganography",
            "Hide or extract your encrypted vault\ninside a PNG image using LSB steganography.",
            "Open Steganography Tool", self._open_stego
        )
        self.stack.addWidget(stego_placeholder)

        # 4. Settings
        self.stack.addWidget(self._build_settings_page())

        root.addWidget(self.stack, 1)

    def _page_placeholder(self, icon, title, desc, btn_text, btn_fn) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("font-size: 48px;")

        title_lbl = QLabel(title)
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color: #e6edf3;")

        desc_lbl = QLabel(desc)
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_lbl.setStyleSheet("color: #8b949e; font-size: 13px;")
        desc_lbl.setWordWrap(True)

        btn = QPushButton(btn_text)
        btn.setObjectName("btnSecondary")
        btn.setFixedSize(220, 42)
        btn.clicked.connect(btn_fn)

        vl.addWidget(icon_lbl)
        vl.addWidget(title_lbl)
        vl.addWidget(desc_lbl)
        vl.addSpacing(16)
        vl.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)
        return w

    def _build_settings_page(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6edf3;")
        layout.addWidget(title)

        def section(heading: str) -> QLabel:
            lbl = QLabel(heading)
            lbl.setStyleSheet(
                "color: #8b949e; font-size: 12px; font-weight: 600; "
                "border-bottom: 1px solid #30363d; padding-bottom: 6px; margin-top: 8px;"
            )
            return lbl

        def setting_row(label: str, description: str, btn_text: str, btn_fn, danger=False):
            row = QFrame()
            row.setStyleSheet(
                "QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(16, 12, 16, 12)
            info = QVBoxLayout()
            info.setSpacing(2)
            lbl = QLabel(label)
            lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            lbl.setStyleSheet("background: transparent; color: #e6edf3;")
            desc = QLabel(description)
            desc.setStyleSheet("background: transparent; color: #8b949e; font-size: 12px;")
            info.addWidget(lbl)
            info.addWidget(desc)
            btn = QPushButton(btn_text)
            btn.setObjectName("btnDanger" if danger else "")
            btn.setFixedHeight(34)
            btn.setFixedWidth(140)
            btn.clicked.connect(btn_fn)
            rl.addLayout(info, 1)
            rl.addWidget(btn)
            return row

        layout.addWidget(section("Security"))
        layout.addWidget(setting_row(
            "Change Master Password",
            "Update the master password used to unlock your vault.",
            "Change Password", self._change_password
        ))
        layout.addWidget(setting_row(
            "Secret Questions",
            "Set backup recovery questions in case you lose your Recovery Key.",
            "Setup Questions", self._setup_questions
        ))

        layout.addWidget(section("Backup"))
        layout.addWidget(setting_row(
            "Steganography Backup",
            "Hide your vault inside a PNG image for secure offline backup.",
            "Open Stego Tool", self._open_stego
        ))

        layout.addWidget(section("Danger Zone"))
        layout.addWidget(setting_row(
            "Delete Vault",
            "Permanently delete the vault and all stored passwords. Cannot be undone.",
            "Delete Vault", self._delete_vault, danger=True
        ))

        layout.addStretch()

        ver = QLabel("ShadowVault v1.0  ·  AES-256-GCM + Argon2id + LSB Steganography")
        ver.setStyleSheet("color: #6e7681; font-size: 11px;")
        layout.addWidget(ver)
        return w

    def _build_menu(self):
        mb = self.menuBar()

        def action(text: str, slot, shortcut: str = "") -> QAction:
            act = QAction(text, self)
            act.triggered.connect(slot)
            if shortcut:
                act.setShortcut(shortcut)
            return act

        vault_menu = mb.addMenu("Vault")
        vault_menu.addAction(action("New Entry",   self._new_entry,             "Ctrl+N"))
        vault_menu.addAction(action("Refresh",     self.vault_view.refresh,     "F5"))
        vault_menu.addSeparator()
        vault_menu.addAction(action("Lock Vault",  self._lock,                  "Ctrl+L"))
        vault_menu.addAction(action("Quit",        self.close,                  "Ctrl+Q"))

        tools_menu = mb.addMenu("Tools")
        tools_menu.addAction(action("Password Health Check",   self._goto_health))
        tools_menu.addAction(action("Steganography",           self._open_stego))
        tools_menu.addSeparator()
        tools_menu.addAction(action("Change Master Password",  self._change_password))
        tools_menu.addAction(action("Setup Secret Questions",  self._setup_questions))

    # ── Navigation ────────────────────────────────────────────────

    def _nav_changed(self, row: int):
        if row == 1:
            self.health_view.set_entries(self.vault_view.get_entries())
        self.stack.setCurrentIndex(row)

    def _goto_health(self):
        self.nav.setCurrentRow(1)

    # ── Entry operations ─────────────────────────────────────────

    @pyqtSlot()
    def _new_entry(self):
        dlg = EntryDialog(parent=self)
        dlg.saved.connect(self._on_entry_saved_new)
        dlg.exec()

    def _on_entry_saved_new(self, entry):
        add_entry(self._dek, entry)
        self.vault_view.refresh(self.vault_view.search.text())
        self.health_view.set_entries(self.vault_view.get_entries())

    @pyqtSlot(int)
    def _edit_entry(self, entry_id: int):
        entry = get_entry(self._dek, entry_id)
        if not entry:
            return
        dlg = EntryDialog(entry=entry, parent=self)
        dlg.saved.connect(self._on_entry_saved_edit)
        dlg.exec()
        # Switch to vault view
        self.nav.setCurrentRow(0)
        self.vault_view.select_entry_by_id(entry_id)

    def _on_entry_saved_edit(self, entry):
        update_entry(self._dek, entry)
        self.vault_view.refresh(self.vault_view.search.text())
        self.health_view.set_entries(self.vault_view.get_entries())

    # ── Dialogs ──────────────────────────────────────────────────

    def _open_stego(self):
        dlg = StegoDialog(self)
        dlg.exec()

    def _show_recovery_key(self, key: str):
        msg = QMessageBox(self)
        msg.setWindowTitle("🔑 Save Your Recovery Key")
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(
            "<b>Your Emergency Recovery Key has been generated.</b><br><br>"
            "Store this key somewhere safe (printed, USB, etc.).<br>"
            "Without it, you cannot recover your vault if you forget your master password.<br><br>"
            f"<code style='font-size:14px; letter-spacing:2px'>{key}</code>"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def _change_password(self):
        old_pw, ok = QInputDialog.getText(
            self, "Change Master Password", "Current Master Password:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not old_pw:
            return
        from core.vault import unlock_vault
        dek_check = unlock_vault(old_pw)
        if dek_check is None:
            QMessageBox.warning(self, "Error", "Incorrect current password.")
            return

        new_pw, ok = QInputDialog.getText(
            self, "Change Master Password", "New Master Password:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not new_pw or len(new_pw) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters.")
            return
        conf_pw, ok = QInputDialog.getText(
            self, "Change Master Password", "Confirm New Password:",
            QLineEdit.EchoMode.Password
        )
        if not ok or new_pw != conf_pw:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        change_master_password(self._dek, new_pw)
        QMessageBox.information(self, "Done", "Master password changed successfully.")

    def _setup_questions(self):
        dlg = SetQuestionsDialog(self._dek, parent=self)
        dlg.exec()

    def _lock(self):
        self.hide()
        from ui.login_dialog import LoginDialog
        login = LoginDialog()
        login.unlocked.connect(self._on_relocked)
        if login.exec() == QDialog.DialogCode.Accepted:
            self.show()
        else:
            self.close()

    def _on_relocked(self, dek: bytes, recovery: str):
        self._dek = dek
        self.vault_view.set_dek(dek)
        self.vault_view.refresh()
        self.health_view.set_entries(self.vault_view.get_entries())

    def _delete_vault(self):
        reply = QMessageBox.critical(
            self, "Delete Vault",
            "This will PERMANENTLY delete all your passwords.\n\nType DELETE to confirm:",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
        )
        if reply != QMessageBox.StandardButton.Ok:
            return
        text, ok = QInputDialog.getText(self, "Confirm", "Type DELETE to confirm:")
        if ok and text.strip().upper() == "DELETE":
            from db.schema import drop_all
            drop_all()
            QMessageBox.information(self, "Deleted", "Vault deleted. The application will now close.")
            self.close()
