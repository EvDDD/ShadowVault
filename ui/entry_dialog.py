"""
Add / Edit Vault Entry dialog for ShadowVault.
Includes inline password generator and real-time strength indicator.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QFrame, QSlider, QCheckBox, QWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont

from core.vault import VaultEntry
from core.password_gen import generate_password, check_strength
from ui.styles import STRENGTH_COLORS

try:
    import pyperclip
    _HAS_CLIP = True
except ImportError:
    _HAS_CLIP = False


class EntryDialog(QDialog):
    """Dialog to create or edit a vault entry."""

    saved = pyqtSignal(VaultEntry)

    def __init__(self, entry: VaultEntry | None = None, vault_id: int = 1, parent=None):
        super().__init__(parent)
        self._entry = entry
        self._vault_id = vault_id
        self._is_edit = entry is not None

        self.setWindowTitle("Edit Entry" if self._is_edit else "New Entry")
        self.setFixedSize(500, 680)
        self._build_ui()

        if self._is_edit:
            self._populate()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Title
        title = QLabel("Edit Entry" if self._is_edit else "New Entry")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        # ── Fields ──────────────────────────────────────────────
        layout.addWidget(self._lbl("Entry Title *"))
        self.f_title = self._input("e.g. Gmail")
        layout.addWidget(self.f_title)

        layout.addWidget(self._lbl("URL / Website"))
        self.f_url = self._input("https://")
        layout.addWidget(self.f_url)

        layout.addWidget(self._lbl("Username / Email"))
        self.f_user = self._input("username@example.com")
        layout.addWidget(self.f_user)

        layout.addWidget(self._lbl("Password *"))
        pw_row = QHBoxLayout()
        pw_row.setSpacing(8)
        self.f_pw = QLineEdit()
        self.f_pw.setPlaceholderText("Enter or generate a password")
        self.f_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.f_pw.setFixedHeight(38)
        self.f_pw.textChanged.connect(self._on_pw_changed)

        self.btn_toggle = QPushButton("👁")
        self.btn_toggle.setFixedSize(38, 38)
        self.btn_toggle.setToolTip("Show/hide password")
        self.btn_toggle.setCheckable(True)
        self.btn_toggle.toggled.connect(self._toggle_pw_visibility)
        self.btn_toggle.setStyleSheet("QPushButton { font-size: 16px; padding: 0; } ")

        pw_row.addWidget(self.f_pw)
        pw_row.addWidget(self.btn_toggle)
        layout.addLayout(pw_row)

        # Strength bar
        self.strength_bar = QFrame()
        self.strength_bar.setFixedHeight(4)
        self.strength_bar.setStyleSheet("background: #30363d; border-radius: 2px;")
        layout.addWidget(self.strength_bar)

        self.strength_lbl = QLabel("")
        self.strength_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(self.strength_lbl)

        # ── Generator ────────────────────────────────────────────
        gen_frame = QFrame()
        gen_frame.setStyleSheet(
            "QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 6px; }"
        )
        gen_layout = QVBoxLayout(gen_frame)
        gen_layout.setContentsMargins(12, 10, 12, 10)
        gen_layout.setSpacing(8)

        gen_hdr = QHBoxLayout()
        gen_lbl = QLabel("Password Generator")
        gen_lbl.setStyleSheet("background: transparent; color: #8b949e; font-size: 12px; font-weight: 600;")
        gen_btn = QPushButton("Generate")
        gen_btn.setObjectName("btnSecondary")
        gen_btn.setFixedHeight(30)
        gen_btn.clicked.connect(self._generate)
        gen_hdr.addWidget(gen_lbl)
        gen_hdr.addStretch()
        gen_hdr.addWidget(gen_btn)
        gen_layout.addLayout(gen_hdr)

        # Length slider
        len_row = QHBoxLayout()
        len_lbl = QLabel("Length:")
        len_lbl.setStyleSheet("background: transparent; color: #8b949e; font-size: 12px;")
        self.len_slider = QSlider(Qt.Orientation.Horizontal)
        self.len_slider.setRange(8, 64)
        self.len_slider.setValue(20)
        self.len_slider.valueChanged.connect(self._update_len_label)
        self.len_val = QLabel("20")
        self.len_val.setFixedWidth(28)
        self.len_val.setStyleSheet("background: transparent; color: #e6edf3; font-size: 12px;")
        len_row.addWidget(len_lbl)
        len_row.addWidget(self.len_slider)
        len_row.addWidget(self.len_val)
        gen_layout.addLayout(len_row)

        # Checkboxes
        cb_row = QHBoxLayout()
        self.cb_upper   = self._cb("A–Z",   True)
        self.cb_lower   = self._cb("a–z",   True)
        self.cb_digits  = self._cb("0–9",   True)
        self.cb_symbols = self._cb("!@#…",  True)
        for cb in [self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols]:
            cb_row.addWidget(cb)
        gen_layout.addLayout(cb_row)
        layout.addWidget(gen_frame)

        # Notes
        layout.addWidget(self._lbl("Notes"))
        self.f_notes = QTextEdit()
        self.f_notes.setPlaceholderText("Optional notes…")
        self.f_notes.setFixedHeight(70)
        layout.addWidget(self.f_notes)

        layout.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Save Entry")
        save.setObjectName("btnPrimary")
        save.setFixedHeight(40)
        save.clicked.connect(self._save)
        btn_row.addWidget(cancel)
        btn_row.addWidget(save)
        layout.addLayout(btn_row)

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600; margin-top: 2px;")
        return l

    def _input(self, placeholder: str) -> QLineEdit:
        e = QLineEdit()
        e.setPlaceholderText(placeholder)
        e.setFixedHeight(38)
        return e

    def _cb(self, text: str, checked: bool = True) -> QCheckBox:
        cb = QCheckBox(text)
        cb.setChecked(checked)
        cb.setStyleSheet("QCheckBox { background: transparent; color: #e6edf3; font-size: 12px; }")
        return cb

    def _populate(self):
        e = self._entry
        self.f_title.setText(e.title)
        self.f_url.setText(e.url)
        self.f_user.setText(e.username)
        self.f_pw.setText(e.password)
        self.f_notes.setPlainText(e.notes)

    def _toggle_pw_visibility(self, checked: bool):
        if checked:
            self.f_pw.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.f_pw.setEchoMode(QLineEdit.EchoMode.Password)

    def _update_len_label(self, val: int):
        self.len_val.setText(str(val))

    def _generate(self):
        pw = generate_password(
            length=self.len_slider.value(),
            use_upper=self.cb_upper.isChecked(),
            use_lower=self.cb_lower.isChecked(),
            use_digits=self.cb_digits.isChecked(),
            use_symbols=self.cb_symbols.isChecked(),
        )
        self.f_pw.setText(pw)
        self.f_pw.setEchoMode(QLineEdit.EchoMode.Normal)
        self.btn_toggle.setChecked(True)

    def _on_pw_changed(self, text: str):
        if not text:
            self.strength_bar.setStyleSheet("background: #30363d; border-radius: 2px;")
            self.strength_lbl.setText("")
            return
        result = check_strength(text)
        color = result.color
        pct = (result.score + 1) * 20
        self.strength_bar.setStyleSheet(
            f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            f"stop:{pct/100:.2f} {color}, stop:{pct/100+0.001:.3f} #30363d); "
            f"border-radius: 2px;"
        )
        self.strength_lbl.setText(
            f"{result.label}  ·  {result.entropy:.0f} bit  ·  Crack time: {result.crack_time}"
        )
        self.strength_lbl.setStyleSheet(f"color: {color}; font-size: 11px;")

    def _save(self):
        title = self.f_title.text().strip()
        pw    = self.f_pw.text()
        if not title:
            self.f_title.setFocus()
            self.f_title.setStyleSheet(
                "QLineEdit { border: 1px solid #f85149; border-radius: 6px; "
                "background: #161b22; color: #e6edf3; padding: 6px 10px; }"
            )
            return
        if not pw:
            self.f_pw.setFocus()
            return

        entry = VaultEntry(
            id=self._entry.id if self._is_edit else None,
            vault_id=self._vault_id,
            title=title,
            url=self.f_url.text().strip(),
            username=self.f_user.text().strip(),
            password=pw,
            notes=self.f_notes.toPlainText().strip(),
        )
        self.saved.emit(entry)
        self.accept()
