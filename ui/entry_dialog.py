"""
Add / Edit Vault Entry dialog for ShadowVault.
Uses QScrollArea so the password generator never gets clipped.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QFrame, QSlider, QCheckBox,
    QWidget, QScrollArea,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.vault import VaultEntry
from core.password_gen import generate_password, check_strength

try:
    import pyperclip
    _HAS_CLIP = True
except ImportError:
    _HAS_CLIP = False


class EntryDialog(QDialog):
    saved = pyqtSignal(VaultEntry)

    def __init__(self, entry: VaultEntry | None = None, vault_id: int = 1, parent=None):
        super().__init__(parent)
        self._entry    = entry
        self._vault_id = vault_id
        self._is_edit  = entry is not None
        self.setWindowTitle("Edit Entry" if self._is_edit else "New Entry")
        self.setMinimumSize(500, 580)
        self.resize(520, 680)
        self._build_ui()
        if self._is_edit:
            self._populate()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        hdr = QFrame()
        hdr.setStyleSheet("background:#161b22; border-bottom:1px solid #30363d;")
        hdr.setFixedHeight(50)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(20, 0, 20, 0)
        lbl = QLabel("Edit Entry" if self._is_edit else "New Entry")
        lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl.setStyleSheet("color:#58a6ff; background:transparent;")
        hl.addWidget(lbl)
        root.addWidget(hdr)

        # Scroll area wraps all form fields
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea{background:#0d1117;border:none;}")

        body = QWidget()
        body.setStyleSheet("background:#0d1117;")
        form = QVBoxLayout(body)
        form.setContentsMargins(20, 14, 20, 14)
        form.setSpacing(4)

        def add_field(label, widget):
            form.addWidget(self._lbl(label))
            form.addWidget(widget)
            form.addSpacing(6)

        self.f_title = self._input("e.g. Gmail")
        add_field("Entry Title *", self.f_title)

        self.f_url = self._input("https://")
        add_field("URL / Website", self.f_url)

        self.f_user = self._input("username@example.com")
        add_field("Username / Email", self.f_user)

        # Password + toggle + copy
        form.addWidget(self._lbl("Password *"))
        pw_row = QHBoxLayout(); pw_row.setSpacing(6)
        self.f_pw = QLineEdit()
        self.f_pw.setPlaceholderText("Enter or generate a password")
        self.f_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.f_pw.setFixedHeight(36)
        self.f_pw.textChanged.connect(self._on_pw_changed)

        self.btn_eye = QPushButton("👁")
        self.btn_eye.setFixedSize(45, 36)
        self.btn_eye.setCheckable(True)
        self.btn_eye.setToolTip("Show/hide")
        self.btn_eye.toggled.connect(
            lambda on: self.f_pw.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))

        btn_copy_pw = QPushButton("📋")
        btn_copy_pw.setFixedSize(45, 36)
        btn_copy_pw.setToolTip("Copy password")
        btn_copy_pw.clicked.connect(self._copy_pw)

        pw_row.addWidget(self.f_pw)
        pw_row.addWidget(self.btn_eye)
        pw_row.addWidget(btn_copy_pw)
        form.addLayout(pw_row)

        # Strength indicator
        self.strength_bar = QFrame()
        self.strength_bar.setFixedHeight(4)
        self.strength_bar.setStyleSheet("background:#30363d; border-radius:2px;")
        form.addWidget(self.strength_bar)
        self.strength_lbl = QLabel("")
        self.strength_lbl.setStyleSheet("color:#8b949e; font-size:11px;")
        form.addWidget(self.strength_lbl)
        form.addSpacing(10)

        # Generator box
        gen = QFrame()
        gen.setStyleSheet(
            "QFrame{background:#161b22; border:1px solid #30363d; border-radius:8px;}"
        )
        gl = QVBoxLayout(gen)
        gl.setContentsMargins(14, 10, 14, 12)
        gl.setSpacing(8)

        gh = QHBoxLayout()
        gtitle = QLabel("Password Generator")
        gtitle.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600; background:transparent;")
        self.btn_gen = QPushButton("⚡ Generate")
        self.btn_gen.setObjectName("btnSecondary")
        self.btn_gen.setFixedHeight(28)
        self.btn_gen.clicked.connect(self._generate)
        gh.addWidget(gtitle); gh.addStretch(); gh.addWidget(self.btn_gen)
        gl.addLayout(gh)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#30363d; background:#30363d;"); sep.setFixedHeight(1)
        gl.addWidget(sep)

        lr = QHBoxLayout(); lr.setSpacing(8)
        ll = QLabel("Length:"); ll.setFixedWidth(48)
        ll.setStyleSheet("color:#8b949e; font-size:12px; background:transparent;")
        self.len_slider = QSlider(Qt.Orientation.Horizontal)
        self.len_slider.setRange(8, 64); self.len_slider.setValue(20)
        self.len_val = QLabel("20"); self.len_val.setFixedWidth(22)
        self.len_val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.len_val.setStyleSheet("color:#e6edf3; font-size:12px; font-weight:600; background:transparent;")
        self.len_slider.valueChanged.connect(lambda v: self.len_val.setText(str(v)))
        lr.addWidget(ll); lr.addWidget(self.len_slider); lr.addWidget(self.len_val)
        gl.addLayout(lr)

        cr = QHBoxLayout(); cr.setSpacing(4)
        self.cb_upper   = self._cb("A–Z",  True)
        self.cb_lower   = self._cb("a–z",  True)
        self.cb_digits  = self._cb("0–9",  True)
        self.cb_symbols = self._cb("!@#",  True)
        for cb in [self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols]:
            cr.addWidget(cb)
        gl.addLayout(cr)
        form.addWidget(gen)
        form.addSpacing(10)

        # Notes
        form.addWidget(self._lbl("Notes"))
        self.f_notes = QTextEdit()
        self.f_notes.setPlaceholderText("Optional notes…")
        self.f_notes.setFixedHeight(68)
        form.addWidget(self.f_notes)
        form.addStretch()

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        # Footer buttons (always visible, outside scroll)
        foot = QFrame()
        foot.setStyleSheet("background:#161b22; border-top:1px solid #30363d;")
        foot.setFixedHeight(56)
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(20, 0, 20, 0); fl.setSpacing(10)
        self.err_lbl = QLabel("")
        self.err_lbl.setStyleSheet("color:#f85149; font-size:12px;")
        fl.addWidget(self.err_lbl, 1)
        btn_cancel = QPushButton("Cancel"); btn_cancel.setFixedHeight(34)
        btn_cancel.clicked.connect(self.reject)
        btn_save = QPushButton("Save Entry")
        btn_save.setObjectName("btnPrimary"); btn_save.setFixedHeight(34); btn_save.setFixedWidth(100)
        btn_save.clicked.connect(self._save)
        fl.addWidget(btn_cancel); fl.addWidget(btn_save)
        root.addWidget(foot)

    def _lbl(self, text):
        l = QLabel(text)
        l.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600;")
        return l

    def _input(self, ph):
        e = QLineEdit(); e.setPlaceholderText(ph); e.setFixedHeight(36); return e

    def _cb(self, text, checked=True):
        cb = QCheckBox(text); cb.setChecked(checked)
        cb.setStyleSheet("QCheckBox{background:transparent;color:#e6edf3;font-size:12px;padding:2px 4px;}")
        return cb

    def _populate(self):
        e = self._entry
        self.f_title.setText(e.title); self.f_url.setText(e.url)
        self.f_user.setText(e.username); self.f_pw.setText(e.password)
        self.f_notes.setPlainText(e.notes)

    def _on_pw_changed(self, text):
        if not text:
            self.strength_bar.setStyleSheet("background:#30363d; border-radius:2px;")
            self.strength_lbl.setText(""); return
        r = check_strength(text)
        pct = (r.score + 1) * 20
        stop = min(pct / 100 + 0.001, 1.0)
        self.strength_bar.setStyleSheet(
            f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:{pct/100:.3f} {r.color},stop:{stop:.3f} #30363d);border-radius:2px;")
        self.strength_lbl.setText(f"{r.label}  ·  {r.entropy:.0f} bit  ·  Crack: {r.crack_time}")
        self.strength_lbl.setStyleSheet(f"color:{r.color};font-size:11px;")

    def _generate(self):
        pw = generate_password(
            length=self.len_slider.value(),
            use_upper=self.cb_upper.isChecked(), use_lower=self.cb_lower.isChecked(),
            use_digits=self.cb_digits.isChecked(), use_symbols=self.cb_symbols.isChecked(),
        )
        self.f_pw.setText(pw)
        self.f_pw.setEchoMode(QLineEdit.EchoMode.Normal)
        self.btn_eye.setChecked(True)

    def _copy_pw(self):
        pw = self.f_pw.text()
        if pw and _HAS_CLIP:
            pyperclip.copy(pw)

    def _save(self):
        title = self.f_title.text().strip()
        pw    = self.f_pw.text()
        if not title:
            self.err_lbl.setText("Title is required."); self.f_title.setFocus(); return
        if not pw:
            self.err_lbl.setText("Password is required."); self.f_pw.setFocus(); return
        self.err_lbl.setText("")
        self.saved.emit(VaultEntry(
            id=self._entry.id if self._is_edit else None,
            vault_id=self._vault_id, title=title,
            url=self.f_url.text().strip(), username=self.f_user.text().strip(),
            password=pw, notes=self.f_notes.toPlainText().strip(),
        ))
        self.accept()
