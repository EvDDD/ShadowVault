"""
Recovery Key display dialog — shown once after vault creation.
Lets the user copy the key to clipboard or acknowledge they've saved it.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QLineEdit,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

try:
    import pyperclip
    _HAS_CLIP = True
except ImportError:
    _HAS_CLIP = False


class RecoveryKeyDialog(QDialog):
    """
    Shown once after vault creation. Displays the emergency recovery key
    with a one-click copy button and a 'confirmed saved' checkbox.
    """

    def __init__(self, recovery_key: str, parent=None):
        super().__init__(parent)
        self._key = recovery_key
        self.setWindowTitle("Save Your Recovery Key — ShadowVault")
        self.setFixedSize(480, 380)
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.MSWindowsFixedSizeDialogHint
        )
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 24)
        layout.setSpacing(16)

        # ── Icon + title ─────────────────────────────────────────
        top = QHBoxLayout()
        icon = QLabel("🔑")
        icon.setStyleSheet("font-size:32px;")
        icon.setFixedWidth(50)
        top.addWidget(icon)

        titles = QVBoxLayout(); titles.setSpacing(2)
        t1 = QLabel("Emergency Recovery Key")
        t1.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t1.setStyleSheet("color:#e6edf3;")
        t2 = QLabel("Save this key in a safe place — it is shown only once.")
        t2.setStyleSheet("color:#8b949e; font-size:12px;")
        titles.addWidget(t1); titles.addWidget(t2)
        top.addLayout(titles, 1)
        layout.addLayout(top)

        # ── Key display ──────────────────────────────────────────
        key_frame = QFrame()
        key_frame.setStyleSheet(
            "QFrame{background:#161b22; border:2px solid #d29922; border-radius:8px; padding:4px;}"
        )
        kl = QVBoxLayout(key_frame); kl.setContentsMargins(16, 12, 16, 12); kl.setSpacing(8)

        key_lbl = QLabel("YOUR RECOVERY KEY")
        key_lbl.setStyleSheet("color:#d29922; font-size:10px; font-weight:700; letter-spacing:2px;")

        # Selectable read-only QLineEdit so user can also manually select+copy
        self.key_display = QLineEdit(self._key)
        self.key_display.setReadOnly(True)
        self.key_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.key_display.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        self.key_display.setStyleSheet(
            "QLineEdit{"
            "  background:transparent; border:none;"
            "  color:#f0c419; font-size:14px; letter-spacing:3px;"
            "  selection-background-color:#d29922; selection-color:#000;"
            "}"
        )
        self.key_display.setFixedHeight(38)
        self.key_display.selectAll()

        kl.addWidget(key_lbl)
        kl.addWidget(self.key_display)
        layout.addWidget(key_frame)

        # ── Copy button ──────────────────────────────────────────
        self.btn_copy = QPushButton("📋  Copy to Clipboard")
        self.btn_copy.setObjectName("btnSecondary")
        self.btn_copy.setFixedHeight(40)
        self.btn_copy.clicked.connect(self._copy)
        layout.addWidget(self.btn_copy)

        # ── Warning notice ───────────────────────────────────────
        warn = QLabel(
            "⚠  If you lose this key AND forget your master password,\n"
            "    your vault data will be permanently unrecoverable."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet(
            "color:#d29922; font-size:11px; background:#d2992218;"
            "border:1px solid #d2992244; border-radius:6px; padding:8px 10px;"
        )
        layout.addWidget(warn)

        layout.addStretch()

        # ── Confirm button ───────────────────────────────────────
        self.btn_ok = QPushButton("I've saved my Recovery Key — Continue")
        self.btn_ok.setObjectName("btnPrimary")
        self.btn_ok.setFixedHeight(42)
        self.btn_ok.clicked.connect(self.accept)
        layout.addWidget(self.btn_ok)

    def _copy(self):
        if _HAS_CLIP:
            pyperclip.copy(self._key)
            self.btn_copy.setText("✓  Copied!")
            self.btn_copy.setStyleSheet(
                "QPushButton{background:#238636; color:#fff; border:1px solid #2ea043; "
                "border-radius:6px; padding:6px 16px; font-weight:600;}"
            )
            QTimer.singleShot(2500, self._reset_copy_btn)
        else:
            # No pyperclip — select all so user can Ctrl+C manually
            self.key_display.selectAll()
            self.key_display.setFocus()
            self.btn_copy.setText("Select all — press Ctrl+C to copy")

    def _reset_copy_btn(self):
        self.btn_copy.setText("📋  Copy to Clipboard")
        self.btn_copy.setStyleSheet("")
