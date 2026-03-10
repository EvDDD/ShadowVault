"""
Steganography dialog for ShadowVault.
Hide the encrypted vault database inside a PNG image, or extract it back.
"""
from __future__ import annotations
import os
import shutil
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QFileDialog, QProgressBar,
    QMessageBox, QFrame,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap

from core.steganography import hide, unhide, estimate_capacity, image_size_ok
from db.schema import DB_PATH


class WorkerThread(QThread):
    finished = pyqtSignal(bool, str)

    def __init__(self, fn, *args):
        super().__init__()
        self._fn = fn
        self._args = args

    def run(self):
        try:
            self._fn(*self._args)
            self.finished.emit(True, "")
        except Exception as e:
            self.finished.emit(False, str(e))


class StegoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Steganography — ShadowVault")
        self.setFixedSize(520, 560)
        self._worker: WorkerThread | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Steganography Module")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        sub = QLabel(
            "Hide your encrypted vault inside a PNG image (Cover Image → Stego Image),\n"
            "or extract the vault back from a Stego Image."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(sub)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_hide_tab(), "🖼  Hide (Embed)")
        self.tabs.addTab(self._build_unhide_tab(), "📤  Unhide (Extract)")
        layout.addWidget(self.tabs, 1)

    # ── Hide tab ─────────────────────────────────────────────────

    def _build_hide_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        # Cover image picker
        layout.addWidget(self._lbl("Cover Image (PNG)"))
        cover_row = QHBoxLayout()
        self.cover_path = QLineEdit()
        self.cover_path.setPlaceholderText("Select a PNG file…")
        self.cover_path.setReadOnly(True)
        self.cover_path.setFixedHeight(36)
        cover_row.addWidget(self.cover_path)
        browse_cover = QPushButton("Browse")
        browse_cover.setFixedHeight(36)
        browse_cover.clicked.connect(self._pick_cover)
        cover_row.addWidget(browse_cover)
        layout.addLayout(cover_row)

        # Capacity info
        self.cap_lbl = QLabel("")
        self.cap_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(self.cap_lbl)

        # Output path
        layout.addWidget(self._lbl("Output Stego Image"))
        out_row = QHBoxLayout()
        self.out_path = QLineEdit()
        self.out_path.setPlaceholderText("Choose output path…")
        self.out_path.setReadOnly(True)
        self.out_path.setFixedHeight(36)
        out_row.addWidget(self.out_path)
        browse_out = QPushButton("Browse")
        browse_out.setFixedHeight(36)
        browse_out.clicked.connect(self._pick_output)
        out_row.addWidget(browse_out)
        layout.addLayout(out_row)

        # DB path info
        db_info = QLabel(f"Vault DB: {DB_PATH}")
        db_info.setWordWrap(True)
        db_info.setStyleSheet("color: #6e7681; font-size: 11px;")
        layout.addWidget(db_info)

        self.hide_progress = QProgressBar()
        self.hide_progress.setRange(0, 0)
        self.hide_progress.setVisible(False)
        self.hide_progress.setFixedHeight(6)
        layout.addWidget(self.hide_progress)

        self.hide_status = QLabel("")
        self.hide_status.setStyleSheet("font-size: 12px;")
        self.hide_status.setWordWrap(True)
        layout.addWidget(self.hide_status)

        layout.addStretch()

        self.hide_btn = QPushButton("Embed Vault into Image")
        self.hide_btn.setObjectName("btnPrimary")
        self.hide_btn.setFixedHeight(42)
        self.hide_btn.clicked.connect(self._do_hide)
        layout.addWidget(self.hide_btn)
        return w

    def _pick_cover(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "PNG Images (*.png);;All Files (*)"
        )
        if path:
            self.cover_path.setText(path)
            try:
                cap = estimate_capacity(path)
                db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
                self.cap_lbl.setText(
                    f"Image capacity: {cap:,} bytes  |  Vault DB size: {db_size:,} bytes  "
                    + ("✓ OK" if cap >= db_size else "✗ Image too small!")
                )
                self.cap_lbl.setStyleSheet(
                    f"color: {'#3fb950' if cap >= db_size else '#f85149'}; font-size: 11px;"
                )
            except Exception as e:
                self.cap_lbl.setText(f"Error reading image: {e}")

    def _pick_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Stego Image", "stego_vault.png", "PNG Images (*.png)"
        )
        if path:
            if not path.endswith(".png"):
                path += ".png"
            self.out_path.setText(path)

    def _do_hide(self):
        cover = self.cover_path.text()
        output = self.out_path.text()

        if not cover or not os.path.exists(cover):
            self.hide_status.setText("⚠  Please select a valid cover image.")
            self.hide_status.setStyleSheet("color: #d29922; font-size: 12px;")
            return
        if not output:
            self.hide_status.setText("⚠  Please select an output path.")
            self.hide_status.setStyleSheet("color: #d29922; font-size: 12px;")
            return
        if not DB_PATH.exists():
            self.hide_status.setText("⚠  Vault database not found.")
            self.hide_status.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        payload = DB_PATH.read_bytes()
        if not image_size_ok(cover, len(payload)):
            self.hide_status.setText("✗  Image too small to embed the vault. Use a larger image.")
            self.hide_status.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        self.hide_btn.setEnabled(False)
        self.hide_progress.setVisible(True)
        self.hide_status.setText("Embedding…")
        self.hide_status.setStyleSheet("color: #8b949e; font-size: 12px;")

        self._worker = WorkerThread(hide, cover, payload, output)
        self._worker.finished.connect(self._on_hide_done)
        self._worker.start()

    def _on_hide_done(self, ok: bool, err: str):
        self.hide_progress.setVisible(False)
        self.hide_btn.setEnabled(True)
        if ok:
            self.hide_status.setText(f"✓  Vault embedded successfully!\n→ {self.out_path.text()}")
            self.hide_status.setStyleSheet("color: #3fb950; font-size: 12px;")
        else:
            self.hide_status.setText(f"✗  Error: {err}")
            self.hide_status.setStyleSheet("color: #f85149; font-size: 12px;")

    # ── Unhide tab ───────────────────────────────────────────────

    def _build_unhide_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        layout.addWidget(self._lbl("Stego Image (PNG)"))
        stego_row = QHBoxLayout()
        self.stego_path = QLineEdit()
        self.stego_path.setPlaceholderText("Select the stego PNG file…")
        self.stego_path.setReadOnly(True)
        self.stego_path.setFixedHeight(36)
        stego_row.addWidget(self.stego_path)
        browse_stego = QPushButton("Browse")
        browse_stego.setFixedHeight(36)
        browse_stego.clicked.connect(self._pick_stego)
        stego_row.addWidget(browse_stego)
        layout.addLayout(stego_row)

        warn = QLabel(
            "⚠  Extracting will overwrite the current vault database.\n"
            "Make sure you have a backup before proceeding."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet(
            "color: #d29922; font-size: 11px; background: #d2992211; "
            "border: 1px solid #d2992244; border-radius: 4px; padding: 8px;"
        )
        layout.addWidget(warn)

        self.unhide_progress = QProgressBar()
        self.unhide_progress.setRange(0, 0)
        self.unhide_progress.setVisible(False)
        self.unhide_progress.setFixedHeight(6)
        layout.addWidget(self.unhide_progress)

        self.unhide_status = QLabel("")
        self.unhide_status.setStyleSheet("font-size: 12px;")
        self.unhide_status.setWordWrap(True)
        layout.addWidget(self.unhide_status)

        layout.addStretch()

        self.unhide_btn = QPushButton("Extract Vault from Image")
        self.unhide_btn.setObjectName("btnDanger")
        self.unhide_btn.setFixedHeight(42)
        self.unhide_btn.clicked.connect(self._do_unhide)
        layout.addWidget(self.unhide_btn)
        return w

    def _pick_stego(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "PNG Images (*.png);;All Files (*)"
        )
        if path:
            self.stego_path.setText(path)

    def _do_unhide(self):
        stego = self.stego_path.text()
        if not stego or not os.path.exists(stego):
            self.unhide_status.setText("⚠  Please select a valid stego image.")
            self.unhide_status.setStyleSheet("color: #d29922; font-size: 12px;")
            return

        reply = QMessageBox.question(
            self, "Confirm Extract",
            "This will overwrite the current vault database. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.unhide_btn.setEnabled(False)
        self.unhide_progress.setVisible(True)
        self.unhide_status.setText("Extracting…")
        self.unhide_status.setStyleSheet("color: #8b949e; font-size: 12px;")

        self._worker = WorkerThread(self._extract_and_restore, stego)
        self._worker.finished.connect(self._on_unhide_done)
        self._worker.start()

    def _extract_and_restore(self, stego: str):
        payload = unhide(stego)
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        DB_PATH.write_bytes(payload)

    def _on_unhide_done(self, ok: bool, err: str):
        self.unhide_progress.setVisible(False)
        self.unhide_btn.setEnabled(True)
        if ok:
            self.unhide_status.setText(
                "✓  Vault extracted successfully!\nPlease restart ShadowVault to unlock."
            )
            self.unhide_status.setStyleSheet("color: #3fb950; font-size: 12px;")
        else:
            self.unhide_status.setText(f"✗  Error: {err}")
            self.unhide_status.setStyleSheet("color: #f85149; font-size: 12px;")

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        return l
