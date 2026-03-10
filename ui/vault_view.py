"""
Vault entries view — the central panel of ShadowVault.
Shows a searchable table of all entries with quick copy actions.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QMenu, QAbstractItemView, QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QAction, QColor, QIcon

from core.vault import VaultEntry, get_all_entries, delete_entry

try:
    import pyperclip
    _HAS_CLIP = True
except ImportError:
    _HAS_CLIP = False

_COL_TITLE    = 0
_COL_USERNAME = 1
_COL_URL      = 2
_COL_UPDATED  = 3


class VaultView(QWidget):
    """Main vault entries panel."""

    entry_selected  = pyqtSignal(int)    # entry id
    add_requested   = pyqtSignal()
    edit_requested  = pyqtSignal(int)    # entry id
    refresh_needed  = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dek: bytes | None = None
        self._entries: list[VaultEntry] = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Toolbar ─────────────────────────────────────────────
        toolbar = QFrame()
        toolbar.setStyleSheet("background: #161b22; border-bottom: 1px solid #21262d;")
        toolbar.setFixedHeight(58)
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(16, 8, 16, 8)
        tl.setSpacing(10)

        self.search = QLineEdit()
        self.search.setPlaceholderText("🔍  Search entries…")
        self.search.setFixedHeight(36)
        self.search.textChanged.connect(self._on_search)

        self.btn_add = QPushButton("+ New Entry")
        self.btn_add.setObjectName("btnPrimary")
        self.btn_add.setFixedHeight(36)
        self.btn_add.clicked.connect(self.add_requested.emit)

        tl.addWidget(self.search, 1)
        tl.addWidget(self.btn_add)
        layout.addWidget(toolbar)

        # ── Table ────────────────────────────────────────────────
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Title", "Username", "URL", "Updated"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setRowHeight(0, 44)

        layout.addWidget(self.table, 1)

        # ── Status bar ──────────────────────────────────────────
        self.status_lbl = QLabel("  0 entries")
        self.status_lbl.setStyleSheet(
            "background: #161b22; border-top: 1px solid #21262d; "
            "color: #8b949e; font-size: 12px; padding: 4px 16px;"
        )
        self.status_lbl.setFixedHeight(26)
        layout.addWidget(self.status_lbl)

        # Clipboard clear timer
        self._clip_timer = QTimer()
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self._clear_clipboard)

    # ── Public API ───────────────────────────────────────────────

    def set_dek(self, dek: bytes):
        self._dek = dek

    def refresh(self, search: str = ""):
        if not self._dek:
            return
        self._entries = get_all_entries(self._dek, search)
        self._populate_table(self._entries)

    def get_entries(self) -> list[VaultEntry]:
        return self._entries

    def select_entry_by_id(self, entry_id: int):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == entry_id:
                self.table.selectRow(row)
                break

    # ── Internal ─────────────────────────────────────────────────

    def _populate_table(self, entries: list[VaultEntry]):
        self.table.setRowCount(0)
        for e in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setRowHeight(row, 44)

            t_item = QTableWidgetItem(e.title)
            t_item.setData(Qt.ItemDataRole.UserRole, e.id)
            t_item.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))

            u_item = QTableWidgetItem(e.username or "—")
            u_item.setForeground(QColor("#8b949e"))

            url_item = QTableWidgetItem(e.url or "—")
            url_item.setForeground(QColor("#58a6ff"))

            date_str = (e.updated_at or "")[:10]
            d_item = QTableWidgetItem(date_str)
            d_item.setForeground(QColor("#6e7681"))
            d_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.table.setItem(row, _COL_TITLE,    t_item)
            self.table.setItem(row, _COL_USERNAME, u_item)
            self.table.setItem(row, _COL_URL,      url_item)
            self.table.setItem(row, _COL_UPDATED,  d_item)

        count = len(entries)
        self.status_lbl.setText(f"  {count} {'entry' if count == 1 else 'entries'}")

    def _on_search(self, text: str):
        self.refresh(text)

    def _selected_entry_id(self) -> int | None:
        rows = self.table.selectedItems()
        if not rows:
            return None
        return self.table.item(self.table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)

    def _on_double_click(self, index):
        eid = self._selected_entry_id()
        if eid:
            self.edit_requested.emit(eid)

    def _show_context_menu(self, pos):
        eid = self._selected_entry_id()
        if not eid:
            return

        entry = next((e for e in self._entries if e.id == eid), None)
        if not entry:
            return

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 4px; }"
            "QMenu::item { padding: 6px 20px; border-radius: 4px; color: #e6edf3; }"
            "QMenu::item:selected { background: #1f6feb33; color: #58a6ff; }"
        )

        copy_pw = menu.addAction("📋  Copy Password")
        copy_user = menu.addAction("📋  Copy Username")
        copy_url = menu.addAction("🔗  Copy URL")
        menu.addSeparator()
        edit_action = menu.addAction("✏  Edit Entry")
        menu.addSeparator()
        del_action = menu.addAction("🗑  Delete")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == copy_pw:
            self._copy_to_clip(entry.password, "Password")
        elif action == copy_user:
            self._copy_to_clip(entry.username, "Username")
        elif action == copy_url:
            self._copy_to_clip(entry.url, "URL")
        elif action == edit_action:
            self.edit_requested.emit(eid)
        elif action == del_action:
            self._delete_entry(eid, entry.title)

    def _copy_to_clip(self, text: str, label: str):
        if not text:
            return
        if _HAS_CLIP:
            pyperclip.copy(text)
            self.status_lbl.setText(f"  ✓ {label} copied to clipboard (clears in 30s)")
            self.status_lbl.setStyleSheet(
                "background: #161b22; border-top: 1px solid #21262d; "
                "color: #3fb950; font-size: 12px; padding: 4px 16px;"
            )
            self._clip_timer.start(30_000)

    def _clear_clipboard(self):
        if _HAS_CLIP:
            pyperclip.copy("")
        self.status_lbl.setText(f"  {len(self._entries)} entries")
        self.status_lbl.setStyleSheet(
            "background: #161b22; border-top: 1px solid #21262d; "
            "color: #8b949e; font-size: 12px; padding: 4px 16px;"
        )

    def _delete_entry(self, eid: int, title: str):
        reply = QMessageBox.question(
            self, "Delete Entry",
            f"Delete '{title}'? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            delete_entry(eid)
            self.refresh(self.search.text())
