"""
Password Health Check view for ShadowVault.
Analyses all vault entries for weak, duplicate, or reused passwords.
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.password_gen import check_all_health, check_strength, HealthIssue

_TYPE_META = {
    "weak":      ("🔴", "#f85149", "Weak Password"),
    "duplicate": ("🟡", "#d29922", "Reused Password"),
}


class HealthView(QWidget):
    """Panel showing a health report for all vault passwords."""

    entry_selected = pyqtSignal(int)   # emits entry id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Password Health")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6edf3;")

        self.scan_btn = QPushButton("Scan Now")
        self.scan_btn.setObjectName("btnSecondary")
        self.scan_btn.setFixedHeight(34)
        self.scan_btn.clicked.connect(self.run_scan)

        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self.scan_btn)
        layout.addLayout(hdr)

        # Summary row
        self.summary_frame = QFrame()
        self.summary_frame.setStyleSheet(
            "QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        self.summary_frame.setFixedHeight(70)
        sum_layout = QHBoxLayout(self.summary_frame)
        sum_layout.setContentsMargins(20, 0, 20, 0)

        self.stat_total  = self._stat_widget("0", "Total")
        self.stat_weak   = self._stat_widget("0", "Weak", "#f85149")
        self.stat_dupl   = self._stat_widget("0", "Reused", "#d29922")
        self.stat_ok     = self._stat_widget("0", "Healthy", "#3fb950")

        for s in [self.stat_total, self.stat_weak, self.stat_dupl, self.stat_ok]:
            sum_layout.addWidget(s)
        layout.addWidget(self.summary_frame)

        # Scroll area for issues
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        self.issues_widget = QWidget()
        self.issues_widget.setStyleSheet("background: transparent;")
        self.issues_layout = QVBoxLayout(self.issues_widget)
        self.issues_layout.setContentsMargins(0, 0, 0, 0)
        self.issues_layout.setSpacing(8)
        self.issues_layout.addStretch()

        scroll.setWidget(self.issues_widget)
        layout.addWidget(scroll, 1)

        self._show_placeholder()

    def _stat_widget(self, value: str, label: str, color: str = "#e6edf3") -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        vl = QVBoxLayout(w)
        vl.setSpacing(2)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val = QLabel(value)
        val.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        val.setStyleSheet(f"color: {color}; background: transparent;")
        val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #8b949e; font-size: 11px; background: transparent;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(val)
        vl.addWidget(lbl)
        # Store ref to val label for updating
        w._val_lbl = val
        return w

    def _show_placeholder(self):
        placeholder = QLabel("Click 'Scan Now' to check your vault's password health.")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #8b949e; font-size: 13px;")
        # Clear and add
        self._clear_issues()
        self.issues_layout.insertWidget(0, placeholder)

    def _clear_issues(self):
        while self.issues_layout.count() > 1:
            item = self.issues_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def set_entries(self, entries):
        self._entries = entries

    def run_scan(self):
        if not self._entries:
            return

        issues = check_all_health(self._entries)
        total  = len(self._entries)
        weak   = sum(1 for i in issues if i.issue_type == "weak")
        dupl   = sum(1 for i in issues if i.issue_type == "duplicate")
        # Count unique affected entries for "healthy"
        affected_ids = {i.entry_id for i in issues}
        ok = total - len(affected_ids)

        self.stat_total._val_lbl.setText(str(total))
        self.stat_weak._val_lbl.setText(str(weak))
        self.stat_dupl._val_lbl.setText(str(dupl))
        self.stat_ok._val_lbl.setText(str(ok))

        self._clear_issues()

        if not issues:
            ok_lbl = QLabel("✅  All passwords look healthy!")
            ok_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ok_lbl.setStyleSheet("color: #3fb950; font-size: 14px; padding: 20px;")
            self.issues_layout.insertWidget(0, ok_lbl)
            return

        for issue in issues:
            card = self._issue_card(issue)
            self.issues_layout.insertWidget(self.issues_layout.count() - 1, card)

    def _issue_card(self, issue: HealthIssue) -> QFrame:
        icon, color, type_label = _TYPE_META.get(issue.issue_type, ("⚪", "#8b949e", issue.issue_type))

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background: #161b22; border: 1px solid {color}44; "
            f"border-left: 3px solid {color}; border-radius: 6px; }}"
        )
        card.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("background: transparent; font-size: 18px;")
        icon_lbl.setFixedWidth(24)

        info = QVBoxLayout()
        info.setSpacing(2)

        name = QLabel(issue.entry_title)
        name.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        name.setStyleSheet("background: transparent; color: #e6edf3;")

        detail = QLabel(f"{type_label}  ·  {issue.detail}")
        detail.setStyleSheet(f"background: transparent; color: {color}; font-size: 11px;")
        detail.setWordWrap(True)

        info.addWidget(name)
        info.addWidget(detail)

        fix_btn = QPushButton("Fix →")
        fix_btn.setFixedSize(60, 28)
        fix_btn.setStyleSheet(
            f"QPushButton {{ background: {color}22; color: {color}; "
            f"border: 1px solid {color}66; border-radius: 4px; font-size: 11px; }}"
            f"QPushButton:hover {{ background: {color}44; }}"
        )
        fix_btn.clicked.connect(lambda _, eid=issue.entry_id: self.entry_selected.emit(eid))

        layout.addWidget(icon_lbl)
        layout.addLayout(info, 1)
        layout.addWidget(fix_btn)
        return card
