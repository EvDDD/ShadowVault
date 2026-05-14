"""
Master Password Recovery dialog for ShadowVault.
Supports: Emergency Recovery Key | Secret Questions
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QMessageBox, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.recovery import (
    unlock_with_recovery_key, unlock_with_secret_questions,
    get_secret_questions, has_secret_questions,
    save_secret_questions, change_master_password,
)



# ── Recovery dialog ───────────────────────────────────────────────
class RecoveryDialog(QDialog):
    recovered = pyqtSignal(bytes)

    def __init__(self, parent=None, vault_id: int = None):
        super().__init__(parent)
        self._vault_id = vault_id
        self.setWindowTitle("Account Recovery — ShadowVault")
        self.setFixedSize(480, 650)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Account Recovery")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color:#58a6ff;")
        layout.addWidget(title)

        sub = QLabel(
            "Use one of the methods below to regain access.\n"
            "You will set a new master password after verification."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#8b949e; font-size:12px;")
        layout.addWidget(sub)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._key_tab(), "🔑  Recovery Key")
        if has_secret_questions(vault_id=self._vault_id):
            self.tabs.addTab(self._questions_tab(), "❓  Secret Questions")
        layout.addWidget(self.tabs, 1)

    # ── Tab 1: Recovery Key ──────────────────────────────────────

    def _key_tab(self) -> QWidget:
        w = QWidget(); w.setStyleSheet("background:transparent;")
        l = QVBoxLayout(w); l.setSpacing(10); l.setContentsMargins(0, 14, 0, 0)

        l.addWidget(self._lbl("Emergency Recovery Key"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX")
        self.key_input.setFixedHeight(36)
        self.key_input.setFont(QFont("Consolas", 11))
        l.addWidget(self.key_input)

        hint = QLabel("Format: 4 groups of 8 hex characters separated by dashes")
        hint.setStyleSheet("color:#6e7681; font-size:11px;")
        l.addWidget(hint)

        self.key_err = QLabel("")
        self.key_err.setStyleSheet("color:#f85149; font-size:12px;")
        self.key_err.setWordWrap(True)
        l.addWidget(self.key_err)

        l.addWidget(self._lbl("New Master Password"))
        self.key_new_pw = QLineEdit()
        self.key_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_new_pw.setPlaceholderText("At least 8 characters")
        self.key_new_pw.setFixedHeight(36)
        l.addWidget(self.key_new_pw)

        l.addWidget(self._lbl("Confirm New Password"))
        self.key_conf = QLineEdit()
        self.key_conf.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_conf.setPlaceholderText("Confirm new password")
        self.key_conf.setFixedHeight(36)
        self.key_conf.returnPressed.connect(self._do_key_recovery)
        l.addWidget(self.key_conf)

        l.addStretch()

        self.btn_key = QPushButton("Recover with Key")
        self.btn_key.setObjectName("btnPrimary")
        self.btn_key.setFixedHeight(40)
        self.btn_key.clicked.connect(self._do_key_recovery)
        l.addWidget(self.btn_key)
        return w

    def _do_key_recovery(self):
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtGui import QCursor
        from PyQt6.QtCore import Qt
        key_str = self.key_input.text().strip().upper()
        new_pw  = self.key_new_pw.text()
        conf    = self.key_conf.text()

        if not key_str:
            self.key_err.setText("Please enter the recovery key."); return
        if len(new_pw) < 8:
            self.key_err.setText("New password must be at least 8 characters."); return
        if new_pw != conf:
            self.key_err.setText("Passwords do not match."); return

        self.btn_key.setEnabled(False)
        self.btn_key.setText("Verifying…")
        self.key_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()
        try:
            dek = unlock_with_recovery_key(key_str, vault_id=self._vault_id)
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_key.setEnabled(True)
            self.btn_key.setText("Recover with Key")

        if dek is None:
            self.key_err.setText(
                "❌  Invalid recovery key. Check format: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
            )
            return
        change_master_password(dek, new_pw, vault_id=self._vault_id)
        QMessageBox.information(self, "Success",
            "Recovery successful. Your master password has been reset.")
        self.recovered.emit(dek)
        self.accept()

    # ── Tab 2: Secret Questions ──────────────────────────────────

    def _questions_tab(self) -> QWidget:
        from PyQt6.QtWidgets import QScrollArea
        w = QWidget(); w.setStyleSheet("background:transparent;")
        l = QVBoxLayout(w); l.setSpacing(8); l.setContentsMargins(0, 14, 0, 0)

        # ── Scrollable Q&A list ──
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        qa_widget = QWidget()
        qa_widget.setStyleSheet("background: transparent;")
        qa_layout = QVBoxLayout(qa_widget)
        qa_layout.setContentsMargins(0, 0, 0, 0)
        qa_layout.setSpacing(6)

        questions = get_secret_questions(vault_id=self._vault_id)
        self.answer_inputs: list[QLineEdit] = []
        for i, q in enumerate(questions):
            ql = QLabel(f"Q{i+1}: {q}")
            ql.setWordWrap(True)
            ql.setStyleSheet("color:#e6edf3; font-size:12px;")
            ai = QLineEdit(); ai.setPlaceholderText("Your answer")
            ai.setFixedHeight(34)
            self.answer_inputs.append(ai)
            qa_layout.addWidget(ql); qa_layout.addWidget(ai)
        qa_layout.addStretch()

        scroll.setWidget(qa_widget)
        l.addWidget(scroll, 1)

        self.q_err = QLabel("")
        self.q_err.setStyleSheet("color:#f85149; font-size:12px;")
        self.q_err.setWordWrap(True)
        l.addWidget(self.q_err)

        l.addWidget(self._lbl("New Master Password"))
        self.q_new_pw = QLineEdit()
        self.q_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.q_new_pw.setPlaceholderText("At least 8 characters")
        self.q_new_pw.setFixedHeight(36)
        l.addWidget(self.q_new_pw)

        l.addWidget(self._lbl("Confirm New Password"))
        self.q_conf = QLineEdit()
        self.q_conf.setEchoMode(QLineEdit.EchoMode.Password)
        self.q_conf.setPlaceholderText("Confirm new password")
        self.q_conf.setFixedHeight(36)
        l.addWidget(self.q_conf)

        self.btn_q = QPushButton("Recover with Answers")
        self.btn_q.setObjectName("btnPrimary")
        self.btn_q.setFixedHeight(40)
        self.btn_q.clicked.connect(self._do_question_recovery)
        l.addWidget(self.btn_q)
        return w

    def _do_question_recovery(self):
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtGui import QCursor
        from PyQt6.QtCore import Qt
        answers = [inp.text() for inp in self.answer_inputs]
        new_pw  = self.q_new_pw.text()
        conf    = self.q_conf.text()

        if any(not a.strip() for a in answers):
            self.q_err.setText("Please answer all questions."); return
        if len(new_pw) < 8:
            self.q_err.setText("New password must be at least 8 characters."); return
        if new_pw != conf:
            self.q_err.setText("Passwords do not match."); return

        self.btn_q.setEnabled(False)
        self.btn_q.setText("Verifying…")
        self.q_err.setText("")
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        QApplication.processEvents()
        try:
            dek = unlock_with_secret_questions(answers, vault_id=self._vault_id)
        finally:
            QApplication.restoreOverrideCursor()
            self.btn_q.setEnabled(True)
            self.btn_q.setText("Recover with Answers")

        if dek is None:
            self.q_err.setText("❌  Incorrect answers. Access denied."); return
        change_master_password(dek, new_pw, vault_id=self._vault_id)
        QMessageBox.information(self, "Success",
            "Recovery successful. Your master password has been reset.")
        self.recovered.emit(dek)
        self.accept()

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600;")
        return l


# ── SetQuestionsDialog ────────────────────────────────────────────
class SetQuestionsDialog(QDialog):
    _MIN_QUESTIONS = 3

    def __init__(self, dek: bytes, parent=None, vault_id: int = None):
        super().__init__(parent)
        self.setWindowTitle("Set Secret Questions — ShadowVault")
        self.setMinimumSize(500, 520)
        self.resize(500, 600)
        self._dek = dek
        self._vault_id = vault_id
        self._rows: list[dict] = []          # each: {frame, q_input, a_input, remove_btn}
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("Secret Questions Setup")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title.setStyleSheet("color:#58a6ff;")
        layout.addWidget(title)

        sub = QLabel(
            "Set at least 3 security questions as a backup recovery method.\n"
            "You can add more questions for extra security. Answers are case-insensitive."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#8b949e; font-size:12px;")
        layout.addWidget(sub)

        # ── Scrollable area for Q&A rows ──
        from PyQt6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        self._rows_container = QWidget()
        self._rows_container.setStyleSheet("background: transparent;")
        self._rows_layout = QVBoxLayout(self._rows_container)
        self._rows_layout.setContentsMargins(0, 0, 0, 0)
        self._rows_layout.setSpacing(10)
        self._rows_layout.addStretch()

        scroll.setWidget(self._rows_container)
        layout.addWidget(scroll, 1)

        # ── Add Question button ──
        self.add_btn = QPushButton("➕  Add Question")
        self.add_btn.setFixedHeight(34)
        self.add_btn.setStyleSheet(
            "QPushButton { background: #21262d; color: #58a6ff; border: 1px dashed #30363d; "
            "border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #30363d; border-color: #58a6ff; }"
        )
        self.add_btn.clicked.connect(lambda _: self._add_row())
        layout.addWidget(self.add_btn)

        # ── Error label ──
        self.err = QLabel("")
        self.err.setStyleSheet("color:#f85149; font-size:12px;")
        self.err.setWordWrap(True)
        layout.addWidget(self.err)

        # ── Buttons ──
        btn_row = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Save Questions")
        save.setObjectName("btnPrimary")
        save.setFixedHeight(40)
        save.clicked.connect(self._save)
        btn_row.addWidget(cancel)
        btn_row.addWidget(save)
        layout.addLayout(btn_row)

        # ── Pre-fill with existing questions or add 3 empty rows ──
        from core.recovery import get_secret_questions
        existing = get_secret_questions(vault_id=self._vault_id)
        if existing:
            for q_text in existing:
                self._add_row(question=q_text)
        else:
            for _ in range(self._MIN_QUESTIONS):
                self._add_row()

    def _add_row(self, question: str = ""):
        idx = len(self._rows) + 1

        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 6px; }"
        )
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(12, 10, 12, 10)
        fl.setSpacing(6)

        # Header row: label + remove button
        header = QHBoxLayout()
        num_lbl = QLabel(f"Question {idx}")
        num_lbl.setStyleSheet("color:#e6edf3; font-size:12px; font-weight:600; background:transparent; border:none;")
        remove_btn = QPushButton("Remove")
        remove_btn.setFixedHeight(26)
        remove_btn.setStyleSheet(
            "QPushButton { background: #f8514922; color: #f85149; "
            "border: 1px solid #f8514966; border-radius: 4px; "
            "font-size: 11px; padding: 2px 8px; }"
            "QPushButton:hover { background: #f8514944; }"
        )
        header.addWidget(num_lbl)
        header.addStretch()
        header.addWidget(remove_btn)
        fl.addLayout(header)

        # Question input
        q_input = QLineEdit(question)
        q_input.setPlaceholderText("Enter your question")
        q_input.setFixedHeight(34)
        q_input.setStyleSheet("background:#0d1117; border:1px solid #30363d; border-radius:4px; color:#e6edf3; padding:4px 8px;")
        fl.addWidget(q_input)

        # Answer input
        a_lbl = QLabel("Answer")
        a_lbl.setStyleSheet("color:#8b949e; font-size:11px; background:transparent; border:none;")
        fl.addWidget(a_lbl)
        a_input = QLineEdit()
        a_input.setPlaceholderText("Your answer")
        a_input.setFixedHeight(34)
        a_input.setStyleSheet("background:#0d1117; border:1px solid #30363d; border-radius:4px; color:#e6edf3; padding:4px 8px;")
        fl.addWidget(a_input)

        row_data = {
            "frame": frame,
            "num_lbl": num_lbl,
            "q_input": q_input,
            "a_input": a_input,
            "remove_btn": remove_btn,
        }
        self._rows.append(row_data)

        # Insert before the stretch at the end
        self._rows_layout.insertWidget(self._rows_layout.count() - 1, frame)

        remove_btn.clicked.connect(lambda _, rd=row_data: self._remove_row(rd))
        self._update_remove_buttons()

    def _remove_row(self, row_data: dict):
        if len(self._rows) <= self._MIN_QUESTIONS:
            return
        self._rows.remove(row_data)
        row_data["frame"].deleteLater()
        self._renumber()
        self._update_remove_buttons()

    def _renumber(self):
        for i, row in enumerate(self._rows):
            row["num_lbl"].setText(f"Question {i + 1}")

    def _update_remove_buttons(self):
        can_remove = len(self._rows) > self._MIN_QUESTIONS
        for row in self._rows:
            row["remove_btn"].setVisible(can_remove)

    def _save(self):
        qa = []
        for row in self._rows:
            q = row["q_input"].text().strip()
            a = row["a_input"].text().strip()
            if not q or not a:
                self.err.setText("All questions and answers must be filled in.")
                return
            qa.append((q, a))
        if len(qa) < self._MIN_QUESTIONS:
            self.err.setText(f"At least {self._MIN_QUESTIONS} questions are required.")
            return
        save_secret_questions(self._dek, qa, vault_id=self._vault_id)
        QMessageBox.information(self, "Saved", "Secret questions saved successfully.")
        self.accept()

