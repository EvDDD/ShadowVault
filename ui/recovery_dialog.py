"""
Master Password Recovery dialog for ShadowVault.
Supports: Emergency Recovery Key | Secret Questions
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QScrollArea, QFrame,
    QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.vault import (
    unlock_with_recovery_key, unlock_with_secret_questions,
    get_secret_questions, has_secret_questions,
    change_master_password,
)
from core.vault import save_secret_questions


class RecoveryDialog(QDialog):
    """Unlock via Recovery Key or Secret Questions, then reset master password."""

    recovered = pyqtSignal(bytes)  # emits dek on success

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Recover Access — ShadowVault")
        self.setFixedSize(460, 520)
        self._dek: bytes | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Account Recovery")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        sub = QLabel(
            "Use one of the recovery methods below to regain access.\n"
            "You will be asked to set a new master password."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(sub)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_key_tab(), "🔑  Recovery Key")

        questions = get_secret_questions()
        if questions:
            self.tabs.addTab(self._build_questions_tab(questions), "❓  Secret Questions")

        layout.addWidget(self.tabs, 1)

    # ── Tab 1: Recovery Key ──────────────────────────────────────

    def _build_key_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        lbl = QLabel("Emergency Recovery Key")
        lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX")
        self.key_input.setFixedHeight(38)

        self.key_error = QLabel("")
        self.key_error.setStyleSheet("color: #f85149; font-size: 12px;")

        new_pw_lbl = QLabel("New Master Password")
        new_pw_lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.key_new_pw = QLineEdit()
        self.key_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_new_pw.setPlaceholderText("New master password")
        self.key_new_pw.setFixedHeight(38)

        conf_lbl = QLabel("Confirm New Password")
        conf_lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.key_conf_pw = QLineEdit()
        self.key_conf_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_conf_pw.setPlaceholderText("Confirm new master password")
        self.key_conf_pw.setFixedHeight(38)

        btn = QPushButton("Recover with Key")
        btn.setObjectName("btnPrimary")
        btn.setFixedHeight(40)
        btn.clicked.connect(self._do_key_recovery)

        layout.addWidget(lbl)
        layout.addWidget(self.key_input)
        layout.addWidget(self.key_error)
        layout.addWidget(new_pw_lbl)
        layout.addWidget(self.key_new_pw)
        layout.addWidget(conf_lbl)
        layout.addWidget(self.key_conf_pw)
        layout.addStretch()
        layout.addWidget(btn)
        return w

    def _do_key_recovery(self):
        key_str   = self.key_input.text().strip()
        new_pw    = self.key_new_pw.text()
        conf_pw   = self.key_conf_pw.text()

        if not key_str:
            self.key_error.setText("Please enter the recovery key.")
            return
        if not new_pw or len(new_pw) < 8:
            self.key_error.setText("New password must be at least 8 characters.")
            return
        if new_pw != conf_pw:
            self.key_error.setText("Passwords do not match.")
            return

        dek = unlock_with_recovery_key(key_str)
        if dek is None:
            self.key_error.setText("Invalid recovery key. Please check and try again.")
            return

        change_master_password(dek, new_pw)
        self.recovered.emit(dek)
        QMessageBox.information(self, "Recovery Successful",
            "Your master password has been reset successfully.")
        self.accept()

    # ── Tab 2: Secret Questions ──────────────────────────────────

    def _build_questions_tab(self, questions: list[str]) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 16, 0, 0)

        self.answer_inputs: list[QLineEdit] = []

        for i, q in enumerate(questions):
            q_lbl = QLabel(f"Q{i+1}: {q}")
            q_lbl.setWordWrap(True)
            q_lbl.setStyleSheet("color: #e6edf3; font-size: 12px;")

            a_input = QLineEdit()
            a_input.setPlaceholderText("Your answer")
            a_input.setFixedHeight(36)
            self.answer_inputs.append(a_input)

            layout.addWidget(q_lbl)
            layout.addWidget(a_input)

        self.q_error = QLabel("")
        self.q_error.setStyleSheet("color: #f85149; font-size: 12px;")
        layout.addWidget(self.q_error)

        new_pw_lbl = QLabel("New Master Password")
        new_pw_lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.q_new_pw = QLineEdit()
        self.q_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.q_new_pw.setPlaceholderText("New master password")
        self.q_new_pw.setFixedHeight(38)

        conf_lbl = QLabel("Confirm New Password")
        conf_lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        self.q_conf_pw = QLineEdit()
        self.q_conf_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.q_conf_pw.setPlaceholderText("Confirm new master password")
        self.q_conf_pw.setFixedHeight(38)

        btn = QPushButton("Recover with Answers")
        btn.setObjectName("btnPrimary")
        btn.setFixedHeight(40)
        btn.clicked.connect(self._do_question_recovery)

        layout.addWidget(new_pw_lbl)
        layout.addWidget(self.q_new_pw)
        layout.addWidget(conf_lbl)
        layout.addWidget(self.q_conf_pw)
        layout.addStretch()
        layout.addWidget(btn)
        return w

    def _do_question_recovery(self):
        answers  = [inp.text() for inp in self.answer_inputs]
        new_pw   = self.q_new_pw.text()
        conf_pw  = self.q_conf_pw.text()

        if any(not a.strip() for a in answers):
            self.q_error.setText("Please answer all questions.")
            return
        if not new_pw or len(new_pw) < 8:
            self.q_error.setText("New password must be at least 8 characters.")
            return
        if new_pw != conf_pw:
            self.q_error.setText("Passwords do not match.")
            return

        dek = unlock_with_secret_questions(answers)
        if dek is None:
            self.q_error.setText("Incorrect answers. Access denied.")
            return

        change_master_password(dek, new_pw)
        self.recovered.emit(dek)
        QMessageBox.information(self, "Recovery Successful",
            "Your master password has been reset successfully.")
        self.accept()


class SetQuestionsDialog(QDialog):
    """Setup/edit secret questions (accessible from settings)."""

    def __init__(self, dek: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Secret Questions — ShadowVault")
        self.setFixedSize(480, 580)
        self._dek = dek
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Secret Questions Setup")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        sub = QLabel(
            "Set at least 3 security questions. These can be used as a\n"
            "backup recovery method if you lose your Recovery Key."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(sub)

        self.pairs: list[tuple[QLineEdit, QLineEdit]] = []
        default_questions = [
            "What was the name of your first pet?",
            "What city were you born in?",
            "What is your mother's maiden name?",
        ]
        for i in range(3):
            q_label = QLabel(f"Question {i+1}")
            q_label.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
            q_input = QLineEdit(default_questions[i])
            q_input.setFixedHeight(36)

            a_label = QLabel("Answer")
            a_label.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
            a_input = QLineEdit()
            a_input.setPlaceholderText("Your answer (case-insensitive)")
            a_input.setFixedHeight(36)

            self.pairs.append((q_input, a_input))
            layout.addWidget(q_label)
            layout.addWidget(q_input)
            layout.addWidget(a_label)
            layout.addWidget(a_input)

        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet("color: #f85149; font-size: 12px;")
        layout.addWidget(self.error_lbl)

        layout.addStretch()

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

    def _save(self):
        qa = []
        for q_in, a_in in self.pairs:
            q = q_in.text().strip()
            a = a_in.text().strip()
            if not q or not a:
                self.error_lbl.setText("All questions and answers must be filled in.")
                return
            qa.append((q, a))

        save_secret_questions(self._dek, qa)
        QMessageBox.information(self, "Saved", "Secret questions have been saved.")
        self.accept()
