"""
Master Password Recovery dialog for ShadowVault.
Supports: Emergency Recovery Key | Secret Questions
"""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QMessageBox, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont

from core.recovery import (
    unlock_with_recovery_key, unlock_with_secret_questions,
    get_secret_questions, has_secret_questions,
    save_secret_questions, change_master_password,
)


# ── Background worker ─────────────────────────────────────────────
class _RecoveryWorker(QThread):
    done = pyqtSignal(object)   # bytes | None

    def __init__(self, fn, *args):
        super().__init__()
        self._fn, self._args = fn, args

    def run(self):
        self.done.emit(self._fn(*self._args))


# ── Recovery dialog ───────────────────────────────────────────────
class RecoveryDialog(QDialog):
    recovered = pyqtSignal(bytes)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Account Recovery — ShadowVault")
        self.setFixedSize(460, 500)
        self._worker = None
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
        if has_secret_questions():
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
        key_str = self.key_input.text().strip().upper()
        new_pw  = self.key_new_pw.text()
        conf    = self.key_conf.text()

        if not key_str:
            self.key_err.setText("Please enter the recovery key."); return
        if len(new_pw) < 8:
            self.key_err.setText("New password must be at least 8 characters."); return
        if new_pw != conf:
            self.key_err.setText("Passwords do not match."); return

        self._set_key_busy(True)
        self._worker = _RecoveryWorker(unlock_with_recovery_key, key_str)
        self._worker.done.connect(lambda dek: self._on_key_done(dek, new_pw))
        self._worker.start()

    def _on_key_done(self, dek, new_pw: str):
        self._set_key_busy(False)
        if dek is None:
            self.key_err.setText(
                "❌  Invalid recovery key. Check format: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
            )
            return
        change_master_password(dek, new_pw)
        QMessageBox.information(self, "Success",
            "Recovery successful. Your master password has been reset.")
        self.recovered.emit(dek)
        self.accept()

    def _set_key_busy(self, busy: bool):
        self.btn_key.setEnabled(not busy)
        self.btn_key.setText("Verifying…" if busy else "Recover with Key")
        self.key_input.setEnabled(not busy)
        self.key_new_pw.setEnabled(not busy)
        self.key_conf.setEnabled(not busy)
        if busy:
            self.key_err.setText("")

    # ── Tab 2: Secret Questions ──────────────────────────────────

    def _questions_tab(self) -> QWidget:
        w = QWidget(); w.setStyleSheet("background:transparent;")
        l = QVBoxLayout(w); l.setSpacing(8); l.setContentsMargins(0, 14, 0, 0)

        questions = get_secret_questions()
        self.answer_inputs: list[QLineEdit] = []
        for i, q in enumerate(questions):
            ql = QLabel(f"Q{i+1}: {q}")
            ql.setWordWrap(True)
            ql.setStyleSheet("color:#e6edf3; font-size:12px;")
            ai = QLineEdit(); ai.setPlaceholderText("Your answer")
            ai.setFixedHeight(34)
            self.answer_inputs.append(ai)
            l.addWidget(ql); l.addWidget(ai)

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

        l.addStretch()
        self.btn_q = QPushButton("Recover with Answers")
        self.btn_q.setObjectName("btnPrimary")
        self.btn_q.setFixedHeight(40)
        self.btn_q.clicked.connect(self._do_question_recovery)
        l.addWidget(self.btn_q)
        return w

    def _do_question_recovery(self):
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
        self._worker = _RecoveryWorker(unlock_with_secret_questions, answers)
        self._worker.done.connect(lambda dek: self._on_q_done(dek, new_pw))
        self._worker.start()

    def _on_q_done(self, dek, new_pw: str):
        self.btn_q.setEnabled(True)
        self.btn_q.setText("Recover with Answers")
        if dek is None:
            self.q_err.setText("❌  Incorrect answers. Access denied."); return
        change_master_password(dek, new_pw)
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
    def __init__(self, dek: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Secret Questions — ShadowVault")
        self.setFixedSize(480, 560)
        self._dek = dek
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
            "Set 3 security questions as a backup recovery method.\n"
            "Answers are case-insensitive."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#8b949e; font-size:12px;")
        layout.addWidget(sub)

        default_questions = [
            "What was the name of your first pet?",
            "What city were you born in?",
            "What is your mother's maiden name?",
        ]
        self.pairs: list[tuple[QLineEdit, QLineEdit]] = []
        for i in range(3):
            ql = QLabel(f"Question {i + 1}")
            ql.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600;")
            q_in = QLineEdit(default_questions[i]); q_in.setFixedHeight(34)

            al = QLabel("Answer")
            al.setStyleSheet("color:#8b949e; font-size:12px; font-weight:600;")
            a_in = QLineEdit(); a_in.setPlaceholderText("Your answer"); a_in.setFixedHeight(34)

            self.pairs.append((q_in, a_in))
            layout.addWidget(ql); layout.addWidget(q_in)
            layout.addWidget(al); layout.addWidget(a_in)

        self.err = QLabel("")
        self.err.setStyleSheet("color:#f85149; font-size:12px;")
        layout.addWidget(self.err)
        layout.addStretch()

        btn_row = QHBoxLayout()
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
        save = QPushButton("Save Questions")
        save.setObjectName("btnPrimary"); save.setFixedHeight(40)
        save.clicked.connect(self._save)
        btn_row.addWidget(cancel); btn_row.addWidget(save)
        layout.addLayout(btn_row)

    def _save(self):
        qa = []
        for q_in, a_in in self.pairs:
            q, a = q_in.text().strip(), a_in.text().strip()
            if not q or not a:
                self.err.setText("All questions and answers must be filled in."); return
            qa.append((q, a))
        save_secret_questions(self._dek, qa)
        QMessageBox.information(self, "Saved", "Secret questions saved successfully.")
        self.accept()
