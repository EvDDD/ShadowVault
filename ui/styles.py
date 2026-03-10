"""
Dark theme stylesheet for ShadowVault.
"""

DARK_STYLESHEET = """
/* ── Base ───────────────────────────────────────────────── */
QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QMainWindow, QDialog {
    background-color: #0d1117;
}

/* ── Buttons ────────────────────────────────────────────── */
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 16px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #58a6ff;
}
QPushButton:pressed {
    background-color: #161b22;
}
QPushButton#btnPrimary {
    background-color: #238636;
    border-color: #2ea043;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#btnPrimary:hover {
    background-color: #2ea043;
}
QPushButton#btnDanger {
    background-color: #da3633;
    border-color: #f85149;
    color: #ffffff;
}
QPushButton#btnDanger:hover {
    background-color: #f85149;
}
QPushButton#btnSecondary {
    background-color: #1f6feb;
    border-color: #388bfd;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#btnSecondary:hover {
    background-color: #388bfd;
}

/* ── Inputs ─────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e6edf3;
    selection-background-color: #1f6feb;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #58a6ff;
    background-color: #0d1117;
}
QLineEdit:disabled {
    color: #6e7681;
    background-color: #161b22;
}

/* ── Labels ─────────────────────────────────────────────── */
QLabel {
    color: #e6edf3;
}
QLabel#labelMuted {
    color: #8b949e;
    font-size: 12px;
}
QLabel#labelTitle {
    font-size: 18px;
    font-weight: 700;
    color: #58a6ff;
}
QLabel#labelSection {
    font-size: 12px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Table ──────────────────────────────────────────────── */
QTableWidget {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    gridline-color: #21262d;
    alternate-background-color: #0d1117;
}
QTableWidget::item {
    padding: 8px 12px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #1f6feb33;
    color: #e6edf3;
}
QTableWidget::item:hover {
    background-color: #21262d;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    border-bottom: 1px solid #30363d;
    padding: 8px 12px;
    font-weight: 600;
    font-size: 12px;
}

/* ── ScrollBar ──────────────────────────────────────────── */
QScrollBar:vertical {
    background: #0d1117;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #58a6ff;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #0d1117;
    height: 8px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #30363d;
    border-radius: 4px;
}

/* ── Sidebar ────────────────────────────────────────────── */
QListWidget {
    background-color: #161b22;
    border: none;
    border-right: 1px solid #21262d;
    padding: 8px 0;
}
QListWidget::item {
    padding: 10px 16px;
    border-radius: 6px;
    margin: 2px 8px;
    color: #8b949e;
    font-weight: 500;
}
QListWidget::item:hover {
    background-color: #21262d;
    color: #e6edf3;
}
QListWidget::item:selected {
    background-color: #1f6feb22;
    color: #58a6ff;
}

/* ── GroupBox ───────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #8b949e;
    font-size: 12px;
}

/* ── ComboBox ───────────────────────────────────────────── */
QComboBox {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e6edf3;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background-color: #21262d;
    border: 1px solid #30363d;
    selection-background-color: #1f6feb;
}

/* ── Slider ─────────────────────────────────────────────── */
QSlider::groove:horizontal {
    height: 4px;
    background: #30363d;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #58a6ff;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}
QSlider::sub-page:horizontal {
    background: #1f6feb;
    border-radius: 2px;
}

/* ── CheckBox ───────────────────────────────────────────── */
QCheckBox {
    color: #e6edf3;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #30363d;
    border-radius: 4px;
    background: #21262d;
}
QCheckBox::indicator:checked {
    background: #1f6feb;
    border-color: #388bfd;
}

/* ── Tabs ───────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #30363d;
    border-radius: 6px;
}
QTabBar::tab {
    background: #161b22;
    color: #8b949e;
    border: 1px solid #30363d;
    border-bottom: none;
    padding: 8px 16px;
    border-radius: 6px 6px 0 0;
}
QTabBar::tab:selected {
    background: #0d1117;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}
QTabBar::tab:hover:!selected {
    color: #e6edf3;
}

/* ── ToolTip ────────────────────────────────────────────── */
QToolTip {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 4px 8px;
}

/* ── ProgressBar ────────────────────────────────────────── */
QProgressBar {
    border: 1px solid #30363d;
    border-radius: 4px;
    background: #21262d;
    text-align: center;
    color: #e6edf3;
    font-size: 11px;
}
QProgressBar::chunk {
    border-radius: 4px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #1f6feb, stop:1 #58a6ff);
}

/* ── Splitter ───────────────────────────────────────────── */
QSplitter::handle {
    background: #21262d;
    width: 1px;
}

/* ── Menu ───────────────────────────────────────────────── */
QMenuBar {
    background: #161b22;
    border-bottom: 1px solid #21262d;
}
QMenuBar::item {
    padding: 6px 12px;
    color: #8b949e;
}
QMenuBar::item:selected {
    background: #21262d;
    color: #e6edf3;
}
QMenu {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}
QMenu::item:selected {
    background: #1f6feb33;
    color: #58a6ff;
}
QMenu::separator {
    height: 1px;
    background: #30363d;
    margin: 4px 0;
}

/* ── StatusBar ──────────────────────────────────────────── */
QStatusBar {
    background: #161b22;
    border-top: 1px solid #21262d;
    color: #8b949e;
    font-size: 12px;
}
"""

# Strength bar colors by score
STRENGTH_COLORS = {
    0: "#f85149",
    1: "#d29922",
    2: "#e3b341",
    3: "#3fb950",
    4: "#58a6ff",
}
