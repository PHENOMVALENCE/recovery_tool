"""
Dark theme stylesheet for Digital Forensics Recovery System.
"""

DARK_STYLESHEET = """
QMainWindow, QWidget, QDialog {
    background-color: #1e1e2e;
}

QTabWidget::pane {
    border: 1px solid #313244;
    border-radius: 6px;
    background-color: #181825;
    top: -1px;
}

QTabBar::tab {
    background-color: #313244;
    color: #cdd6f4;
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}

QTabBar::tab:selected {
    background-color: #45475a;
    color: #89b4fa;
}

QTabBar::tab:hover:!selected {
    background-color: #45475a;
}

QGroupBox {
    font-weight: bold;
    border: 1px solid #313244;
    border-radius: 6px;
    margin-top: 12px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 5px;
    color: #89b4fa;
}

QLabel {
    color: #cdd6f4;
}

QLineEdit, QPlainTextEdit, QTextEdit {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px;
    selection-background-color: #89b4fa;
}

QPushButton {
    background-color: #45475a;
    color: #cdd6f4;
    border: 1px solid #585b70;
    border-radius: 6px;
    padding: 8px 16px;
}

QPushButton:hover {
    background-color: #585b70;
}

QPushButton:pressed {
    background-color: #313244;
}

QPushButton:disabled {
    background-color: #313244;
    color: #6c7086;
}

QPushButton#startButton {
    background-color: #a6e3a1;
    color: #1e1e2e;
}

QPushButton#startButton:hover {
    background-color: #94e2d5;
}

QPushButton#stopButton {
    background-color: #f38ba8;
    color: #1e1e2e;
}

QPushButton#stopButton:hover {
    background-color: #fab387;
}

QProgressBar {
    border: 1px solid #313244;
    border-radius: 4px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 3px;
}

QTableWidget {
    background-color: #313244;
    alternate-background-color: #45475a;
    color: #cdd6f4;
    gridline-color: #45475a;
}

QTableWidget::item {
    padding: 4px;
}

QHeaderView::section {
    background-color: #45475a;
    color: #89b4fa;
    padding: 8px;
    border: none;
}

QComboBox {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px;
}

QCheckBox {
    color: #cdd6f4;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid #45475a;
    background-color: #313244;
}

QCheckBox::indicator:checked {
    background-color: #89b4fa;
}

QScrollBar:vertical {
    background-color: #313244;
    width: 12px;
    border-radius: 6px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #585b70;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #6c7086;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
"""
