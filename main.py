#!/usr/bin/env python3
"""
Digital Forensics Recovery System

Entry point for the application.
"""

import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Digital Forensics Recovery System")
    app.setOrganizationName("Forensics")
    
    # High DPI scaling (deprecated in Qt6 - Qt handles this automatically)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
