"""
Main Window - Tab-based application shell.
"""

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ui.theme import DARK_STYLESHEET
from ui.dashboard_tab import DashboardTab
from ui.recovery_tab import RecoveryTab
from ui.results_tab import ResultsTab
from ui.integrity_tab import IntegrityTab
from ui.reports_tab import ReportsTab


class MainWindow(QMainWindow):
    """Main application window with tabs."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Forensics Recovery System")
        self.setMinimumSize(900, 600)
        self.resize(1100, 700)
        self.setStyleSheet(DARK_STYLESHEET)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        self.tabs = QTabWidget()
        
        self.dashboard_tab = DashboardTab()
        self.recovery_tab = RecoveryTab()
        self.results_tab = ResultsTab()
        self.integrity_tab = IntegrityTab()
        self.reports_tab = ReportsTab()
        
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.recovery_tab, "Disk Recovery")
        self.tabs.addTab(self.results_tab, "Results Viewer")
        self.tabs.addTab(self.integrity_tab, "Integrity Monitor")
        self.tabs.addTab(self.reports_tab, "Reports")
        
        self.recovery_tab.recovery_complete.connect(self._on_recovery_complete)
        
        layout.addWidget(self.tabs)
    
    def _on_recovery_complete(self, stats: dict):
        """When recovery finishes, refresh Results and Reports from the output directory."""
        # stats doesn't include output_dir; we get it from the recovery tab
        output_dir = self.recovery_tab.output_edit.text().strip()
        if output_dir:
            audit_path = str(Path(output_dir) / "recovery_audit_log.csv")
            if Path(audit_path).exists():
                self.results_tab.load_from_audit_log(audit_path)
                self.reports_tab.load_from_audit_log(audit_path)
                self.tabs.setCurrentWidget(self.results_tab)
