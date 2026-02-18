"""
Reports Tab - Recovery summary and export.
"""

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QFileDialog, QMessageBox, QFormLayout, QFrame
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.reports import generate_recovery_summary, export_summary_to_csv


class ReportsTab(QWidget):
    """Reports - summary display and CSV export."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._summary = None
        self._audit_log_path = ''
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Source
        source_group = QGroupBox("Data Source")
        source_layout = QHBoxLayout()
        self.path_label = QLabel("No recovery data loaded")
        self.path_label.setStyleSheet("color: #6c7086;")
        source_layout.addWidget(self.path_label)
        
        load_btn = QPushButton("Load Summary")
        load_btn.clicked.connect(self._load_summary)
        source_layout.addWidget(load_btn)
        source_group.setLayout(source_layout)
        layout.addWidget(source_group)
        
        # Summary display
        self.summary_frame = QFrame()
        summary_layout = QFormLayout(self.summary_frame)
        
        self.total_label = QLabel("—")
        self.unique_label = QLabel("—")
        self.duplicate_label = QLabel("—")
        self.failures_label = QLabel("—")
        self.size_label = QLabel("—")
        self.by_type_label = QLabel("—")
        
        summary_layout.addRow("Total Files Recovered:", self.total_label)
        summary_layout.addRow("Unique Files:", self.unique_label)
        summary_layout.addRow("Duplicate Count:", self.duplicate_label)
        summary_layout.addRow("Verification Failures:", self.failures_label)
        summary_layout.addRow("Total Recovered Size:", self.size_label)
        summary_layout.addRow("Files by Type:", self.by_type_label)
        
        layout.addWidget(self.summary_frame)
        
        # Export
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export Summary to CSV")
        self.export_btn.clicked.connect(self._export_summary)
        self.export_btn.setEnabled(False)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        layout.addStretch()
    
    def load_from_audit_log(self, audit_log_path: str) -> None:
        """Load and display summary from audit log."""
        self._audit_log_path = audit_log_path
        self._summary = generate_recovery_summary(audit_log_path)
        self.path_label.setText(Path(audit_log_path).name)
        self.path_label.setStyleSheet("color: #a6e3a1;")
        self._update_display()
        self.export_btn.setEnabled(True)
    
    def _load_summary(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Recovery Audit Log", "",
            "CSV Files (*.csv);;All Files (*)"
        )
        if path:
            self.load_from_audit_log(path)
    
    def _update_display(self):
        if not self._summary:
            return
        
        self.total_label.setText(str(self._summary.get('total_files', 0)))
        self.unique_label.setText(str(self._summary.get('unique_files', 0)))
        self.duplicate_label.setText(str(self._summary.get('duplicate_count', 0)))
        self.failures_label.setText(str(self._summary.get('verification_failures', 0)))
        
        size_bytes = self._summary.get('total_size', 0)
        if size_bytes >= 1024 * 1024 * 1024:
            size_str = f"{size_bytes / (1024**3):.2f} GB"
        elif size_bytes >= 1024 * 1024:
            size_str = f"{size_bytes / (1024**2):.2f} MB"
        elif size_bytes >= 1024:
            size_str = f"{size_bytes / 1024:.2f} KB"
        else:
            size_str = f"{size_bytes} bytes"
        self.size_label.setText(size_str)
        
        by_type = self._summary.get('by_type', {})
        type_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items())) if by_type else "—"
        self.by_type_label.setText(type_str)
        self.by_type_label.setWordWrap(True)
    
    def _export_summary(self):
        if not self._summary:
            QMessageBox.warning(self, "No Data", "No summary to export. Load a recovery audit log first.")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Summary", "", "CSV (*.csv)"
        )
        if path:
            try:
                export_summary_to_csv(self._summary, path)
                QMessageBox.information(self, "Export", f"Summary saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))
