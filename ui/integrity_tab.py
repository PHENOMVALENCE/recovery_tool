"""
Integrity Monitor Tab - Baseline creation and comparison.
"""

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QLineEdit, QPushButton, QFileDialog, QMessageBox, QProgressBar,
    QFrame
)
from PySide6.QtCore import QThread, Signal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.integrity import (
    create_baseline,
    compare_with_baseline,
    export_integrity_report,
    load_baseline
)


class IntegrityWorker(QThread):
    """Worker for baseline/compare operations."""
    
    progress = Signal(int, str)
    finished_signal = Signal(object)
    error = Signal(str)
    
    def __init__(self, mode: str, folder_path: str, baseline_path: str = None, parent=None):
        super().__init__(parent)
        self.mode = mode  # 'baseline' or 'compare'
        self.folder_path = folder_path
        self.baseline_path = baseline_path
    
    def run(self):
        try:
            if self.mode == 'baseline':
                result = create_baseline(
                    self.folder_path,
                    self.baseline_path,
                    progress_callback=lambda c, p: self.progress.emit(c, p)
                )
                self.finished_signal.emit({'action': 'baseline', 'data': result})
            else:  # compare
                result = compare_with_baseline(
                    self.folder_path,
                    self.baseline_path,
                    progress_callback=lambda c, p: self.progress.emit(c, p)
                )
                self.finished_signal.emit({'action': 'compare', 'data': result})
        except Exception as e:
            self.error.emit(str(e))


class IntegrityTab(QWidget):
    """Integrity Monitor tab widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._last_comparison = None
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Folder selection
        folder_group = QGroupBox("Monitor Folder")
        folder_layout = QHBoxLayout()
        
        self.folder_edit = QLineEdit()
        self.folder_edit.setPlaceholderText("Select folder to monitor")
        folder_layout.addWidget(self.folder_edit)
        
        folder_btn = QPushButton("Browse")
        folder_btn.clicked.connect(self._browse_folder)
        folder_layout.addWidget(folder_btn)
        
        folder_group.setLayout(folder_layout)
        layout.addWidget(folder_group)
        
        # Baseline
        baseline_group = QGroupBox("Baseline")
        baseline_layout = QVBoxLayout()
        
        bl_row = QHBoxLayout()
        self.baseline_edit = QLineEdit()
        self.baseline_edit.setPlaceholderText("Baseline JSON file path")
        bl_row.addWidget(self.baseline_edit)
        
        bl_save = QPushButton("Save As...")
        bl_save.clicked.connect(self._browse_baseline_save)
        bl_row.addWidget(bl_save)
        
        bl_load = QPushButton("Load...")
        bl_load.clicked.connect(self._browse_baseline_load)
        bl_row.addWidget(bl_load)
        baseline_layout.addLayout(bl_row)
        
        baseline_group.setLayout(baseline_layout)
        layout.addWidget(baseline_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results summary
        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #89b4fa; font-weight: bold;")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        
        # Counters frame
        self.counters_frame = QFrame()
        counters_layout = QHBoxLayout(self.counters_frame)
        self.new_label = QLabel("New: 0")
        self.modified_label = QLabel("Modified: 0")
        self.deleted_label = QLabel("Deleted: 0")
        self.unchanged_label = QLabel("Unchanged: 0")
        counters_layout.addWidget(self.new_label)
        counters_layout.addWidget(self.modified_label)
        counters_layout.addWidget(self.deleted_label)
        counters_layout.addWidget(self.unchanged_label)
        counters_layout.addStretch()
        self.counters_frame.setVisible(False)
        layout.addWidget(self.counters_frame)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.create_baseline_btn = QPushButton("Create Baseline")
        self.create_baseline_btn.setObjectName("startButton")
        self.create_baseline_btn.clicked.connect(self._create_baseline)
        
        self.compare_btn = QPushButton("Compare with Baseline")
        self.compare_btn.clicked.connect(self._compare_baseline)
        
        self.export_btn = QPushButton("Export Report (CSV)")
        self.export_btn.clicked.connect(self._export_report)
        self.export_btn.setEnabled(False)
        
        btn_layout.addWidget(self.create_baseline_btn)
        btn_layout.addWidget(self.compare_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        layout.addStretch()
    
    def _browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if path:
            self.folder_edit.setText(path)
    
    def _browse_baseline_save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Baseline As", "", "JSON (*.json)"
        )
        if path:
            self.baseline_edit.setText(path)
    
    def _browse_baseline_load(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Baseline File", "", "JSON (*.json);;All Files (*)"
        )
        if path:
            self.baseline_edit.setText(path)
    
    def _create_baseline(self):
        folder = self.folder_edit.text().strip()
        baseline_path = self.baseline_edit.text().strip()
        
        if not folder or not Path(folder).exists():
            QMessageBox.warning(self, "Validation", "Please select a valid folder.")
            return
        if not baseline_path:
            baseline_path = str(Path(folder) / "baseline.json")
            self.baseline_edit.setText(baseline_path)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.create_baseline_btn.setEnabled(False)
        
        self._worker = IntegrityWorker('baseline', folder, baseline_path)
        self._worker.finished_signal.connect(self._on_baseline_created)
        self._worker.error.connect(self._on_error)
        self._worker.start()
    
    def _on_baseline_created(self, result: dict):
        self.progress_bar.setVisible(False)
        self.create_baseline_btn.setEnabled(True)
        data = result.get('data', {})
        count = data.get('file_count', 0)
        self.summary_label.setText(f"Baseline created: {count} files recorded.")
        QMessageBox.information(
            self,
            "Baseline Created",
            f"Baseline saved with {count} files.\n\nPath: {self.baseline_edit.text()}"
        )
    
    def _compare_baseline(self):
        folder = self.folder_edit.text().strip()
        baseline_path = self.baseline_edit.text().strip()
        
        if not folder or not Path(folder).exists():
            QMessageBox.warning(self, "Validation", "Please select a valid folder.")
            return
        if not baseline_path or not Path(baseline_path).exists():
            QMessageBox.warning(self, "Validation", "Please select an existing baseline file.")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.compare_btn.setEnabled(False)
        
        self._worker = IntegrityWorker('compare', folder, baseline_path)
        self._worker.finished_signal.connect(self._on_compare_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()
    
    def _on_compare_done(self, result: dict):
        self.progress_bar.setVisible(False)
        self.compare_btn.setEnabled(True)
        
        data = result.get('data', {})
        self._last_comparison = data
        summary = data.get('summary', {})
        
        self.new_label.setText(f"New: {summary.get('new_count', 0)}")
        self.modified_label.setText(f"Modified: {summary.get('modified_count', 0)}")
        self.deleted_label.setText(f"Deleted: {summary.get('deleted_count', 0)}")
        self.unchanged_label.setText(f"Unchanged: {summary.get('unchanged_count', 0)}")
        self.counters_frame.setVisible(True)
        self.export_btn.setEnabled(True)
        
        self.summary_label.setText(
            f"Comparison complete: {summary.get('new_count', 0)} new, "
            f"{summary.get('modified_count', 0)} modified, "
            f"{summary.get('deleted_count', 0)} deleted."
        )
    
    def _export_report(self):
        if not self._last_comparison:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Integrity Report", "", "CSV (*.csv)"
        )
        if path:
            export_integrity_report(self._last_comparison, path)
            QMessageBox.information(self, "Export", f"Report saved to {path}")
    
    def _on_error(self, msg: str):
        self.progress_bar.setVisible(False)
        self.create_baseline_btn.setEnabled(True)
        self.compare_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", msg)
