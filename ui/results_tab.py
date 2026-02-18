"""
Results Viewer Tab - Display and manage recovered files.
"""

import sys
import csv
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLineEdit, QPushButton, QHeaderView, QFileDialog, QMessageBox,
    QAbstractItemView
)
from PySide6.QtCore import Qt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.reports import load_recovery_results


class ResultsTab(QWidget):
    """Results Viewer - sortable table with search, filter, export."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._results: list = []
        self._filtered: list = []
        self._audit_log_path: str = ''
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by name, type, offset, SHA-256...")
        self.search_edit.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_edit)
        
        load_btn = QPushButton("Load Results")
        load_btn.clicked.connect(self._load_results)
        toolbar.addWidget(load_btn)
        
        open_btn = QPushButton("Open File Location")
        open_btn.clicked.connect(self._open_file_location)
        toolbar.addWidget(open_btn)
        
        export_btn = QPushButton("Export Selected")
        export_btn.clicked.connect(self._export_selected)
        toolbar.addWidget(export_btn)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "File Name", "Type", "Offset", "Size", "SHA-256", "Verified", "Duplicate"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
    
    def load_from_audit_log(self, audit_log_path: str) -> None:
        """Load results from audit log path (e.g. output_dir/recovery_audit_log.csv)."""
        self._audit_log_path = audit_log_path
        self._results = load_recovery_results(audit_log_path)
        self._apply_filter()
    
    def _load_results(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Recovery Audit Log", "",
            "CSV Files (*.csv);;All Files (*)"
        )
        if path:
            self.load_from_audit_log(path)
    
    def _apply_filter(self):
        q = self.search_edit.text().strip().lower()
        if not q:
            self._filtered = self._results
        else:
            self._filtered = [
                r for r in self._results
                if q in r.get('file_name', '').lower()
                or q in r.get('type', '').lower()
                or q in r.get('offset', '').lower()
                or q in r.get('sha256', '').lower()
            ]
        self._populate_table()
    
    def _populate_table(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self._filtered))
        
        for row_idx, r in enumerate(self._filtered):
            name_item = QTableWidgetItem(r.get('file_name', ''))
            name_item.setData(Qt.UserRole, row_idx)  # Store index for selection mapping
            self.table.setItem(row_idx, 0, name_item)
            self.table.setItem(row_idx, 1, QTableWidgetItem(r.get('type', '')))
            self.table.setItem(row_idx, 2, QTableWidgetItem(r.get('offset', '')))
            size_item = QTableWidgetItem(str(r.get('size', 0)))
            size_item.setData(Qt.UserRole, r.get('size', 0))
            self.table.setItem(row_idx, 3, size_item)
            self.table.setItem(row_idx, 4, QTableWidgetItem(r.get('sha256', '')[:16] + '...' if len(r.get('sha256', '')) > 16 else r.get('sha256', '')))
            self.table.setItem(row_idx, 5, QTableWidgetItem('Yes' if r.get('verified') else 'No'))
            self.table.setItem(row_idx, 6, QTableWidgetItem('Yes' if r.get('duplicate') else 'No'))
        
        self.table.setSortingEnabled(True)
    
    def _open_file_location(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection", "Please select a row first.")
            return
        
        idx = self._table_row_to_result_idx(row)
        if idx is None or idx >= len(self._filtered):
            return
        
        r = self._filtered[idx]
        file_path = r.get('file_path', '')
        if not file_path or not Path(file_path).exists():
            QMessageBox.warning(
                self, "File Not Found",
                f"Could not locate file:\n{file_path or 'No path'}"
            )
            return
        
        try:
            import subprocess
            import platform
            path_obj = Path(file_path)
            if platform.system() == 'Windows':
                subprocess.run(['explorer', '/select,', str(path_obj.resolve())], check=False)
            elif platform.system() == 'Darwin':
                subprocess.run(['open', '-R', str(path_obj)], check=False)
            else:
                subprocess.run(['xdg-open', str(path_obj.parent)], check=False)
        except Exception as e:
            QMessageBox.warning(self, "Open Failed", str(e))
    
    def _table_row_to_result_idx(self, row: int):
        """Map table row to index in _filtered using stored UserRole."""
        name_item = self.table.item(row, 0)
        if not name_item:
            return None
        idx = name_item.data(Qt.UserRole)
        if idx is not None and 0 <= idx < len(self._filtered):
            return idx
        return None
    
    def _get_selected_result_indices(self):
        indices = set()
        for row in self.table.selectionModel().selectedRows():
            idx = self._table_row_to_result_idx(row.row())
            if idx is not None:
                indices.add(idx)
        return list(indices)
    
    def _export_selected(self):
        indices = self._get_selected_result_indices()
        if not indices:
            QMessageBox.information(self, "No Selection", "Please select one or more rows to export.")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Selected to CSV", "", "CSV (*.csv)"
        )
        if not path:
            return
        
        rows_to_export = [self._filtered[i] for i in sorted(indices)]
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['file_name', 'type', 'offset', 'size', 'sha256', 'verified', 'duplicate', 'file_path'], extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows_to_export)
            QMessageBox.information(self, "Export", f"Exported {len(rows_to_export)} rows to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
