"""
Disk Recovery Tab - File carving from disk images.
"""

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QLineEdit, QPushButton, QProgressBar, QCheckBox, QFileDialog,
    QMessageBox
)
from PySide6.QtCore import QThread, Signal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.signatures import get_signatures_by_types
from core.carver import FileCarver
from core.logger import RecoveryLogger


class CarverWorker(QThread):
    progress = Signal(int, int)
    stats_updated = Signal(int, int, int, int)
    finished_signal = Signal(dict)
    error = Signal(str)

    def __init__(self, image_path: str, output_dir: str, file_types: list, parent=None):
        super().__init__(parent)
        self.image_path = image_path
        self.output_dir = output_dir
        self.file_types = file_types
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        try:
            signatures = get_signatures_by_types(self.file_types)
            if not signatures:
                self.error.emit("No valid file types selected")
                return

            log_path = Path(self.output_dir) / 'recovery_audit_log.csv'
            logger = RecoveryLogger(str(log_path))

            carver = FileCarver(
                signatures=signatures,
                output_dir=self.output_dir,
                logger=logger,
                chunk_size=1024 * 1024
            )

            def progress_cb(bytes_processed, total_size):
                if self._stop_requested:
                    return
                self.progress.emit(bytes_processed, total_size)
                self.stats_updated.emit(
                    carver.recovered_count,
                    carver.duplicate_count,
                    0,
                    bytes_processed
                )

            stats = carver.carve(self.image_path, progress_callback=progress_cb)

            if not self._stop_requested:
                self.finished_signal.emit(stats)

        except Exception as e:
            self.error.emit(str(e))


class RecoveryTab(QWidget):
    recovery_complete = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        file_group = QGroupBox("Source")
        file_layout = QHBoxLayout()
        self.image_edit = QLineEdit()
        self.image_edit.setPlaceholderText("Select disk image (.dd, .img, .raw, .bin)")
        file_layout.addWidget(self.image_edit)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_image)
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        output_group = QGroupBox("Output Folder")
        output_layout = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select output directory")
        output_layout.addWidget(self.output_edit)
        output_btn = QPushButton("Browse")
        output_btn.clicked.connect(self._browse_output)
        output_layout.addWidget(output_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        types_group = QGroupBox("File Types to Recover")
        types_layout = QHBoxLayout()
        self.type_pdf = QCheckBox("PDF")
        self.type_pdf.setChecked(True)
        self.type_jpg = QCheckBox("JPG")
        self.type_jpg.setChecked(True)
        self.type_png = QCheckBox("PNG")
        self.type_png.setChecked(True)
        self.type_docx = QCheckBox("DOCX")
        self.type_docx.setChecked(True)
        self.type_xlsx = QCheckBox("XLSX")
        self.type_xlsx.setChecked(True)
        types_layout.addWidget(self.type_pdf)
        types_layout.addWidget(self.type_jpg)
        types_layout.addWidget(self.type_png)
        types_layout.addWidget(self.type_docx)
        types_layout.addWidget(self.type_xlsx)
        types_layout.addStretch()
        types_group.setLayout(types_layout)
        layout.addWidget(types_group)

        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        self.stats_label = QLabel("Ready")
        self.stats_label.setStyleSheet("color: #a6e3a1;")
        progress_layout.addWidget(self.stats_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Recovery")
        self.start_btn.setObjectName("startButton")
        self.start_btn.clicked.connect(self._start_recovery)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_recovery)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        layout.addStretch()

    def _browse_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            "Disk Images (*.dd *.img *.raw *.bin);;All Files (*)"
        )
        if path:
            self.image_edit.setText(path)

    def _browse_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if path:
            self.output_edit.setText(path)

    def _get_selected_types(self):
        types = []
        if self.type_pdf.isChecked():
            types.append('pdf')
        if self.type_jpg.isChecked():
            types.append('jpg')
        if self.type_png.isChecked():
            types.append('png')
        if self.type_docx.isChecked():
            types.append('docx')
        if self.type_xlsx.isChecked():
            types.append('xlsx')
        return types

    def _start_recovery(self):
        image_path = self.image_edit.text().strip()
        output_dir = self.output_edit.text().strip()
        file_types = self._get_selected_types()

        if not image_path:
            QMessageBox.warning(self, "Validation", "Please select a disk image file.")
            return
        if not Path(image_path).exists():
            QMessageBox.warning(self, "Validation", "Disk image file does not exist.")
            return
        if not output_dir:
            QMessageBox.warning(self, "Validation", "Please select an output folder.")
            return
        if not file_types:
            QMessageBox.warning(self, "Validation", "Please select at least one file type.")
            return

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.stats_label.setText("Scanning...")

        self._worker = CarverWorker(image_path, output_dir, file_types)
        self._worker.progress.connect(self._on_progress)
        self._worker.stats_updated.connect(self._on_stats)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, bytes_processed: int, total_size: int):
        if total_size > 0:
            pct = int(100 * bytes_processed / total_size)
            self.progress_bar.setMaximum(100)
            self.progress_bar.setValue(pct)

    def _on_stats(self, files_found: int, duplicates: int, errors: int, bytes_processed: int):
        size_mb = bytes_processed / (1024 * 1024)
        self.stats_label.setText(
            f"Files found: {files_found} | Duplicates: {duplicates} | Processed: {size_mb:.1f} MB"
        )

    def _on_finished(self, stats: dict):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        total = stats.get('total_recovered', 0)
        unique = stats.get('unique_files', total)
        dupes = stats.get('duplicate_files', 0)
        self.stats_label.setText(
            f"Complete: {unique} unique files recovered ({dupes} duplicates skipped)"
        )
        self.recovery_complete.emit(stats)

    def _on_error(self, msg: str):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        QMessageBox.critical(self, "Error", msg)
        self.stats_label.setText("Error occurred")

    def _stop_recovery(self):
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
