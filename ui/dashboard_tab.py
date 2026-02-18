"""
Dashboard Tab - Overview and quick actions.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QFrame, QGridLayout
)
from PySide6.QtCore import Qt


class DashboardTab(QWidget):
    """Welcome dashboard with overview and quick links."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        title = QLabel("Digital Forensics Recovery System")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #89b4fa;")
        layout.addWidget(title)
        
        subtitle = QLabel("Production-quality software recovery and integrity monitoring")
        subtitle.setStyleSheet("color: #6c7086; font-size: 14px;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(24)
        
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("QFrame { background-color: #313244; border-radius: 8px; }")
        frame_layout = QVBoxLayout(frame)
        
        frame_layout.addWidget(QLabel("Quick Start"))
        frame_layout.addWidget(QLabel("• Disk Recovery: Select a raw disk image (.dd, .img, .raw, .bin) and recover files by type"))
        frame_layout.addWidget(QLabel("• Results Viewer: View recovered files, search, filter, and export"))
        frame_layout.addWidget(QLabel("• Integrity Monitor: Create a baseline of a folder and compare for changes"))
        frame_layout.addWidget(QLabel("• Reports: Generate and export recovery summaries"))
        
        layout.addWidget(frame)
        layout.addStretch()
