"""
Audit Logging Module for Forensic Chain of Custody

Implements append-only logging for recovery operations.
Logs are designed to be audit-ready and reproducible.
"""

import csv
import os
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path


class RecoveryLogger:
    """
    Forensic audit logger for recovery operations.
    
    Maintains chain of custody through append-only CSV logs.
    Each log entry records:
    - Timestamp of recovery
    - File type
    - Original byte offset
    - File size
    - SHA-256 hash
    - Verification status
    """
    
    CSV_COLUMNS = [
        'timestamp',
        'file_type',
        'offset_hex',
        'file_size',
        'sha256',
        'verification_status',
        'is_duplicate'
    ]
    
    def __init__(self, log_file_path: str):
        """
        Initialize recovery logger.
        
        Args:
            log_file_path: Path to CSV log file (will be created if it doesn't exist)
        """
        self.log_file_path = Path(log_file_path)
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Create log file with headers if it doesn't exist."""
        if not self.log_file_path.exists():
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.CSV_COLUMNS)
                writer.writeheader()
        else:
            # Check if file has old format (without is_duplicate column)
            try:
                with open(self.log_file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    if reader.fieldnames and 'is_duplicate' not in reader.fieldnames:
                        # Old format detected - we'll add the column when writing
                        pass
            except Exception:
                pass
    
    def log_recovery(self, 
                    file_type: str,
                    offset_hex: str,
                    file_size: int,
                    sha256: str,
                    verification_status: str = 'unverified') -> None:
        """
        Log a recovered file to the audit log.
        
        This is an append-only operation for forensic integrity.
        
        Args:
            file_type: Type of recovered file (e.g., 'pdf', 'docx')
            offset_hex: Hexadecimal offset where file was found (e.g., '0x1FA340')
            file_size: Size of recovered file in bytes
            sha256: SHA-256 hash of recovered file
            verification_status: Verification status ('verified', 'unverified', 'failed', or with ',duplicate')
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Extract duplicate status from verification_status
        is_duplicate = ',duplicate' in verification_status
        clean_status = verification_status.replace(',duplicate', '')
        
        log_entry = {
            'timestamp': timestamp,
            'file_type': file_type,
            'offset_hex': offset_hex,
            'file_size': file_size,
            'sha256': sha256,
            'verification_status': clean_status,
            'is_duplicate': 'Yes' if is_duplicate else 'No'
        }
        
        # Append-only write for forensic integrity
        with open(self.log_file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.CSV_COLUMNS)
            writer.writerow(log_entry)
    
    def get_log_stats(self) -> Dict[str, int]:
        """
        Get statistics from the log file.
        
        Returns:
            Dictionary with counts by file type
        """
        stats = {}
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    file_type = row['file_type']
                    stats[file_type] = stats.get(file_type, 0) + 1
        except (IOError, OSError):
            pass
        return stats
