"""
Metadata Verification Module

Verifies internal structure of recovered files to reduce false positives.
Specifically handles ZIP-based Office files (DOCX, XLSX) and distinguishes
them from generic ZIP archives.
"""

import zipfile
import io
from typing import Optional, Tuple


def verify_office_file(file_data: bytes, expected_type: str) -> Tuple[bool, str]:
    """
    Verify that recovered file matches its claimed type through internal metadata.
    
    For ZIP-based Office files (DOCX, XLSX):
    - Opens as ZIP archive
    - Checks for required internal XML files
    - Reduces false positives from generic ZIP files
    
    Args:
        file_data: Binary data of the recovered file
        expected_type: Expected file type ('docx' or 'xlsx')
    
    Returns:
        Tuple of (is_verified: bool, status_message: str)
        Status messages:
        - 'verified': File matches expected type
        - 'unverified': Could not verify (generic ZIP or legacy format)
        - 'failed': Verification failed (corrupted or not the expected type)
    """
    expected_type = expected_type.lower()
    
    # Only verify ZIP-based Office formats
    if expected_type not in ['docx', 'xlsx']:
        return True, 'unverified'  # Legacy formats can't be easily verified
    
    # Check if it's a valid ZIP file
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(file_data))
        file_list = zip_file.namelist()
    except (zipfile.BadZipFile, IOError, OSError):
        return False, 'failed'
    
    # Verify DOCX structure
    if expected_type == 'docx':
        # DOCX must contain word/document.xml
        required_file = 'word/document.xml'
        if required_file in file_list:
            return True, 'verified'
        else:
            # Might be a generic ZIP file
            return False, 'unverified'
    
    # Verify XLSX structure
    elif expected_type == 'xlsx':
        # XLSX must contain xl/workbook.xml
        required_file = 'xl/workbook.xml'
        if required_file in file_list:
            return True, 'verified'
        else:
            # Might be a generic ZIP file
            return False, 'unverified'
    
    return False, 'failed'


def relabel_unverified_office(file_type: str, verification_status: str) -> str:
    """
    Relabel unverified Office files as generic office_zip.
    
    This helps distinguish between verified Office documents and
    generic ZIP files that happen to match the Office signature.
    
    Args:
        file_type: Original file type (docx or xlsx)
        verification_status: Verification status from verify_office_file()
    
    Returns:
        Relabeled file type ('office_zip' if unverified, original otherwise)
    """
    if verification_status == 'unverified' and file_type.lower() in ['docx', 'xlsx']:
        return 'office_zip'
    return file_type
