"""
Metadata Extraction Module

Extracts original filenames and metadata from recovered files.
Supports PDF, DOCX, and other file formats.
"""

import re
import zipfile
import io
from typing import Optional, Dict
from pathlib import Path


def extract_pdf_title(file_data: bytes) -> Optional[str]:
    """
    Extract title from PDF metadata.
    
    PDFs may contain metadata with title information.
    This function searches for /Title entries in the PDF.
    
    Args:
        file_data: Binary PDF data
    
    Returns:
        Title string if found, None otherwise
    """
    try:
        # Convert to string for searching (PDFs contain text)
        # Look for /Title entries in PDF metadata
        text = file_data[:min(8192, len(file_data))].decode('latin-1', errors='ignore')
        
        # Search for /Title( or /Title <
        title_patterns = [
            r'/Title\s*\(([^)]+)\)',
            r'/Title\s*<([^>]+)>',
            r'/Title\s*([^\s\n]+)',
        ]
        
        for pattern in title_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
                # Clean up the title
                title = title.replace('\\n', ' ').replace('\\r', ' ')
                title = re.sub(r'\s+', ' ', title)
                if title and len(title) > 0 and len(title) < 200:
                    return sanitize_filename(title)
    except Exception:
        pass
    
    return None


def extract_docx_title(file_data: bytes) -> Optional[str]:
    """
    Extract title from DOCX metadata.
    
    DOCX files are ZIP archives containing XML files.
    The title may be in core.xml (document properties).
    
    Args:
        file_data: Binary DOCX data
    
    Returns:
        Title string if found, None otherwise
    """
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(file_data))
        
        # Try to read core.xml (document properties)
        if 'docProps/core.xml' in zip_file.namelist():
            core_xml = zip_file.read('docProps/core.xml')
            text = core_xml.decode('utf-8', errors='ignore')
            
            # Look for <dc:title> tag
            title_match = re.search(r'<dc:title[^>]*>([^<]+)</dc:title>', text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                if title and len(title) > 0:
                    return sanitize_filename(title)
        
        # Alternative: Try app.xml
        if 'docProps/app.xml' in zip_file.namelist():
            app_xml = zip_file.read('docProps/app.xml')
            text = app_xml.decode('utf-8', errors='ignore')
            
            # Look for <Title> tag
            title_match = re.search(r'<Title[^>]*>([^<]+)</Title>', text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                if title and len(title) > 0:
                    return sanitize_filename(title)
                    
    except Exception:
        pass
    
    return None


def extract_xlsx_title(file_data: bytes) -> Optional[str]:
    """
    Extract title from XLSX metadata.
    
    Similar to DOCX, XLSX files contain metadata in core.xml.
    
    Args:
        file_data: Binary XLSX data
    
    Returns:
        Title string if found, None otherwise
    """
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(file_data))
        
        if 'docProps/core.xml' in zip_file.namelist():
            core_xml = zip_file.read('docProps/core.xml')
            text = core_xml.decode('utf-8', errors='ignore')
            
            title_match = re.search(r'<dc:title[^>]*>([^<]+)</dc:title>', text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                if title and len(title) > 0:
                    return sanitize_filename(title)
                    
    except Exception:
        pass
    
    return None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to be filesystem-safe.
    
    Removes or replaces invalid characters for filenames.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename safe for filesystem
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32 or char in '\n\r\t')
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Ensure it's not empty
    if not filename:
        return None
    
    return filename


def extract_original_filename(file_data: bytes, file_type: str) -> Optional[str]:
    """
    Extract original filename from file metadata.
    
    Attempts to extract title/name from various file formats.
    
    Args:
        file_data: Binary file data
        file_type: Type of file (pdf, docx, xlsx, etc.)
    
    Returns:
        Original filename if found, None otherwise
    """
    file_type_lower = file_type.lower()
    
    if file_type_lower == 'pdf':
        return extract_pdf_title(file_data)
    elif file_type_lower == 'docx':
        return extract_docx_title(file_data)
    elif file_type_lower == 'xlsx':
        return extract_xlsx_title(file_data)
    
    return None
