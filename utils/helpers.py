"""
Helper Utilities

Miscellaneous helper functions for the recovery tool.
"""

import os
import sys
from pathlib import Path
from typing import List


def print_banner():
    """Print ASCII banner for the tool."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║         Software Recovery Tool (Cybersecurity-Grade)         ║
║                  Digital Forensics & File Carving            ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def format_bytes(size: int) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        size: Size in bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def validate_image_file(image_path: str) -> bool:
    """
    Validate that image file exists and is readable.
    
    Args:
        image_path: Path to disk image
    
    Returns:
        True if valid, False otherwise
    """
    path = Path(image_path)
    if not path.exists():
        print(f"[-] Error: Image file not found: {image_path}", file=sys.stderr)
        return False
    
    if not path.is_file():
        print(f"[-] Error: Path is not a file: {image_path}", file=sys.stderr)
        return False
    
    if not os.access(image_path, os.R_OK):
        print(f"[-] Error: Cannot read image file: {image_path}", file=sys.stderr)
        return False
    
    return True


def parse_file_types(types_string: str) -> List[str]:
    """
    Parse comma-separated file types string.
    
    Args:
        types_string: Comma-separated list (e.g., "pdf,docx,jpg")
    
    Returns:
        List of file type strings
    """
    if not types_string:
        return []
    
    return [t.strip().lower() for t in types_string.split(',') if t.strip()]


def ensure_output_directory(output_dir: str) -> bool:
    """
    Ensure output directory exists and is writable.
    
    Args:
        output_dir: Path to output directory
    
    Returns:
        True if successful, False otherwise
    """
    try:
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        
        # Test write permission
        test_file = path / '.write_test'
        test_file.touch()
        test_file.unlink()
        
        return True
    except (OSError, PermissionError) as e:
        print(f"[-] Error: Cannot create output directory: {output_dir}", file=sys.stderr)
        print(f"[-] {str(e)}", file=sys.stderr)
        return False
