"""
SHA-256 Hashing Utilities for Forensic Chain of Custody

Computes cryptographic hashes for recovered files to maintain
forensic integrity and enable verification.
"""

import hashlib
from typing import Optional


def compute_sha256(data: bytes) -> str:
    """
    Compute SHA-256 hash of binary data.
    
    This hash is used for:
    - Forensic chain of custody
    - File integrity verification
    - Duplicate detection
    - Evidence documentation
    
    Args:
        data: Binary file data to hash
    
    Returns:
        Hexadecimal string representation of SHA-256 hash (64 characters)
    
    Example:
        >>> hash_value = compute_sha256(b"test data")
        >>> len(hash_value)
        64
    """
    sha256_hash = hashlib.sha256(data)
    return sha256_hash.hexdigest()


def compute_sha256_stream(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """
    Compute SHA-256 hash of a file using streaming for large files.
    
    This method is memory-efficient and suitable for large disk images
    and recovered files.
    
    Args:
        file_path: Path to file to hash
        chunk_size: Size of chunks to read (default: 8KB)
    
    Returns:
        Hexadecimal string representation of SHA-256 hash, or None if file not found
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        return None
