"""
Signature Library for File Type Detection

This module contains hex signatures (headers and trailers) for various file types.
Used for signature-based file carving in digital forensics.
"""

from typing import Dict, Tuple, Optional, List


class FileSignature:
    """Represents a file signature with header and optional trailer patterns."""
    
    def __init__(self, file_type: str, header: bytes, trailer: Optional[bytes] = None):
        """
        Initialize a file signature.
        
        Args:
            file_type: Human-readable file type name
            header: Hex pattern for file header (magic bytes)
            trailer: Optional hex pattern for file trailer/footer
        """
        self.file_type = file_type
        self.header = header
        self.trailer = trailer
        self.header_length = len(header)
        self.trailer_length = len(trailer) if trailer else 0
    
    def matches_header(self, data: bytes, offset: int = 0) -> bool:
        """Check if data at offset matches the header pattern."""
        if offset + self.header_length > len(data):
            return False
        return data[offset:offset + self.header_length] == self.header
    
    def find_trailer(self, data: bytes, start_offset: int) -> Optional[int]:
        """
        Find trailer pattern in data starting from start_offset.
        
        Returns:
            Offset of trailer if found, None otherwise
        """
        if not self.trailer:
            return None
        
        trailer_pos = data.find(self.trailer, start_offset)
        return trailer_pos if trailer_pos != -1 else None


# Central signature dictionary
SIGNATURES: Dict[str, FileSignature] = {
    'pdf': FileSignature(
        file_type='pdf',
        header=bytes.fromhex('25504446'),  # %PDF
        trailer=bytes.fromhex('2525454F46')  # %%EOF
    ),
    'docx': FileSignature(
        file_type='docx',
        header=bytes.fromhex('504B0304'),  # ZIP header (PK..)
        trailer=bytes.fromhex('504B0506')  # ZIP end-of-central-directory
    ),
    'xlsx': FileSignature(
        file_type='xlsx',
        header=bytes.fromhex('504B0304'),  # ZIP header (PK..)
        trailer=bytes.fromhex('504B0506')  # ZIP end-of-central-directory
    ),
    'doc': FileSignature(
        file_type='doc',
        header=bytes.fromhex('D0CF11E0'),  # Legacy MS Office (OLE2)
        trailer=None  # Legacy Office files don't have a reliable trailer
    ),
    'xls': FileSignature(
        file_type='xls',
        header=bytes.fromhex('D0CF11E0'),  # Legacy MS Office (OLE2)
        trailer=None
    ),
    'gif': FileSignature(
        file_type='gif',
        header=bytes.fromhex('47494638'),  # GIF8
        trailer=bytes.fromhex('003B')  # ; (GIF terminator)
    ),
    'jpg': FileSignature(
        file_type='jpg',
        header=bytes.fromhex('FFD8FFE0'),  # JPEG header
        trailer=bytes.fromhex('FFD9')  # JPEG trailer
    ),
    'png': FileSignature(
        file_type='png',
        header=bytes.fromhex('89504E47'),  # PNG header
        trailer=bytes.fromhex('49454E44AE426082')  # PNG IEND chunk
    ),
}


def get_signature(file_type: str) -> Optional[FileSignature]:
    """Get signature for a specific file type."""
    return SIGNATURES.get(file_type.lower())


def get_all_signatures() -> Dict[str, FileSignature]:
    """Get all available signatures."""
    return SIGNATURES.copy()


def get_signatures_by_types(requested_types: List[str]) -> Dict[str, FileSignature]:
    """
    Get signatures filtered by requested file types.
    
    Args:
        requested_types: List of file type strings (e.g., ['pdf', 'docx'])
    
    Returns:
        Dictionary of filtered signatures
    """
    if not requested_types:
        return get_all_signatures()
    
    return {ft: sig for ft, sig in SIGNATURES.items() 
            if ft.lower() in [t.lower() for t in requested_types]}


def list_available_types() -> List[str]:
    """Return list of all supported file types."""
    return list(SIGNATURES.keys())
