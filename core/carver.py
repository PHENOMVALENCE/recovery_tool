"""
File Carving Engine

Implements signature-based file carving for digital forensics.
Scans raw disk images byte-by-byte to recover deleted files.
"""

import os
from typing import List, Tuple, Optional, Dict
from pathlib import Path

from .signatures import FileSignature, get_signatures_by_types
from .hasher import compute_sha256
from .verifier import verify_office_file, relabel_unverified_office


class FileCarver:
    """
    Signature-based file carving engine.
    
    Performs deep scans of disk images, detecting file headers
    and extracting complete files based on signature patterns.
    """
    
    def __init__(self, 
                 signatures: Dict[str, FileSignature],
                 output_dir: str,
                 logger,
                 chunk_size: int = 1024 * 1024):  # 1MB chunks
        """
        Initialize file carver.
        
        Args:
            signatures: Dictionary of file signatures to search for
            output_dir: Base output directory for recovered files
            logger: RecoveryLogger instance for audit logging
            chunk_size: Size of chunks to read from disk image (default: 1MB)
        """
        self.signatures = signatures
        self.output_dir = Path(output_dir)
        self.logger = logger
        self.chunk_size = chunk_size
        self.recovered_count = 0
        self.processed_bytes = 0
        
        # Create output subdirectories
        self._create_output_directories()
    
    def _create_output_directories(self):
        """Create subdirectories for each file type."""
        type_dirs = {
            'pdf': 'pdf',
            'docx': 'docx',
            'xlsx': 'xlsx',
            'doc': 'doc',
            'xls': 'xls',
            'gif': 'images',
            'jpg': 'images',
            'png': 'images',
            'office_zip': 'office_zip'
        }
        
        for file_type, subdir in type_dirs.items():
            (self.output_dir / subdir).mkdir(parents=True, exist_ok=True)
    
    def _get_output_subdir(self, file_type: str) -> Path:
        """Get output subdirectory for a file type."""
        type_map = {
            'pdf': 'pdf',
            'docx': 'docx',
            'xlsx': 'xlsx',
            'doc': 'doc',
            'xls': 'xls',
            'gif': 'images',
            'jpg': 'images',
            'png': 'images',
            'office_zip': 'office_zip'
        }
        subdir = type_map.get(file_type.lower(), 'misc')
        return self.output_dir / subdir
    
    def _save_recovered_file(self, 
                            file_data: bytes,
                            file_type: str,
                            offset: int) -> str:
        """
        Save recovered file to disk with forensic naming convention.
        
        Naming format: {file_type}_offset_{hex_offset}.{ext}
        
        Args:
            file_data: Binary file data
            file_type: Type of file
            offset: Original offset in disk image
        
        Returns:
            Path to saved file
        """
        offset_hex = f'0x{offset:X}'
        extension = file_type.lower()
        
        # Handle image extensions
        if extension == 'jpg':
            extension = 'jpg'
        elif extension == 'gif':
            extension = 'gif'
        elif extension == 'png':
            extension = 'png'
        
        subdir = self._get_output_subdir(file_type)
        filename = f"{file_type}_offset_{offset_hex}.{extension}"
        file_path = subdir / filename
        
        # Handle filename conflicts
        counter = 1
        while file_path.exists():
            filename = f"{file_type}_offset_{offset_hex}_{counter}.{extension}"
            file_path = subdir / filename
            counter += 1
        
        # Write file
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        return str(file_path)
    
    def _extract_file_with_trailer(self,
                                   image_data: bytes,
                                   signature: FileSignature,
                                   header_offset: int,
                                   max_size: int = 100 * 1024 * 1024) -> Optional[bytes]:
        """
        Extract file when trailer signature is available.
        
        Args:
            image_data: Full disk image data
            signature: File signature to match
            header_offset: Offset where header was found
            max_size: Maximum file size to prevent runaway extraction
        
        Returns:
            Extracted file data, or None if extraction fails
        """
        # Find trailer
        trailer_offset = signature.find_trailer(
            image_data, 
            header_offset + signature.header_length
        )
        
        if trailer_offset is None:
            # No trailer found - could be fragmented or corrupted
            return None
        
        # Calculate file size (include trailer)
        file_end = trailer_offset + signature.trailer_length
        file_size = file_end - header_offset
        
        # Safety check: prevent unreasonably large files
        if file_size > max_size or file_size < signature.header_length:
            return None
        
        # Extract file data
        file_data = image_data[header_offset:file_end]
        
        return file_data
    
    def _extract_file_without_trailer(self,
                                     image_data: bytes,
                                     signature: FileSignature,
                                     header_offset: int,
                                     max_size: int = 50 * 1024 * 1024) -> Optional[bytes]:
        """
        Extract file when no trailer signature is available.
        
        For files without reliable trailers (e.g., legacy DOC/XLS),
        use heuristics or size limits.
        
        Args:
            image_data: Full disk image data
            signature: File signature to match
            header_offset: Offset where header was found
            max_size: Maximum file size for files without trailers
        
        Returns:
            Extracted file data, or None if extraction fails
        """
        # For files without trailers, we need a different strategy
        # This is a simplified approach - real forensics would use more sophisticated methods
        
        # Look for next signature or use size limit
        remaining_data = image_data[header_offset:]
        
        # Try to find the start of the next file signature
        next_header_offset = len(remaining_data)
        
        # Search for any known header after current position
        search_start = signature.header_length
        search_window = min(max_size, len(remaining_data) - search_start)
        
        for sig in self.signatures.values():
            if sig.header_length > 0:
                pos = remaining_data.find(sig.header, search_start, search_start + search_window)
                if pos != -1 and pos < next_header_offset:
                    next_header_offset = pos
        
        # If no other signature found, use max_size
        if next_header_offset == len(remaining_data):
            next_header_offset = min(max_size, len(remaining_data))
        
        # Safety check
        file_size = next_header_offset
        if file_size > max_size or file_size < signature.header_length:
            return None
        
        file_data = image_data[header_offset:header_offset + file_size]
        
        return file_data
    
    def _extract_file(self,
                     image_data: bytes,
                     signature: FileSignature,
                     header_offset: int) -> Optional[bytes]:
        """
        Extract complete file from disk image.
        
        Args:
            image_data: Full disk image data
            signature: File signature matched
            header_offset: Byte offset where header was found
        
        Returns:
            Extracted file data, or None if extraction fails
        """
        if signature.trailer:
            return self._extract_file_with_trailer(image_data, signature, header_offset)
        else:
            return self._extract_file_without_trailer(image_data, signature, header_offset)
    
    def carve(self, 
             image_path: str,
             progress_callback=None) -> Dict[str, int]:
        """
        Perform file carving on disk image.
        
        Args:
            image_path: Path to disk image file
            progress_callback: Optional callback function(current_offset, total_size)
        
        Returns:
            Dictionary with recovery statistics
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Disk image not found: {image_path}")
        
        # Get file size for progress tracking
        image_size = os.path.getsize(image_path)
        self.processed_bytes = 0
        self.recovered_count = 0
        
        # Track found headers to prevent overlapping extractions
        found_files: List[Tuple[int, FileSignature]] = []
        
        # Read and scan image in chunks for memory efficiency
        with open(image_path, 'rb') as image_file:
            # For signature matching, we need to scan byte-by-byte
            # But we'll read in chunks and handle overlaps
            
            current_buffer = b''
            absolute_offset = 0
            
            while True:
                chunk = image_file.read(self.chunk_size)
                if not chunk:
                    break
                
                # Combine with previous buffer to catch signatures spanning chunks
                search_buffer = current_buffer + chunk
                current_buffer = chunk[-max(s.header_length for s in self.signatures.values()):]
                
                # Scan for headers
                for file_type, signature in self.signatures.items():
                    offset = 0
                    while True:
                        # Search for header in current search window
                        pos = search_buffer.find(signature.header, offset)
                        if pos == -1:
                            break
                        
                        # Calculate absolute offset in image
                        absolute_pos = absolute_offset - len(current_buffer) + pos
                        
                        # Check if we already found a file at this location
                        # (allow small overlap tolerance)
                        is_overlap = False
                        for found_offset, found_sig in found_files:
                            if abs(absolute_pos - found_offset) < found_sig.header_length:
                                is_overlap = True
                                break
                        
                        if not is_overlap:
                            found_files.append((absolute_pos, signature))
                        
                        offset = pos + 1
                
                absolute_offset += len(chunk)
                self.processed_bytes += len(chunk)
                
                if progress_callback:
                    progress_callback(self.processed_bytes, image_size)
            
            # Now read full image for extraction (or optimize with memory mapping)
            # For large files, we'll use chunked extraction
            image_file.seek(0)
            image_data = image_file.read()
        
        # Extract and save all found files
        for header_offset, signature in found_files:
            file_data = self._extract_file(image_data, signature, header_offset)
            
            if file_data is None:
                continue
            
            # Verify and potentially relabel
            file_type = signature.file_type
            is_verified, verification_status = verify_office_file(file_data, file_type)
            
            if not is_verified and verification_status == 'unverified':
                file_type = relabel_unverified_office(file_type, verification_status)
            
            # Compute hash
            sha256_hash = compute_sha256(file_data)
            
            # Save file
            saved_path = self._save_recovered_file(file_data, file_type, header_offset)
            
            # Log recovery
            offset_hex = f'0x{header_offset:X}'
            self.logger.log_recovery(
                file_type=file_type,
                offset_hex=offset_hex,
                file_size=len(file_data),
                sha256=sha256_hash,
                verification_status=verification_status
            )
            
            self.recovered_count += 1
        
        return {
            'total_recovered': self.recovered_count,
            'bytes_processed': self.processed_bytes
        }
