"""
Live File System Scanner

Scans live folders and drives to detect files and check for alterations.
Compares current file state with baseline to identify changes.
Collects comprehensive file properties and metadata.
"""

import os
import hashlib
import stat
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import json


class FileIntegrityRecord:
    """Record of comprehensive file information."""
    
    def __init__(self, file_path: str, size: int, sha256: str, 
                 modified_time: float, created_time: float = None,
                 accessed_time: float = None, extension: str = None,
                 file_type: str = None, permissions: str = None,
                 owner: str = None, attributes: str = None,
                 is_readonly: bool = False, is_hidden: bool = False,
                 is_system: bool = False):
        self.file_path = file_path
        self.size = size
        self.sha256 = sha256
        self.modified_time = modified_time
        self.created_time = created_time
        self.accessed_time = accessed_time
        self.extension = extension
        self.file_type = file_type
        self.permissions = permissions
        self.owner = owner
        self.attributes = attributes
        self.is_readonly = is_readonly
        self.is_hidden = is_hidden
        self.is_system = is_system
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'file_path': self.file_path,
            'size': self.size,
            'sha256': self.sha256,
            'modified_time': self.modified_time,
            'created_time': self.created_time,
            'accessed_time': self.accessed_time,
            'extension': self.extension,
            'file_type': self.file_type,
            'permissions': self.permissions,
            'owner': self.owner,
            'attributes': self.attributes,
            'is_readonly': self.is_readonly,
            'is_hidden': self.is_hidden,
            'is_system': self.is_system,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'FileIntegrityRecord':
        """Create from dictionary."""
        return cls(
            file_path=data['file_path'],
            size=data['size'],
            sha256=data['sha256'],
            modified_time=data['modified_time'],
            created_time=data.get('created_time')
        )


class LiveFileScanner:
    """
    Scanner for live file systems (folders and drives).
    
    Scans directories and files, computes hashes, and can detect
    alterations by comparing against a baseline.
    """
    
    def __init__(self, target_path: str, logger=None):
        """
        Initialize live file scanner.
        
        Args:
            target_path: Path to folder or drive to scan
            logger: Optional logger for audit trail
        """
        self.target_path = Path(target_path)
        if not self.target_path.exists():
            raise FileNotFoundError(f"Path does not exist: {target_path}")
        
        self.logger = logger
        self.scanned_files: List[FileIntegrityRecord] = []
        self.altered_files: List[Dict] = []
        self.new_files: List[FileIntegrityRecord] = []
        self.deleted_files: List[str] = []
        
    def compute_file_hash(self, file_path: Path, chunk_size: int = 8192) -> Optional[str]:
        """
        Compute SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read
        
        Returns:
            SHA-256 hash as hex string, or None if error
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
        except (IOError, OSError, PermissionError):
            return None
    
    def get_file_info(self, file_path: Path) -> Optional[Dict]:
        """
        Get comprehensive file information including size, timestamps, permissions, and attributes.
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary with file info, or None if error
        """
        try:
            file_stat = file_path.stat()
            
            # Basic info
            info = {
                'size': file_stat.st_size,
                'modified_time': file_stat.st_mtime,
                'created_time': getattr(file_stat, 'st_birthtime', file_stat.st_ctime) if hasattr(file_stat, 'st_birthtime') else file_stat.st_ctime,
                'accessed_time': file_stat.st_atime,
                'extension': file_path.suffix.lower(),
            }
            
            # File type detection
            info['file_type'] = self._detect_file_type(file_path)
            
            # Permissions (Unix-style)
            if platform.system() != 'Windows':
                info['permissions'] = oct(file_stat.st_mode)[-3:]
                try:
                    import pwd
                    info['owner'] = pwd.getpwuid(file_stat.st_uid).pw_name
                except:
                    info['owner'] = str(file_stat.st_uid)
            else:
                # Windows permissions
                info['permissions'] = self._get_windows_permissions(file_path)
                try:
                    import win32security
                    sd = win32security.GetFileSecurity(str(file_path), win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    info['owner'] = win32security.LookupAccountSid(None, owner_sid)[0]
                except ImportError:
                    info['owner'] = 'Unknown (pywin32 not installed)'
                except:
                    info['owner'] = 'Unknown'
            
            # File attributes (Windows)
            if platform.system() == 'Windows':
                try:
                    import win32api
                    import win32con
                    attrs = win32api.GetFileAttributes(str(file_path))
                    info['is_readonly'] = bool(attrs & win32con.FILE_ATTRIBUTE_READONLY)
                    info['is_hidden'] = bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN)
                    info['is_system'] = bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM)
                    info['attributes'] = self._format_windows_attributes(attrs)
                except ImportError:
                    # pywin32 not installed, use basic detection
                    info['is_readonly'] = not os.access(file_path, os.W_OK)
                    info['is_hidden'] = file_path.name.startswith('.')
                    info['is_system'] = False
                    info['attributes'] = 'Basic (pywin32 not installed)'
                except:
                    info['is_readonly'] = not os.access(file_path, os.W_OK)
                    info['is_hidden'] = file_path.name.startswith('.')
                    info['is_system'] = False
                    info['attributes'] = 'Unknown'
            else:
                # Unix attributes
                mode = file_stat.st_mode
                info['is_readonly'] = not (mode & stat.S_IWRITE)
                info['is_hidden'] = file_path.name.startswith('.')
                info['is_system'] = False
                info['attributes'] = self._format_unix_mode(mode)
            
            return info
        except (OSError, PermissionError) as e:
            return None
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type from extension and magic bytes."""
        extension = file_path.suffix.lower()
        
        # Try to read magic bytes for type detection
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            # Check common file signatures
            if header.startswith(b'%PDF'):
                return 'PDF Document'
            elif header.startswith(b'PK\x03\x04'):
                if extension in ['.docx', '.xlsx', '.pptx']:
                    return f'Microsoft Office ({extension[1:].upper()})'
                return 'ZIP Archive'
            elif header.startswith(b'\xd0\xcf\x11\xe0'):
                return 'Microsoft Office (Legacy)'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'JPEG Image'
            elif header.startswith(b'\x89PNG'):
                return 'PNG Image'
            elif header.startswith(b'GIF8'):
                return 'GIF Image'
            elif header.startswith(b'BM'):
                return 'Bitmap Image'
            elif header.startswith(b'RIFF') and b'WEBP' in header:
                return 'WebP Image'
        except:
            pass
        
        # Fallback to extension-based detection
        type_map = {
            '.pdf': 'PDF Document',
            '.doc': 'Microsoft Word (Legacy)',
            '.docx': 'Microsoft Word',
            '.xls': 'Microsoft Excel (Legacy)',
            '.xlsx': 'Microsoft Excel',
            '.ppt': 'Microsoft PowerPoint (Legacy)',
            '.pptx': 'Microsoft PowerPoint',
            '.txt': 'Text File',
            '.html': 'HTML Document',
            '.htm': 'HTML Document',
            '.xml': 'XML Document',
            '.json': 'JSON File',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.bmp': 'Bitmap Image',
            '.mp3': 'MP3 Audio',
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.exe': 'Executable',
            '.dll': 'Dynamic Link Library',
            '.py': 'Python Script',
            '.js': 'JavaScript',
            '.css': 'CSS Stylesheet',
        }
        
        return type_map.get(extension, f'Unknown ({extension or "no extension"})')
    
    def _get_windows_permissions(self, file_path: Path) -> str:
        """Get Windows file permissions as string."""
        try:
            import win32security
            sd = win32security.GetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl:
                return f"{dacl.GetAceCount()} ACEs"
        except ImportError:
            return 'N/A (pywin32 not installed)'
        except:
            pass
        return 'Unknown'
    
    def _format_windows_attributes(self, attrs: int) -> str:
        """Format Windows file attributes."""
        try:
            import win32con
            attr_list = []
            if attrs & win32con.FILE_ATTRIBUTE_READONLY:
                attr_list.append('ReadOnly')
            if attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                attr_list.append('Hidden')
            if attrs & win32con.FILE_ATTRIBUTE_SYSTEM:
                attr_list.append('System')
            if attrs & win32con.FILE_ATTRIBUTE_ARCHIVE:
                attr_list.append('Archive')
            if attrs & win32con.FILE_ATTRIBUTE_COMPRESSED:
                attr_list.append('Compressed')
            if attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED:
                attr_list.append('Encrypted')
            return ', '.join(attr_list) if attr_list else 'Normal'
        except ImportError:
            return 'N/A (pywin32 not installed)'
        except:
            return 'Unknown'
    
    def _format_unix_mode(self, mode: int) -> str:
        """Format Unix file mode."""
        perms = []
        if stat.S_ISDIR(mode):
            perms.append('Directory')
        if mode & stat.S_IRUSR:
            perms.append('Owner-Read')
        if mode & stat.S_IWUSR:
            perms.append('Owner-Write')
        if mode & stat.S_IXUSR:
            perms.append('Owner-Execute')
        return ', '.join(perms) if perms else 'Unknown'
    
    def scan_directory(self, 
                      directory: Path = None,
                      recursive: bool = True,
                      file_extensions: List[str] = None,
                      progress_callback=None) -> List[FileIntegrityRecord]:
        """
        Scan directory for files and compute their integrity information.
        
        Args:
            directory: Directory to scan (defaults to target_path)
            recursive: Whether to scan subdirectories
            file_extensions: Optional list of extensions to filter (e.g., ['.pdf', '.docx'])
            progress_callback: Optional callback(file_count, current_file)
        
        Returns:
            List of FileIntegrityRecord objects
        """
        if directory is None:
            directory = self.target_path
        
        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")
        
        scanned_files = []
        file_count = 0
        
        # Normalize extensions
        if file_extensions:
            file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' 
                             for ext in file_extensions]
        
        # Walk directory
        for root, dirs, files in os.walk(directory):
            root_path = Path(root)
            
            # Skip hidden/system directories on Windows
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                file_path = root_path / filename
                
                # Filter by extension if specified
                if file_extensions:
                    if file_path.suffix.lower() not in file_extensions:
                        continue
                
                # Get file info
                file_info = self.get_file_info(file_path)
                if file_info is None:
                    continue
                
                # Compute hash (optional for performance)
                file_hash = None
                if compute_hash:
                    file_hash = self.compute_file_hash(file_path)
                    if file_hash is None:
                        continue  # Skip if hash computation fails
                else:
                    file_hash = 'not_computed'  # Placeholder
                
                # Create record with comprehensive info
                record = FileIntegrityRecord(
                    file_path=str(file_path),
                    size=file_info['size'],
                    sha256=file_hash,
                    modified_time=file_info['modified_time'],
                    created_time=file_info.get('created_time'),
                    accessed_time=file_info.get('accessed_time'),
                    extension=file_info.get('extension'),
                    file_type=file_info.get('file_type'),
                    permissions=file_info.get('permissions'),
                    owner=file_info.get('owner'),
                    attributes=file_info.get('attributes'),
                    is_readonly=file_info.get('is_readonly', False),
                    is_hidden=file_info.get('is_hidden', False),
                    is_system=file_info.get('is_system', False)
                )
                
                scanned_files.append(record)
                file_count += 1
                
                if progress_callback:
                    progress_callback(file_count, str(file_path))
                
                if not recursive:
                    break
        
        self.scanned_files = scanned_files
        return scanned_files
    
    def save_baseline(self, baseline_path: str):
        """
        Save current scan as baseline for future comparison.
        
        Args:
            baseline_path: Path to save baseline JSON file
        """
        baseline_data = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'target_path': str(self.target_path),
            'file_count': len(self.scanned_files),
            'files': [record.to_dict() for record in self.scanned_files]
        }
        
        with open(baseline_path, 'w', encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=2)
    
    def load_baseline(self, baseline_path: str) -> Dict:
        """
        Load baseline for comparison.
        
        Args:
            baseline_path: Path to baseline JSON file
        
        Returns:
            Dictionary with baseline data
        """
        with open(baseline_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def compare_with_baseline(self, baseline_path: str) -> Dict:
        """
        Compare current scan with baseline to detect alterations.
        
        Args:
            baseline_path: Path to baseline JSON file
        
        Returns:
            Dictionary with comparison results:
            - altered_files: Files that changed
            - new_files: Files that are new
            - deleted_files: Files that were deleted
        """
        baseline = self.load_baseline(baseline_path)
        baseline_files = {record['file_path']: record for record in baseline['files']}
        
        current_files = {record.file_path: record for record in self.scanned_files}
        
        altered = []
        new = []
        deleted = []
        
        # Check for altered files
        for file_path, current_record in current_files.items():
            if file_path in baseline_files:
                baseline_record = baseline_files[file_path]
                
                # Check if hash changed (file content altered)
                if current_record.sha256 != baseline_record['sha256']:
                    altered.append({
                        'file_path': file_path,
                        'baseline_hash': baseline_record['sha256'],
                        'current_hash': current_record.sha256,
                        'baseline_size': baseline_record['size'],
                        'current_size': current_record.size,
                        'baseline_modified': baseline_record['modified_time'],
                        'current_modified': current_record.modified_time,
                        'change_type': 'content_altered'
                    })
                # Check if size changed but hash same (unlikely but possible)
                elif current_record.size != baseline_record['size']:
                    altered.append({
                        'file_path': file_path,
                        'baseline_hash': baseline_record['sha256'],
                        'current_hash': current_record.sha256,
                        'baseline_size': baseline_record['size'],
                        'current_size': current_record.size,
                        'change_type': 'size_changed'
                    })
                # Check if modified time changed significantly (potential tampering)
                elif abs(current_record.modified_time - baseline_record['modified_time']) > 1:
                    altered.append({
                        'file_path': file_path,
                        'baseline_hash': baseline_record['sha256'],
                        'current_hash': current_record.sha256,
                        'baseline_modified': baseline_record['modified_time'],
                        'current_modified': current_record.modified_time,
                        'change_type': 'timestamp_altered'
                    })
            else:
                # New file
                new.append(current_record)
        
        # Check for deleted files
        for file_path in baseline_files:
            if file_path not in current_files:
                deleted.append(file_path)
        
        self.altered_files = altered
        self.new_files = new
        self.deleted_files = deleted
        
        return {
            'altered_files': altered,
            'new_files': [record.to_dict() for record in new],
            'deleted_files': deleted,
            'unchanged_files': len(current_files) - len(altered) - len(new)
        }
    
    def scan_drive(self, drive_letter: str = None, 
                   file_extensions: List[str] = None,
                   progress_callback=None) -> List[FileIntegrityRecord]:
        """
        Scan a drive (Windows) or mount point (Linux/Mac).
        
        Args:
            drive_letter: Drive letter (e.g., 'C:') on Windows, or mount point on Unix
            file_extensions: Optional list of extensions to filter
            progress_callback: Optional callback for progress
        
        Returns:
            List of FileIntegrityRecord objects
        """
        if drive_letter:
            drive_path = Path(drive_letter)
        else:
            drive_path = self.target_path
        
        if not drive_path.exists():
            raise FileNotFoundError(f"Drive/path does not exist: {drive_path}")
        
        return self.scan_directory(
            directory=drive_path,
            recursive=True,
            file_extensions=file_extensions,
            progress_callback=progress_callback
        )
