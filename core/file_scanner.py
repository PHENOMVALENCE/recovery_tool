"""
File Scanner Module

Scans folders and drives to analyze and report on file types, sizes, and properties.
Generates comprehensive reports of file system contents.
"""

import os
import stat
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import json
import csv


class FileScanReport:
    """Comprehensive file scan report generator."""
    
    def __init__(self, scan_path: str):
        """
        Initialize file scan report.
        
        Args:
            scan_path: Path to folder or drive to scan
        """
        self.scan_path = Path(scan_path)
        if not self.scan_path.exists():
            raise FileNotFoundError(f"Path does not exist: {scan_path}")
        
        self.file_stats = {
            'total_files': 0,
            'total_size': 0,
            'total_directories': 0,
            'by_extension': defaultdict(int),
            'by_file_type': defaultdict(int),
            'by_size_range': defaultdict(int),
            'by_date_range': defaultdict(int),
            'readonly_files': 0,
            'hidden_files': 0,
            'system_files': 0,
            'largest_files': [],
            'oldest_files': [],
            'newest_files': [],
            'file_details': []
        }
    
    def scan(self, 
             recursive: bool = True,
             file_extensions: List[str] = None,
             max_files: Optional[int] = None,
             include_details: bool = True,
             progress_callback=None) -> Dict:
        """
        Scan directory and collect statistics.
        
        Args:
            recursive: Whether to scan subdirectories
            file_extensions: Optional list of extensions to filter
            max_files: Maximum number of files to scan (None = unlimited)
            include_details: Whether to include detailed file information
            progress_callback: Optional callback(file_count, current_file)
        
        Returns:
            Dictionary with scan statistics
        """
        if file_extensions:
            file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' 
                             for ext in file_extensions]
        
        file_count = 0
        dir_count = 0
        
        # Size ranges (in bytes)
        size_ranges = [
            (0, 1024, '0-1 KB'),
            (1024, 1024 * 10, '1-10 KB'),
            (1024 * 10, 1024 * 100, '10-100 KB'),
            (1024 * 100, 1024 * 1024, '100 KB-1 MB'),
            (1024 * 1024, 1024 * 1024 * 10, '1-10 MB'),
            (1024 * 1024 * 10, 1024 * 1024 * 100, '10-100 MB'),
            (1024 * 1024 * 100, float('inf'), '100+ MB')
        ]
        
        # Walk directory
        for root, dirs, files in os.walk(self.scan_path):
            root_path = Path(root)
            
            # Skip hidden/system directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            dir_count += len(dirs)
            
            for filename in files:
                if max_files and file_count >= max_files:
                    break
                
                file_path = root_path / filename
                
                # Filter by extension if specified
                if file_extensions:
                    if file_path.suffix.lower() not in file_extensions:
                        continue
                
                try:
                    file_stat = file_path.stat()
                    file_size = file_stat.st_size
                    modified_time = file_stat.st_mtime
                    
                    # Update statistics
                    self.file_stats['total_files'] += 1
                    self.file_stats['total_size'] += file_size
                    
                    # Extension
                    ext = file_path.suffix.lower() or '(no extension)'
                    self.file_stats['by_extension'][ext] += 1
                    
                    # File type
                    file_type = self._detect_file_type(file_path)
                    self.file_stats['by_file_type'][file_type] += 1
                    
                    # Size range
                    for min_size, max_size, label in size_ranges:
                        if min_size <= file_size < max_size:
                            self.file_stats['by_size_range'][label] += 1
                            break
                    
                    # Date range (by month)
                    date_label = datetime.fromtimestamp(modified_time).strftime('%Y-%m')
                    self.file_stats['by_date_range'][date_label] += 1
                    
                    # Attributes
                    if platform.system() == 'Windows':
                        try:
                            import win32api
                            import win32con
                            attrs = win32api.GetFileAttributes(str(file_path))
                            if attrs & win32con.FILE_ATTRIBUTE_READONLY:
                                self.file_stats['readonly_files'] += 1
                            if attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
                                self.file_stats['hidden_files'] += 1
                            if attrs & win32con.FILE_ATTRIBUTE_SYSTEM:
                                self.file_stats['system_files'] += 1
                        except:
                            pass
                    else:
                        mode = file_stat.st_mode
                        if not (mode & stat.S_IWRITE):
                            self.file_stats['readonly_files'] += 1
                        if filename.startswith('.'):
                            self.file_stats['hidden_files'] += 1
                    
                    # Track largest files
                    if include_details:
                        file_info = {
                            'path': str(file_path),
                            'name': filename,
                            'size': file_size,
                            'extension': ext,
                            'type': file_type,
                            'modified': modified_time,
                            'created': getattr(file_stat, 'st_birthtime', file_stat.st_ctime) if hasattr(file_stat, 'st_birthtime') else file_stat.st_ctime
                        }
                        
                        self.file_stats['file_details'].append(file_info)
                        
                        # Maintain top 20 largest files
                        self.file_stats['largest_files'].append(file_info)
                        self.file_stats['largest_files'].sort(key=lambda x: x['size'], reverse=True)
                        self.file_stats['largest_files'] = self.file_stats['largest_files'][:20]
                        
                        # Maintain oldest/newest files
                        self.file_stats['oldest_files'].append(file_info)
                        self.file_stats['oldest_files'].sort(key=lambda x: x['modified'])
                        self.file_stats['oldest_files'] = self.file_stats['oldest_files'][:20]
                        
                        self.file_stats['newest_files'].append(file_info)
                        self.file_stats['newest_files'].sort(key=lambda x: x['modified'], reverse=True)
                        self.file_stats['newest_files'] = self.file_stats['newest_files'][:20]
                    
                    file_count += 1
                    
                    if progress_callback:
                        progress_callback(file_count, str(file_path))
                
                except (OSError, PermissionError):
                    continue
            
            if max_files and file_count >= max_files:
                break
            
            if not recursive:
                break
        
        self.file_stats['total_directories'] = dir_count
        return self.file_stats
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type from extension and magic bytes."""
        extension = file_path.suffix.lower()
        
        # Try magic bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
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
        except:
            pass
        
        # Extension-based detection
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
            '.tar': 'TAR Archive',
            '.gz': 'GZIP Archive',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.bmp': 'Bitmap Image',
            '.tiff': 'TIFF Image',
            '.svg': 'SVG Image',
            '.mp3': 'MP3 Audio',
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mov': 'QuickTime Video',
            '.wmv': 'Windows Media Video',
            '.exe': 'Executable',
            '.dll': 'Dynamic Link Library',
            '.py': 'Python Script',
            '.js': 'JavaScript',
            '.css': 'CSS Stylesheet',
            '.java': 'Java Source',
            '.cpp': 'C++ Source',
            '.c': 'C Source',
            '.h': 'C/C++ Header',
        }
        
        return type_map.get(extension, f'Unknown ({extension or "no extension"})')
    
    def generate_text_report(self) -> str:
        """Generate human-readable text report."""
        stats = self.file_stats
        
        report = []
        report.append("=" * 80)
        report.append("FILE SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Scan Path: {self.scan_path}")
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Files: {stats['total_files']:,}")
        report.append(f"Total Directories: {stats['total_directories']:,}")
        report.append(f"Total Size: {self._format_bytes(stats['total_size'])}")
        report.append(f"Read-only Files: {stats['readonly_files']:,}")
        report.append(f"Hidden Files: {stats['hidden_files']:,}")
        report.append(f"System Files: {stats['system_files']:,}")
        report.append("")
        
        # Files by Extension
        report.append("FILES BY EXTENSION (Top 20)")
        report.append("-" * 80)
        for ext, count in sorted(stats['by_extension'].items(), key=lambda x: x[1], reverse=True)[:20]:
            percentage = (count / stats['total_files'] * 100) if stats['total_files'] > 0 else 0
            report.append(f"  {ext:20s} {count:8,} files ({percentage:5.1f}%)")
        report.append("")
        
        # Files by Type
        report.append("FILES BY TYPE (Top 20)")
        report.append("-" * 80)
        for file_type, count in sorted(stats['by_file_type'].items(), key=lambda x: x[1], reverse=True)[:20]:
            percentage = (count / stats['total_files'] * 100) if stats['total_files'] > 0 else 0
            report.append(f"  {file_type:40s} {count:8,} files ({percentage:5.1f}%)")
        report.append("")
        
        # Files by Size Range
        report.append("FILES BY SIZE RANGE")
        report.append("-" * 80)
        for size_range in ['0-1 KB', '1-10 KB', '10-100 KB', '100 KB-1 MB', '1-10 MB', '10-100 MB', '100+ MB']:
            count = stats['by_size_range'].get(size_range, 0)
            if count > 0:
                percentage = (count / stats['total_files'] * 100) if stats['total_files'] > 0 else 0
                report.append(f"  {size_range:15s} {count:8,} files ({percentage:5.1f}%)")
        report.append("")
        
        # Files by Date Range
        report.append("FILES BY DATE (Modified Date - Top 15)")
        report.append("-" * 80)
        for date_label, count in sorted(stats['by_date_range'].items(), reverse=True)[:15]:
            report.append(f"  {date_label} {count:8,} files")
        report.append("")
        
        # Largest Files
        if stats['largest_files']:
            report.append("LARGEST FILES (Top 10)")
            report.append("-" * 80)
            for i, file_info in enumerate(stats['largest_files'][:10], 1):
                report.append(f"  {i:2d}. {self._format_bytes(file_info['size']):>12s} - {file_info['name']}")
                report.append(f"      {file_info['path']}")
            report.append("")
        
        # Oldest Files
        if stats['oldest_files']:
            report.append("OLDEST FILES (Top 10)")
            report.append("-" * 80)
            for i, file_info in enumerate(stats['oldest_files'][:10], 1):
                mod_date = datetime.fromtimestamp(file_info['modified']).strftime('%Y-%m-%d')
                report.append(f"  {i:2d}. {mod_date} - {file_info['name']}")
                report.append(f"      {file_info['path']}")
            report.append("")
        
        # Newest Files
        if stats['newest_files']:
            report.append("NEWEST FILES (Top 10)")
            report.append("-" * 80)
            for i, file_info in enumerate(stats['newest_files'][:10], 1):
                mod_date = datetime.fromtimestamp(file_info['modified']).strftime('%Y-%m-%d %H:%M:%S')
                report.append(f"  {i:2d}. {mod_date} - {file_info['name']}")
                report.append(f"      {file_info['path']}")
            report.append("")
        
        report.append("=" * 80)
        report.append("End of Report")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report_data = {
            'scan_path': str(self.scan_path),
            'scan_date': datetime.now().isoformat(),
            'statistics': {
                'total_files': self.file_stats['total_files'],
                'total_directories': self.file_stats['total_directories'],
                'total_size': self.file_stats['total_size'],
                'readonly_files': self.file_stats['readonly_files'],
                'hidden_files': self.file_stats['hidden_files'],
                'system_files': self.file_stats['system_files'],
            },
            'by_extension': dict(self.file_stats['by_extension']),
            'by_file_type': dict(self.file_stats['by_file_type']),
            'by_size_range': dict(self.file_stats['by_size_range']),
            'by_date_range': dict(self.file_stats['by_date_range']),
            'largest_files': [
                {
                    'path': f['path'],
                    'name': f['name'],
                    'size': f['size'],
                    'size_formatted': self._format_bytes(f['size']),
                    'type': f['type']
                }
                for f in self.file_stats['largest_files'][:20]
            ],
            'oldest_files': [
                {
                    'path': f['path'],
                    'name': f['name'],
                    'modified': datetime.fromtimestamp(f['modified']).isoformat(),
                    'type': f['type']
                }
                for f in self.file_stats['oldest_files'][:20]
            ],
            'newest_files': [
                {
                    'path': f['path'],
                    'name': f['name'],
                    'modified': datetime.fromtimestamp(f['modified']).isoformat(),
                    'type': f['type']
                }
                for f in self.file_stats['newest_files'][:20]
            ]
        }
        
        return json.dumps(report_data, indent=2)
    
    def generate_csv_report(self, output_path: str):
        """Generate CSV report of all files."""
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Path', 'Name', 'Size (bytes)', 'Size (formatted)', 
                'Extension', 'Type', 'Modified Date', 'Created Date'
            ])
            
            for file_info in self.file_stats['file_details']:
                writer.writerow([
                    file_info['path'],
                    file_info['name'],
                    file_info['size'],
                    self._format_bytes(file_info['size']),
                    file_info['extension'],
                    file_info['type'],
                    datetime.fromtimestamp(file_info['modified']).isoformat(),
                    datetime.fromtimestamp(file_info['created']).isoformat()
                ])
    
    def _format_bytes(self, size: int) -> str:
        """Format bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def save_report(self, output_path: str, format: str = 'text'):
        """
        Save report to file.
        
        Args:
            output_path: Path to save report
            format: Report format ('text', 'json', or 'csv')
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'text':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_text_report())
        elif format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_json_report())
        elif format == 'csv':
            self.generate_csv_report(str(output_path))
        else:
            raise ValueError(f"Unknown format: {format}")
