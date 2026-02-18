"""
Integrity Monitoring Module

Generates baseline snapshots and compares current file state
to detect new, modified, and deleted files.
"""

import hashlib
import json
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


def compute_file_sha256(file_path: Path, chunk_size: int = 8192) -> Optional[str]:
    """
    Compute SHA-256 hash of a file using streaming.
    
    Args:
        file_path: Path to file
        chunk_size: Read chunk size in bytes
        
    Returns:
        Hex digest string or None on error
    """
    try:
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError, PermissionError):
        return None


def scan_folder(folder_path: str, progress_callback=None) -> Dict[str, Dict]:
    """
    Scan folder and return file manifest.
    
    Args:
        folder_path: Path to folder to scan
        progress_callback: Optional callback(file_count, current_path)
        
    Returns:
        Dict mapping file_path to {path, size, modified_time, sha256}
    """
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Invalid folder path: {folder_path}")
    
    manifest = {}
    count = 0
    
    for item in folder.rglob('*'):
        if not item.is_file():
            continue
        try:
            stat = item.stat()
            sha256 = compute_file_sha256(item)
            if sha256 is None:
                continue
            
            rel_path = str(item.relative_to(folder))
            manifest[rel_path] = {
                'path': rel_path,
                'size': stat.st_size,
                'modified_time': stat.st_mtime,
                'sha256': sha256
            }
            count += 1
            if progress_callback:
                progress_callback(count, str(item))
        except (OSError, PermissionError):
            continue
    
    return manifest


def create_baseline(folder_path: str, output_path: str, progress_callback=None) -> Dict:
    """
    Create baseline snapshot and save to JSON.
    
    Args:
        folder_path: Folder to scan
        output_path: Path to save baseline JSON
        progress_callback: Optional callback
        
    Returns:
        Baseline data dict
    """
    manifest = scan_folder(folder_path, progress_callback)
    
    baseline = {
        'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
        'target_path': str(Path(folder_path).resolve()),
        'file_count': len(manifest),
        'files': manifest
    }
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(baseline, f, indent=2)
    
    return baseline


def load_baseline(baseline_path: str) -> Dict:
    """Load baseline from JSON file."""
    with open(baseline_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def compare_with_baseline(
    folder_path: str,
    baseline_path: str,
    progress_callback=None
) -> Dict[str, List]:
    """
    Compare current folder state with baseline.
    
    Args:
        folder_path: Folder to scan
        baseline_path: Path to baseline JSON
        progress_callback: Optional callback
        
    Returns:
        Dict with keys: new_files, modified_files, deleted_files, unchanged_files
        Each value is a list of file info dicts
    """
    baseline = load_baseline(baseline_path)
    baseline_files = baseline.get('files', {})
    base_path = Path(baseline.get('target_path', folder_path))
    
    folder = Path(folder_path)
    current = scan_folder(str(folder), progress_callback)
    
    # Normalize paths for comparison (relative to scanned folder)
    current_rel = {str(Path(k).as_posix()): v for k, v in current.items()}
    baseline_rel = {str(Path(k).as_posix()): v for k, v in baseline_files.items()}
    
    new_files = []
    modified_files = []
    deleted_files = []
    unchanged_files = []
    
    for path, info in current_rel.items():
        if path not in baseline_rel:
            new_files.append(info)
        elif info['sha256'] != baseline_rel[path]['sha256']:
            info['baseline_sha256'] = baseline_rel[path]['sha256']
            info['baseline_size'] = baseline_rel[path]['size']
            info['baseline_modified'] = baseline_rel[path]['modified_time']
            modified_files.append(info)
        else:
            unchanged_files.append(info)
    
    for path in baseline_rel:
        if path not in current_rel:
            deleted_files.append({
                'path': path,
                **baseline_rel[path]
            })
    
    return {
        'new_files': new_files,
        'modified_files': modified_files,
        'deleted_files': deleted_files,
        'unchanged_files': unchanged_files,
        'summary': {
            'new_count': len(new_files),
            'modified_count': len(modified_files),
            'deleted_count': len(deleted_files),
            'unchanged_count': len(unchanged_files)
        }
    }


def export_integrity_report(comparison: Dict, output_path: str) -> None:
    """
    Export integrity comparison to CSV.
    
    Args:
        comparison: Result from compare_with_baseline
        output_path: Path to save CSV
    """
    rows = []
    
    for item in comparison['new_files']:
        rows.append({
            'status': 'NEW',
            'path': item['path'],
            'size': item['size'],
            'modified': datetime.fromtimestamp(item['modified_time']).isoformat(),
            'sha256': item['sha256']
        })
    
    for item in comparison['modified_files']:
        rows.append({
            'status': 'MODIFIED',
            'path': item['path'],
            'size': item['size'],
            'modified': datetime.fromtimestamp(item['modified_time']).isoformat(),
            'sha256': item['sha256'],
            'baseline_sha256': item.get('baseline_sha256', '')
        })
    
    for item in comparison['deleted_files']:
        rows.append({
            'status': 'DELETED',
            'path': item['path'],
            'size': item['size'],
            'modified': datetime.fromtimestamp(item['modified_time']).isoformat() if item.get('modified_time') else '',
            'sha256': item.get('sha256', '')
        })
    
    if rows:
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['status', 'path', 'size', 'modified', 'sha256', 'baseline_sha256'], extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
