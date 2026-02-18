"""
Reporting Module

Generates recovery summaries and exports to CSV.
"""

import csv
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


def generate_recovery_summary(audit_log_path: str) -> Dict:
    """
    Generate summary from recovery audit log.
    
    Args:
        audit_log_path: Path to recovery_audit_log.csv
        
    Returns:
        Summary dict with total_files, by_type, total_size, duplicate_count, verification_failures
    """
    summary = {
        'total_files': 0,
        'unique_files': 0,
        'duplicate_count': 0,
        'verification_failures': 0,
        'total_size': 0,
        'by_type': {},
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    log_path = Path(audit_log_path)
    if not log_path.exists():
        return summary
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                summary['total_files'] += 1
                if row.get('is_duplicate', 'No').lower() == 'yes':
                    summary['duplicate_count'] += 1
                else:
                    summary['unique_files'] += 1
                
                status = row.get('verification_status', '').lower()
                if status == 'failed':  # Only count explicit failures; 'unverified' is expected for images/PDF
                    summary['verification_failures'] += 1
                
                try:
                    summary['total_size'] += int(row.get('file_size', 0))
                except (ValueError, TypeError):
                    pass
                
                ft = row.get('file_type', 'unknown')
                summary['by_type'][ft] = summary['by_type'].get(ft, 0) + 1
    except (IOError, csv.Error):
        pass
    
    return summary


def export_summary_to_csv(summary: Dict, output_path: str) -> None:
    """
    Export recovery summary to CSV.
    
    Args:
        summary: Result from generate_recovery_summary
        output_path: Path to save CSV
    """
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Timestamp', summary.get('timestamp', '')])
        writer.writerow(['Total Files Recovered', summary.get('total_files', 0)])
        writer.writerow(['Unique Files', summary.get('unique_files', 0)])
        writer.writerow(['Duplicate Count', summary.get('duplicate_count', 0)])
        writer.writerow(['Verification Failures', summary.get('verification_failures', 0)])
        writer.writerow(['Total Recovered Size (bytes)', summary.get('total_size', 0)])
        writer.writerow([])
        writer.writerow(['Files by Type', 'Count'])
        for ft, count in sorted(summary.get('by_type', {}).items()):
            writer.writerow([ft, count])


def load_recovery_results(audit_log_path: str) -> List[Dict]:
    """
    Load recovery results from audit log for display in Results Viewer.
    
    Args:
        audit_log_path: Path to recovery_audit_log.csv
        
    Returns:
        List of dicts with file_name, type, offset, size, sha256, verified, duplicate
    """
    results = []
    log_path = Path(audit_log_path)
    if not log_path.exists():
        return results
    
    output_dir = log_path.parent
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ft = row.get('file_type', '')
                offset = row.get('offset_hex', '')
                ext = ft.lower() if ft else 'bin'
                file_name = f"{ft}_offset_{offset}.{ext}"
                
                # Try to find actual filename in output dir
                type_dirs = {'pdf': 'pdf', 'docx': 'docx', 'xlsx': 'xlsx', 'jpg': 'images', 'png': 'images'}
                subdir = type_dirs.get(ft.lower(), 'misc')
                search_dir = output_dir / subdir
                resolved_path = ''
                if search_dir.exists():
                    for p in search_dir.glob(f"*{offset}*"):
                        file_name = p.name
                        resolved_path = str(p.resolve())
                        break
                
                results.append({
                    'file_name': file_name,
                    'type': ft,
                    'offset': offset,
                    'size': int(row.get('file_size', 0)),
                    'sha256': row.get('sha256', ''),
                    'verified': row.get('verification_status', '') == 'verified',
                    'duplicate': row.get('is_duplicate', 'No').lower() == 'yes',
                    'file_path': resolved_path
                })
    except (IOError, csv.Error):
        pass
    
    return results
