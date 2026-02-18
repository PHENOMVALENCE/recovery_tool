#!/usr/bin/env python3
"""
Software Recovery Tool - Main CLI Entry Point

Cybersecurity-grade file carving tool for digital forensics.
Recovers deleted/lost files from raw disk images using signature-based carving.
"""

import argparse
import os
import sys
from pathlib import Path

from core.signatures import get_signatures_by_types, list_available_types
from core.carver import FileCarver
from core.logger import RecoveryLogger
from core.live_scanner import LiveFileScanner
from core.file_scanner import FileScanReport
from utils.helpers import (
    print_banner,
    format_bytes,
    validate_image_file,
    parse_file_types,
    ensure_output_directory
)
from utils.progress import ProgressTracker


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Software Recovery Tool - Signature-based file carving for digital forensics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Scan for PDF and DOCX files
  python recover.py scan --image disk.dd --output recovered --types pdf,docx

  # Deep scan with verbose output
  python recover.py scan --image disk.dd --output recovered --types pdf,docx,xlsx --deep-scan --verbose

  # Scan for all supported file types
  python recover.py scan --image disk.dd --output recovered --deep-scan

Supported file types: {', '.join(list_available_types())}
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Scan command (disk image or folder)
    scan_parser = subparsers.add_parser('scan', help='Scan disk image or folder for recoverable files')
    scan_parser.add_argument(
        '--image',
        type=str,
        help='Path to disk image file (e.g., disk.dd, image.img). Use --folder for folder scanning.'
    )
    scan_parser.add_argument(
        '--folder',
        type=str,
        help='Path to folder to scan for file signatures. Use --image for disk image scanning.'
    )
    scan_parser.add_argument(
        '--output',
        required=True,
        help='Output directory for recovered files'
    )
    scan_parser.add_argument(
        '--types',
        type=str,
        default='',
        help='Comma-separated list of file types to scan for (default: all types). '
             f'Available: {", ".join(list_available_types())}'
    )
    scan_parser.add_argument(
        '--deep-scan',
        action='store_true',
        help='Enable deep scan (recommended for thorough recovery)'
    )
    scan_parser.add_argument(
        '--log-format',
        choices=['csv'],
        default='csv',
        help='Audit log format (default: csv)'
    )
    scan_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output with progress bars'
    )
    
    # Live scan command (folders/drives)
    live_parser = subparsers.add_parser('live', help='Scan live folders/drives and check for alterations')
    live_parser.add_argument(
        '--path',
        required=True,
        help='Path to folder or drive to scan (e.g., C:\\Users\\Documents or /home/user)'
    )
    live_parser.add_argument(
        '--baseline',
        type=str,
        help='Path to baseline JSON file for comparison (optional)'
    )
    live_parser.add_argument(
        '--save-baseline',
        type=str,
        help='Save current scan as baseline to specified file'
    )
    live_parser.add_argument(
        '--extensions',
        type=str,
        default='',
        help='Comma-separated file extensions to scan (e.g., pdf,docx,jpg). Leave empty for all files'
    )
    live_parser.add_argument(
        '--output',
        type=str,
        help='Output directory for scan report (optional)'
    )
    live_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Report command (new dedicated file scanner)
    report_parser = subparsers.add_parser('report', help='Scan folder/drive and generate file type report')
    report_parser.add_argument(
        '--path',
        required=True,
        help='Path to folder or drive to scan'
    )
    report_parser.add_argument(
        '--output',
        type=str,
        help='Output file path for report (optional, prints to console if not specified)'
    )
    report_parser.add_argument(
        '--format',
        choices=['text', 'json', 'csv'],
        default='text',
        help='Report format (default: text)'
    )
    report_parser.add_argument(
        '--extensions',
        type=str,
        default='',
        help='Comma-separated file extensions to filter (e.g., pdf,docx,jpg). Leave empty for all files'
    )
    report_parser.add_argument(
        '--max-files',
        type=int,
        help='Maximum number of files to scan (optional, for large directories)'
    )
    report_parser.add_argument(
        '--no-details',
        action='store_true',
        help='Skip detailed file information (faster scan)'
    )
    report_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show progress during scan'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'live':
        run_live_scan(args)
    elif args.command == 'report':
        run_report(args)


def run_scan(args):
    """Execute scan operation."""
    # Print banner
    print_banner()
    
    # Determine scan mode
    if args.image and args.folder:
        print("[-] Error: Cannot specify both --image and --folder. Choose one.", file=sys.stderr)
        sys.exit(1)
    
    if not args.image and not args.folder:
        print("[-] Error: Must specify either --image or --folder", file=sys.stderr)
        sys.exit(1)
    
    scan_mode = 'image' if args.image else 'folder'
    source_path = args.image if args.image else args.folder
    
    # Validate inputs
    if scan_mode == 'image':
        if not validate_image_file(source_path):
            sys.exit(1)
    else:
        if not os.path.exists(source_path):
            print(f"[-] Error: Folder does not exist: {source_path}", file=sys.stderr)
            sys.exit(1)
        if not os.path.isdir(source_path):
            print(f"[-] Error: Path is not a directory: {source_path}", file=sys.stderr)
            sys.exit(1)
    
    if not ensure_output_directory(args.output):
        sys.exit(1)
    
    # Parse file types
    requested_types = parse_file_types(args.types) if args.types else []
    signatures = get_signatures_by_types(requested_types)
    
    if not signatures:
        print("[-] Error: No valid file types specified or available", file=sys.stderr)
        sys.exit(1)
    
    # Print scan configuration
    mode_name = "disk image" if scan_mode == 'image' else "folder"
    print(f"[+] Scanning {mode_name}: {source_path}")
    print(f"[+] Output directory: {args.output}")
    print(f"[+] File types: {', '.join(signatures.keys())}")
    if args.deep_scan:
        print("[+] Deep scan enabled")
    print()
    
    # Initialize logger
    log_file = Path(args.output) / 'recovery_audit_log.csv'
    logger = RecoveryLogger(str(log_file))
    
    # Initialize carver
    carver = FileCarver(
        signatures=signatures,
        output_dir=args.output,
        logger=logger
    )
    
    try:
        if scan_mode == 'image':
            # Disk image mode
            image_size = Path(source_path).stat().st_size
            progress = ProgressTracker(image_size, verbose=args.verbose)
            
            def progress_callback(bytes_processed, total_size):
                progress.update(bytes_processed, carver.recovered_count)
            
            stats = carver.carve(source_path, progress_callback=progress_callback)
            
            # Final progress update
            progress.update(image_size, carver.recovered_count)
            progress.close()
        else:
            # Folder mode
            # Count files for progress estimation
            file_count = sum(1 for _ in Path(source_path).rglob('*') if _.is_file())
            total_bytes = sum(f.stat().st_size for f in Path(source_path).rglob('*') if f.is_file())
            
            progress = ProgressTracker(total_bytes, verbose=args.verbose)
            
            def progress_callback(files_processed, total_files):
                # Estimate bytes processed
                bytes_processed = int((files_processed / total_files) * total_bytes) if total_files > 0 else 0
                progress.update(bytes_processed, carver.recovered_count)
            
            stats = carver.carve_folder(source_path, progress_callback=progress_callback)
            
            # Final progress update
            progress.update(total_bytes, carver.recovered_count)
            progress.close()
        
        # Print summary
        print()
        print("=" * 60)
        print("RECOVERY SUMMARY")
        print("=" * 60)
        total_recovered = stats.get('total_recovered', 0)
        unique_files = stats.get('unique_files', total_recovered)
        duplicate_files = stats.get('duplicate_files', 0)
        
        print(f"[✓] Recovery complete!")
        print(f"[+] Total files found: {total_recovered}")
        print(f"[+] Unique files: {unique_files}")
        if duplicate_files > 0:
            print(f"[+] Duplicate files: {duplicate_files}")
        print(f"[+] Bytes processed: {format_bytes(stats['bytes_processed'])}")
        print(f"[+] Audit log: {log_file}")
        
        # Print statistics by file type
        log_stats = logger.get_log_stats()
        if log_stats:
            print()
            print("Files by type:")
            for file_type, count in sorted(log_stats.items()):
                print(f"  {file_type}: {count}")
        
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        progress.close()
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error during recovery: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        progress.close()
        sys.exit(1)


def run_live_scan(args):
    """Execute live folder/drive scan."""
    print_banner()
    
    # Validate path exists
    if not os.path.exists(args.path):
        print(f"[-] Error: Path does not exist: {args.path}", file=sys.stderr)
        print(f"[-] Please check the path and try again.", file=sys.stderr)
        sys.exit(1)
    
    print(f"[+] Scanning live path: {args.path}")
    if args.baseline:
        print(f"[+] Comparing with baseline: {args.baseline}")
    if args.save_baseline:
        print(f"[+] Will save baseline to: {args.save_baseline}")
    print()
    
    try:
        # Initialize scanner
        scanner = LiveFileScanner(args.path)
        
        # Parse extensions
        extensions = None
        if args.extensions:
            extensions = [ext.strip() for ext in args.extensions.split(',')]
            print(f"[+] Filtering by extensions: {', '.join(extensions)}")
        
        # Progress tracking
        file_count = [0]  # Use list for mutable closure
        
        def progress_callback(count, current_file):
            file_count[0] = count
            if args.verbose and count % 100 == 0:
                print(f"[*] Scanned {count} files... {current_file[:60]}...", end='\r')
        
        # Scan directory
        print("[+] Starting scan...")
        records = scanner.scan_directory(
            recursive=True,
            file_extensions=extensions,
            progress_callback=progress_callback if args.verbose else None
        )
        
        if args.verbose:
            print()  # New line after progress
        
        print(f"[+] Scan complete: {len(records)} files found")
        
        # Save baseline if requested
        if args.save_baseline:
            scanner.save_baseline(args.save_baseline)
            print(f"[+] Baseline saved to: {args.save_baseline}")
        
        # Compare with baseline if provided
        if args.baseline:
            print("\n[+] Comparing with baseline...")
            comparison = scanner.compare_with_baseline(args.baseline)
            
            print("\n" + "=" * 60)
            print("INTEGRITY CHECK RESULTS")
            print("=" * 60)
            print(f"[+] Unchanged files: {comparison['unchanged_files']}")
            print(f"[!] Altered files: {len(comparison['altered_files'])}")
            print(f"[+] New files: {len(comparison['new_files'])}")
            print(f"[-] Deleted files: {len(comparison['deleted_files'])}")
            print()
            
            # Show altered files
            if comparison['altered_files']:
                print("ALTERED FILES:")
                print("-" * 60)
                for altered in comparison['altered_files']:
                    print(f"\n[!] {altered['file_path']}")
                    print(f"    Change Type: {altered['change_type']}")
                    if altered['change_type'] == 'content_altered':
                        print(f"    Baseline Hash: {altered['baseline_hash'][:32]}...")
                        print(f"    Current Hash:  {altered['current_hash'][:32]}...")
                        print(f"    Size: {format_bytes(altered['baseline_size'])} → {format_bytes(altered['current_size'])}")
            
            # Show new files
            if comparison['new_files']:
                print("\nNEW FILES:")
                print("-" * 60)
                for new_file in comparison['new_files'][:10]:  # Show first 10
                    print(f"[+] {new_file['file_path']} ({format_bytes(new_file['size'])})")
                if len(comparison['new_files']) > 10:
                    print(f"... and {len(comparison['new_files']) - 10} more")
            
            # Show deleted files
            if comparison['deleted_files']:
                print("\nDELETED FILES:")
                print("-" * 60)
                for deleted in comparison['deleted_files'][:10]:  # Show first 10
                    print(f"[-] {deleted}")
                if len(comparison['deleted_files']) > 10:
                    print(f"... and {len(comparison['deleted_files']) - 10} more")
            
            print("=" * 60)
            
            # Save report if output directory specified
            if args.output:
                ensure_output_directory(args.output)
                report_path = Path(args.output) / 'integrity_report.json'
                with open(report_path, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(comparison, f, indent=2)
                print(f"\n[+] Report saved to: {report_path}")
        else:
            # Show detailed file list
            print("\n" + "=" * 60)
            print("SCAN RESULTS - DETAILED FILE INFORMATION")
            print("=" * 60)
            print(f"Total files: {len(records)}")
            
            # Group by extension and file type
            by_extension = {}
            by_file_type = {}
            total_size = 0
            readonly_count = 0
            hidden_count = 0
            
            for record in records:
                ext = record.extension or '(no extension)'
                by_extension[ext] = by_extension.get(ext, 0) + 1
                
                file_type = record.file_type or 'Unknown'
                by_file_type[file_type] = by_file_type.get(file_type, 0) + 1
                
                total_size += record.size
                if record.is_readonly:
                    readonly_count += 1
                if record.is_hidden:
                    hidden_count += 1
            
            print(f"Total size: {format_bytes(total_size)}")
            print(f"Read-only files: {readonly_count}")
            print(f"Hidden files: {hidden_count}")
            
            print("\nFiles by extension (top 10):")
            for ext, count in sorted(by_extension.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {ext}: {count}")
            
            print("\nFiles by type (top 10):")
            for file_type, count in sorted(by_file_type.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {file_type}: {count}")
            
            # Show detailed file information (first 20 files)
            if args.verbose and records:
                print("\n" + "=" * 60)
                print("DETAILED FILE PROPERTIES (First 20 files)")
                print("=" * 60)
                for i, record in enumerate(records[:20], 1):
                    print(f"\n[{i}] {Path(record.file_path).name}")
                    print(f"    Path: {record.file_path}")
                    print(f"    Size: {format_bytes(record.size)}")
                    print(f"    Type: {record.file_type}")
                    print(f"    Extension: {record.extension or 'None'}")
                    print(f"    Modified: {datetime.fromtimestamp(record.modified_time).strftime('%Y-%m-%d %H:%M:%S')}")
                    if record.created_time:
                        print(f"    Created: {datetime.fromtimestamp(record.created_time).strftime('%Y-%m-%d %H:%M:%S')}")
                    if record.permissions:
                        print(f"    Permissions: {record.permissions}")
                    if record.owner:
                        print(f"    Owner: {record.owner}")
                    if record.attributes:
                        print(f"    Attributes: {record.attributes}")
                    flags = []
                    if record.is_readonly:
                        flags.append('ReadOnly')
                    if record.is_hidden:
                        flags.append('Hidden')
                    if record.is_system:
                        flags.append('System')
                    if flags:
                        print(f"    Flags: {', '.join(flags)}")
                    if record.sha256 and record.sha256 != 'not_computed':
                        print(f"    SHA-256: {record.sha256[:32]}...")
            
            print("=" * 60)
            
            if args.save_baseline:
                print(f"\n[+] Use this baseline for future comparisons:")
                print(f"    python recover.py live --path {args.path} --baseline {args.save_baseline}")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error during scan: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_report(args):
    """Execute file scan and generate report."""
    print_banner()
    
    # Validate path
    if not os.path.exists(args.path):
        print(f"[-] Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)
    
    print(f"[+] Generating file scan report for: {args.path}")
    print(f"[+] Report format: {args.format}")
    if args.output:
        print(f"[+] Output file: {args.output}")
    print()
    
    try:
        # Initialize scanner
        scanner = FileScanReport(args.path)
        
        # Parse extensions
        extensions = None
        if args.extensions:
            extensions = [ext.strip() for ext in args.extensions.split(',')]
            print(f"[+] Filtering by extensions: {', '.join(extensions)}")
        
        # Progress callback
        file_count = [0]
        
        def progress_callback(count, current_file):
            file_count[0] = count
            if args.verbose and count % 100 == 0:
                print(f"[*] Scanned {count} files... {current_file[:60]}...", end='\r')
        
        # Scan
        print("[+] Starting scan...")
        stats = scanner.scan(
            recursive=True,
            file_extensions=extensions,
            max_files=args.max_files,
            include_details=not args.no_details,
            progress_callback=progress_callback if args.verbose else None
        )
        
        if args.verbose:
            print()  # New line after progress
        
        print(f"[+] Scan complete: {stats['total_files']:,} files found")
        print(f"[+] Total size: {format_bytes(stats['total_size'])}")
        print()
        
        # Generate and save/display report
        if args.output:
            scanner.save_report(args.output, format=args.format)
            print(f"[+] Report saved to: {args.output}")
        else:
            # Print to console
            if args.format == 'text':
                print(scanner.generate_text_report())
            elif args.format == 'json':
                print(scanner.generate_json_report())
            else:
                print("[!] CSV format requires --output parameter")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error during scan: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
