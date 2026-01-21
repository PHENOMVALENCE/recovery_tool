#!/usr/bin/env python3
"""
Software Recovery Tool - Main CLI Entry Point

Cybersecurity-grade file carving tool for digital forensics.
Recovers deleted/lost files from raw disk images using signature-based carving.
"""

import argparse
import sys
from pathlib import Path

from core.signatures import get_signatures_by_types, list_available_types
from core.carver import FileCarver
from core.logger import RecoveryLogger
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
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan disk image for recoverable files')
    scan_parser.add_argument(
        '--image',
        required=True,
        help='Path to disk image file (e.g., disk.dd, image.img)'
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        run_scan(args)


def run_scan(args):
    """Execute scan operation."""
    # Print banner
    print_banner()
    
    # Validate inputs
    if not validate_image_file(args.image):
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
    print(f"[+] Scanning disk image: {args.image}")
    print(f"[+] Output directory: {args.output}")
    print(f"[+] File types: {', '.join(signatures.keys())}")
    if args.deep_scan:
        print("[+] Deep scan enabled")
    print()
    
    # Initialize logger
    log_file = Path(args.output) / 'recovery_audit_log.csv'
    logger = RecoveryLogger(str(log_file))
    
    # Initialize progress tracker
    image_size = Path(args.image).stat().st_size
    progress = ProgressTracker(image_size, verbose=args.verbose)
    
    # Initialize carver
    carver = FileCarver(
        signatures=signatures,
        output_dir=args.output,
        logger=logger
    )
    
    try:
        # Perform carving
        def progress_callback(bytes_processed, total_size):
            progress.update(bytes_processed, carver.recovered_count)
        
        stats = carver.carve(args.image, progress_callback=progress_callback)
        
        # Final progress update
        progress.update(image_size, carver.recovered_count)
        progress.close()
        
        # Print summary
        print()
        print("=" * 60)
        print("RECOVERY SUMMARY")
        print("=" * 60)
        print(f"[✓] Recovery complete: {stats['total_recovered']} files recovered")
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


if __name__ == '__main__':
    main()
