# Software Recovery Tool

**Cybersecurity-Grade CLI Application for Digital Forensics & File Carving**

A professional, command-line file recovery tool designed for digital forensics, incident response, and academic demonstration. This tool performs signature-based file carving on raw disk images to recover deleted or lost files while maintaining forensic chain of custody.

## 🔍 Overview

The Software Recovery Tool scans raw disk images byte-by-byte, detecting file signatures (magic bytes) and extracting complete files. It implements professional forensic practices including:

- **Signature-based carving**: Detects files by their hexadecimal header/trailer patterns
- **False positive reduction**: Verifies internal metadata for ZIP-based Office files
- **Slack space scanning**: Deep scans entire disk images, not just file boundaries
- **Forensic chain of custody**: Generates audit logs with SHA-256 hashes and timestamps
- **Professional CLI**: Clean, user-friendly command-line interface with progress tracking

## 📋 Supported File Types

The tool supports the following file formats with exact hex signature matching:

| File Type | Header (Hex) | Trailer (Hex) | Notes |
|-----------|--------------|---------------|-------|
| PDF | `25 50 44 46` | `25 25 45 4F 46` | `%PDF` ... `%%EOF` |
| DOCX | `50 4B 03 04` | `50 4B 05 06` | ZIP-based, verified via `word/document.xml` |
| XLSX | `50 4B 03 04` | `50 4B 05 06` | ZIP-based, verified via `xl/workbook.xml` |
| DOC | `D0 CF 11 E0` | None | Legacy MS Office (OLE2) |
| XLS | `D0 CF 11 E0` | None | Legacy MS Office (OLE2) |
| GIF | `47 49 46 38` | `00 3B` | `GIF8` ... `;` |
| JPG | `FF D8 FF E0` | `FF D9` | JPEG with JFIF |
| PNG | `89 50 4E 47` | `49 45 4E 44 AE 42 60 82` | PNG with IEND chunk |

### False Positive Reduction

For ZIP-based Office files (DOCX/XLSX), the tool performs internal verification:
- **DOCX**: Must contain `word/document.xml` in ZIP structure
- **XLSX**: Must contain `xl/workbook.xml` in ZIP structure
- Files that match the ZIP signature but fail verification are labeled as `office_zip`

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. Clone or download this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## 📖 Usage

### Basic Syntax

```bash
python recover.py scan --image <disk_image> --output <output_dir> [OPTIONS]
```

### Examples

#### Scan for specific file types

```bash
python recover.py scan \
  --image disk.dd \
  --output recovered_files \
  --types pdf,docx,jpg
```

#### Deep scan (recommended)

```bash
python recover.py scan \
  --image disk.dd \
  --output recovered_files \
  --types pdf,docx,xlsx \
  --deep-scan \
  --verbose
```

#### Scan for all supported file types

```bash
python recover.py scan \
  --image disk.dd \
  --output recovered_files \
  --deep-scan \
  --verbose
```

### Command-Line Options

#### Required Arguments

- `--image`: Path to disk image file (e.g., `disk.dd`, `image.img`)
- `--output`: Output directory for recovered files

#### Optional Arguments

- `--types`: Comma-separated list of file types to scan for (default: all types)
  - Example: `--types pdf,docx,xlsx`
  - Available: `pdf`, `docx`, `xlsx`, `doc`, `xls`, `gif`, `jpg`, `png`

- `--deep-scan`: Enable deep scan mode (recommended for thorough recovery)
  - Scans entire disk image including slack space
  - No assumptions about file system structures

- `--log-format`: Audit log format (default: `csv`)
  - Currently only `csv` is supported

- `--verbose`: Enable verbose output with real-time progress bar

- `-h, --help`: Show help message and exit

## 📁 Output Structure

Recovered files are organized in the following directory structure:

```
recovered_files/
├── pdf/                    # PDF documents
├── docx/                   # DOCX documents (verified)
├── xlsx/                   # XLSX spreadsheets (verified)
├── doc/                    # Legacy DOC files
├── xls/                    # Legacy XLS files
├── images/                 # GIF, JPG, PNG images
├── office_zip/             # Unverified ZIP files matching Office signatures
└── recovery_audit_log.csv  # Forensic audit log
```

### File Naming Convention

Recovered files are named using the format:
```
{file_type}_offset_{hex_offset}.{extension}
```

Example: `pdf_offset_0x1FA340.pdf`

If filename conflicts occur, a counter is appended:
- `pdf_offset_0x1FA340.pdf`
- `pdf_offset_0x1FA340_1.pdf`
- `pdf_offset_0x1FA340_2.pdf`

### Audit Log Format

The `recovery_audit_log.csv` file contains the following columns:

| Column | Description |
|--------|-------------|
| `timestamp` | UTC timestamp of recovery (ISO 8601 format) |
| `file_type` | Type of recovered file |
| `offset_hex` | Hexadecimal offset where file was found (e.g., `0x1FA340`) |
| `file_size` | Size of recovered file in bytes |
| `sha256` | SHA-256 hash of recovered file (64 hex characters) |
| `verification_status` | Verification status: `verified`, `unverified`, or `failed` |

**Example log entry:**
```csv
timestamp,file_type,offset_hex,file_size,sha256,verification_status
2024-01-15T10:30:45.123Z,pdf,0x1FA340,245678,9d3f8a2b...,verified
```

## 🔬 How It Works

### File Carving Process

1. **Image Reading**: Disk image is read as a binary stream in chunks (1MB default)
2. **Signature Detection**: Byte-by-byte scan for known file headers (magic bytes)
3. **File Extraction**: 
   - For files with trailers: Locate trailer pattern and extract header-to-trailer data
   - For files without trailers: Use heuristics and size limits
4. **Verification**: Internal metadata verification for ZIP-based Office files
5. **Hashing**: Compute SHA-256 hash for forensic integrity
6. **Logging**: Append-only audit log entry with all metadata

### Key Features

- **Memory Efficiency**: Chunked reading for large disk images
- **Overlap Prevention**: Tracks found files to prevent overlapping extractions
- **Size Limits**: Prevents runaway extraction of corrupted or fragmented files
- **Forensic Integrity**: SHA-256 hashing ensures evidence integrity

## 🔒 Security & Forensic Best Practices

- **No Hardcoded Paths**: All paths are user-specified via CLI
- **Safe Memory Usage**: Chunked processing prevents memory exhaustion
- **Append-Only Logs**: Audit logs are append-only for chain of custody
- **Reproducible Results**: Deterministic hashing and logging
- **Error Handling**: Graceful error handling with meaningful messages

## 🧪 Cybersecurity Concepts Demonstrated

1. **File Carving**: Signature-based recovery of deleted files
2. **Magic Byte Detection**: Identification of file types by headers
3. **Slack Space Analysis**: Recovery from unallocated space
4. **Chain of Custody**: Cryptographic hashing and audit logging
5. **False Positive Reduction**: Metadata verification to improve accuracy
6. **Digital Forensics**: Evidence preservation and documentation

## 📝 Code Quality

- **PEP 8 Compliant**: Follows Python style guidelines
- **Modular Architecture**: Clean separation of concerns
- **Well-Documented**: Comprehensive docstrings and inline comments
- **Type Hints**: Type annotations for better code clarity
- **Error Handling**: Robust error handling throughout

## 🗂️ Project Structure

```
software_recovery_tool/
│
├── recover.py              # CLI entry point
├── core/
│   ├── __init__.py
│   ├── carver.py           # File carving engine
│   ├── signatures.py       # Signature library
│   ├── verifier.py         # Metadata verification
│   ├── hasher.py           # SHA-256 utilities
│   └── logger.py           # Audit logging
│
├── utils/
│   ├── __init__.py
│   ├── progress.py         # Progress bar utilities
│   └── helpers.py          # Helper functions
│
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── LICENSE                # License file (if applicable)
```

## ⚠️ Limitations & Considerations

1. **Fragmented Files**: Files split across multiple disk locations may not be fully recovered
2. **No File System Awareness**: Tool treats disk as raw binary data
3. **Trailer-Less Files**: Legacy Office files (DOC/XLS) without trailers use heuristics
4. **Performance**: Large disk images may take significant time to process
5. **Memory**: Very large files (>100MB) without trailers may require adjustment

## 📚 Academic & Educational Use

This tool is suitable for:
- Digital forensics courses
- Incident response training
- Cybersecurity demonstrations
- File system research
- Data recovery education

## 🤝 Contributing

This is a demonstration tool. For production use, consider:
- Additional file type signatures
- More sophisticated fragmentation handling
- Parallel processing for performance
- Integration with forensic frameworks

## 📄 License

This tool is provided for educational and demonstration purposes. Please review license terms before use.

## 🔗 References

- **File Carving**: Signature-based file recovery technique
- **SHA-256**: Cryptographic hash function (NIST FIPS 180-4)
- **Digital Forensics**: Investigation of digital evidence
- **Chain of Custody**: Legal documentation of evidence handling

---

**Disclaimer**: This tool is for authorized forensic investigations and educational purposes only. Always ensure you have proper authorization before analyzing disk images.
