# Software Recovery Tool - Complete System Explanation

## Overview

The **Software Recovery Tool** is a cybersecurity-grade application designed for digital forensics, file recovery, and file system analysis. It combines multiple capabilities into a unified tool that can recover deleted files, scan live file systems, detect file alterations, and generate comprehensive reports.

---

## System Architecture

### Three-Layer Design

```
┌─────────────────────────────────────────────────────────┐
│              User Interface Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  CLI (CLI)   │  │  GUI (Tkinter)│  │  Both Modes  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
└─────────┼──────────────────┼──────────────────┼─────────┘
          │                  │                  │
┌─────────┼──────────────────┼──────────────────┼─────────┐
│         │                  │                  │          │
│  ┌──────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐  │
│  │ File Carver │  │ Live Scanner  │  │ File Scanner │  │
│  │  (Core)     │  │  (Core)       │  │  (Core)      │  │
│  └──────┬──────┘  └───────┬──────┘  └───────┬──────┘  │
│         │                  │                  │          │
│  ┌──────▼──────────────────▼──────────────────▼──────┐ │
│  │         Shared Core Modules                        │ │
│  │  • Signatures  • Hasher  • Logger  • Verifier      │ │
│  │  • Metadata Extractor                               │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. File Carving Engine (`core/carver.py`)

**Purpose**: Recover deleted files from disk images using signature-based carving.

**How It Works**:

```
┌─────────────────────────────────────────────────────┐
│  Disk Image (Raw Binary Data)                       │
│  [random][%PDF][content][%%EOF][random][FFD8FF...] │
│         ↑                    ↑         ↑           │
│      PDF Header          PDF Trailer  JPG Header   │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  1. Read disk image in chunks (1MB)                 │
│  2. Scan byte-by-byte for known signatures          │
│  3. When header found:                              │
│     - Search for trailer (if available)             │
│     - Extract data from header to trailer           │
│  4. Verify file structure (for Office files)        │
│  5. Compute SHA-256 hash                            │
│  6. Save with original name (if metadata available)  │
│  7. Log to audit trail                              │
└─────────────────────────────────────────────────────┘
```

**Key Features**:
- **Signature-Based Detection**: Uses magic bytes (hex patterns) to identify files
- **Trailer Matching**: Finds file endings for complete extraction
- **Duplicate Detection**: Uses SHA-256 hashing to identify duplicate files
- **Metadata Extraction**: Recovers original filenames from PDF/Office files
- **False Positive Reduction**: Verifies Office file structure

**Supported Modes**:
- **Disk Image Mode**: Scans `.dd`, `.img`, `.bin`, `.raw` files
- **Folder Mode**: Scans folders for files matching signatures

---

### 2. Live File Scanner (`core/live_scanner.py`)

**Purpose**: Scan live folders/drives and check for file alterations.

**How It Works**:

```
┌─────────────────────────────────────────────────────┐
│  Live Folder/Drive                                  │
│  ├── file1.pdf                                      │
│  ├── file2.docx                                     │
│  └── file3.jpg                                      │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  1. Walk directory tree                             │
│  2. For each file:                                  │
│     - Get file properties (size, dates, permissions) │
│     - Compute SHA-256 hash                          │
│     - Detect file type (magic bytes + extension)    │
│     - Check attributes (read-only, hidden, system)  │
│  3. Create baseline (optional)                      │
│  4. Compare with baseline (if provided)             │
│  5. Report changes                                  │
└─────────────────────────────────────────────────────┘
```

**Key Features**:
- **Comprehensive Properties**: Size, timestamps, permissions, ownership
- **File Type Detection**: Magic bytes + extension-based identification
- **Baseline Comparison**: Compare current state with previous scan
- **Change Detection**: Identifies altered, new, and deleted files
- **Cross-Platform**: Works on Windows, Linux, macOS

---

### 3. File Scanner (`core/file_scanner.py`)

**Purpose**: Generate comprehensive reports of file types in folders/drives.

**How It Works**:

```
┌─────────────────────────────────────────────────────┐
│  Folder/Drive                                      │
│  ├── Documents/                                     │
│  │   ├── report.pdf                                 │
│  │   └── data.xlsx                                  │
│  └── Images/                                        │
│      └── photo.jpg                                 │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  1. Scan all files recursively                      │
│  2. Collect statistics:                             │
│     - Count by extension                            │
│     - Count by file type                            │
│     - Group by size range                           │
│     - Group by date                                 │
│     - Identify largest/oldest/newest files          │
│  3. Generate report (Text/JSON/CSV)                │
└─────────────────────────────────────────────────────┘
```

**Key Features**:
- **Statistical Analysis**: Comprehensive file type breakdown
- **Multiple Report Formats**: Text, JSON, CSV
- **Size Analysis**: Groups files by size ranges
- **Date Analysis**: Groups files by modification date
- **Top Lists**: Largest, oldest, newest files

---

## Supporting Modules

### Signature Library (`core/signatures.py`)

**Purpose**: Centralized storage of file type signatures (magic bytes).

**What It Contains**:
- **Headers**: Initial bytes that identify file type (e.g., `%PDF` for PDFs)
- **Trailers**: Ending bytes that mark file end (e.g., `%%EOF` for PDFs)
- **8 File Types**: PDF, DOCX, XLSX, DOC, XLS, GIF, JPG, PNG

**Example**:
```python
'pdf': FileSignature(
    header=bytes.fromhex('25504446'),      # %PDF
    trailer=bytes.fromhex('2525454F46')    # %%EOF
)
```

---

### SHA-256 Hasher (`core/hasher.py`)

**Purpose**: Compute cryptographic hashes for forensic integrity.

**Uses**:
- **Chain of Custody**: Prove file hasn't been modified
- **Duplicate Detection**: Identify identical files
- **Evidence Integrity**: Verify recovered files

---

### Metadata Extractor (`core/metadata.py`)

**Purpose**: Extract original filenames from file metadata.

**Supported Formats**:
- **PDF**: Extracts title from `/Title` metadata
- **DOCX**: Extracts title from `docProps/core.xml`
- **XLSX**: Extracts title from `docProps/core.xml`

**Benefit**: Recovered files can have their original names instead of generic `pdf_offset_0x1FA340.pdf`

---

### Verifier (`core/verifier.py`)

**Purpose**: Reduce false positives by verifying file structure.

**How It Works**:
- For ZIP-based Office files (DOCX, XLSX):
  - Opens file as ZIP archive
  - Checks for required internal files:
    - DOCX: Must have `word/document.xml`
    - XLSX: Must have `xl/workbook.xml`
  - If verification fails: Relabels as `office_zip`

**Result**: Distinguishes real Office documents from generic ZIP files

---

### Audit Logger (`core/logger.py`)

**Purpose**: Maintain forensic chain of custody.

**Log Format** (CSV):
```csv
timestamp,file_type,offset_hex,file_size,sha256,verification_status,is_duplicate
2024-01-15T10:30:45.123Z,pdf,0x1FA340,245678,9d3f8a2b...,verified,No
```

**Features**:
- **Append-Only**: Logs are never modified (forensic integrity)
- **Complete Information**: All recovery details recorded
- **Reproducible**: Same input produces same log

---

## User Interfaces

### 1. Command-Line Interface (CLI)

**File**: `recover.py`

**Commands**:

#### File Carving
```bash
# Scan disk image
python recover.py scan --image disk.dd --output recovered --types pdf,docx

# Scan folder for signatures
python recover.py scan --folder "C:\Documents" --output recovered --types pdf
```

#### Live Scanning
```bash
# Scan folder
python recover.py live --path "C:\Documents"

# Create baseline
python recover.py live --path "C:\Documents" --save-baseline baseline.json

# Compare with baseline
python recover.py live --path "C:\Documents" --baseline baseline.json
```

#### File Type Report
```bash
# Generate report
python recover.py report --path "C:\Documents" --output report.txt --format text
```

**Features**:
- Scriptable and automatable
- Progress bars with `tqdm`
- Verbose output option
- Professional ASCII banner

---

### 2. Graphical User Interface (GUI)

**File**: `recover_gui.py`

**Three Tabs**:

#### Tab 1: File Carving
- **Mode Selection**: Radio buttons for "Disk Image" or "Folder"
- **Source Selection**: Browse for image file or folder
- **File Type Checkboxes**: PDF, DOCX, JPG
- **Progress Bar**: Real-time scanning progress
- **Recovery Log**: Shows files as they're found with hex offsets and hashes

#### Tab 2: Live Scan & Integrity
- **Scan Path**: Select folder/drive to scan
- **Baseline Management**: Load/save baseline files
- **Extension Filter**: Optional file type filtering
- **Integrity Check**: Compare with baseline to detect changes

#### Tab 3: File Type Report
- **Scan Path**: Select folder/drive
- **Output File**: Optional report file
- **Format Selection**: Text, JSON, or CSV
- **Generate Report**: Creates comprehensive file analysis

**Features**:
- **Dark Theme**: Professional `#2c3e50` background
- **Thread-Safe**: Uses threading to prevent GUI freezing
- **Real-Time Updates**: Queue-based communication
- **Progress Tracking**: Visual progress bars

---

## Workflow Examples

### Example 1: Recovering Deleted PDF from Disk Image

```
1. User creates disk image: disk.dd
2. Opens GUI → File Carving tab
3. Selects "Disk Image" mode
4. Browses to disk.dd
5. Checks "PDF Documents"
6. Clicks "Start Recovery"
7. System:
   - Scans disk image byte-by-byte
   - Finds %PDF signature at offset 0x1FA340
   - Locates %%EOF trailer
   - Extracts PDF data
   - Extracts original filename from metadata: "Annual_Report.pdf"
   - Computes SHA-256 hash
   - Saves to recovered_files/pdf/Annual_Report.pdf
   - Logs to audit trail
8. Result: Deleted PDF recovered with original name!
```

### Example 2: Detecting File Alterations

```
1. User creates baseline:
   python recover.py live --path "C:\Important" --save-baseline baseline.json

2. Later, user modifies a file

3. User compares:
   python recover.py live --path "C:\Important" --baseline baseline.json

4. System reports:
   - Unchanged files: 230
   - Altered files: 1
     [!] report.pdf
       Change Type: content_altered
       Baseline Hash: 9d3f8a2b...
       Current Hash:  1a2b3c4d...  ← Different hash = file was modified!
```

### Example 3: Generating File Type Report

```
1. User runs:
   python recover.py report --path "C:\Users\Documents" --output report.txt

2. System generates:
   ================================================================================
   FILE SCAN REPORT
   ================================================================================
   Total Files: 1,245
   Total Size: 2.45 GB
   
   FILES BY EXTENSION (Top 20)
   --------------------------------------------------------------------------------
     .pdf                   245 files ( 19.7%)
     .docx                  189 files ( 15.2%)
     .jpg                   156 files ( 12.5%)
   ...
   
   FILES BY TYPE (Top 20)
   --------------------------------------------------------------------------------
     PDF Document                         245 files ( 19.7%)
     Microsoft Word                       189 files ( 15.2%)
     JPEG Image                           156 files ( 12.5%)
   ...
```

---

## Technical Concepts

### 1. File Carving

**Definition**: Recovering files from raw data by identifying their content signatures rather than relying on file system metadata.

**Why It Works**: When files are deleted, the file system marks space as available but doesn't immediately erase the data. The file content remains until overwritten.

**Process**:
1. Read raw binary data (disk image or folder)
2. Search for known file signatures (magic bytes)
3. Extract complete file based on header/trailer patterns
4. Verify and save recovered file

---

### 2. Signature-Based Detection

**Magic Bytes**: The first few bytes of a file that identify its type.

**Examples**:
- PDF: `25 50 44 46` = `%PDF`
- JPEG: `FF D8 FF E0` = JPEG header
- ZIP: `50 4B 03 04` = `PK..` (ZIP header)

**Advantages**:
- Works even if file extension is wrong
- Detects embedded files
- Identifies files without metadata

---

### 3. Forensic Chain of Custody

**Definition**: Chronological documentation proving evidence hasn't been tampered with.

**How Tool Maintains It**:
- **SHA-256 Hashing**: Every file is hashed (cryptographically secure)
- **Append-Only Logs**: Logs are never modified
- **Timestamping**: Every operation is timestamped
- **Offset Recording**: Original location is recorded
- **Verification Status**: File verification is documented

---

### 4. Duplicate Detection

**Method**: SHA-256 hash comparison

**Why Important**: 
- Prevents counting same file multiple times
- Identifies files found at different locations
- Reduces false positive counts

**Example**:
- Same PDF found at 3 different disk locations
- All 3 have same SHA-256 hash
- Counted as: 1 unique file, 2 duplicates

---

### 5. Threading Architecture

**Problem**: File scanning is CPU/I/O intensive and would freeze GUI

**Solution**: Separate threads

```
Main Thread (GUI)          Worker Thread (Scanning)
─────────────────          ────────────────────────
│                         │
│ Display GUI             │ Read files
│ Handle user input       │ Scan for signatures
│ Update progress bar     │ Extract files
│ Update log window       │ Compute hashes
│                         │
│ ←──── Queue ────→       │ (thread-safe communication)
│                         │
│ Updates from queue      │ Sends updates via queue
│ every 100ms             │
```

**Benefits**:
- GUI remains responsive
- Real-time progress updates
- Can cancel operations
- No freezing or "Not Responding" messages

---

## File Types Supported

| File Type | Header (Hex) | Trailer (Hex) | Notes |
|-----------|--------------|---------------|-------|
| **PDF** | `25 50 44 46` | `25 25 45 4F 46` | `%PDF` ... `%%EOF` |
| **DOCX** | `50 4B 03 04` | `50 4B 05 06` | ZIP-based, verified |
| **XLSX** | `50 4B 03 04` | `50 4B 05 06` | ZIP-based, verified |
| **DOC** | `D0 CF 11 E0` | None | Legacy Office |
| **XLS** | `D0 CF 11 E0` | None | Legacy Office |
| **GIF** | `47 49 46 38` | `00 3B` | `GIF8` ... `;` |
| **JPG** | `FF D8 FF E0` | `FF D9` | JPEG with JFIF |
| **PNG** | `89 50 4E 47` | `49 45 4E 44...` | PNG with IEND |

---

## Use Cases

### 1. Digital Forensics

**Scenario**: Criminal investigation, need to recover deleted evidence

**Tool Usage**:
1. Create forensic disk image (bit-by-bit copy)
2. Run file carving on image
3. Recover deleted files
4. Document chain of custody
5. Generate report for legal proceedings

**Key Features Used**:
- File carving from disk images
- SHA-256 hashing
- Audit logging
- Original filename recovery

---

### 2. Incident Response

**Scenario**: Security breach, need to find deleted malicious files

**Tool Usage**:
1. Capture disk image quickly
2. Carve for specific file types (executables, documents)
3. Analyze recovered files
4. Document findings

**Key Features Used**:
- File carving
- File type filtering
- Hash-based duplicate detection

---

### 3. File Integrity Monitoring

**Scenario**: Monitor important documents for unauthorized changes

**Tool Usage**:
1. Create baseline of folder
2. Periodically compare with baseline
3. Detect any alterations
4. Investigate changes

**Key Features Used**:
- Live scanning
- Baseline creation
- Integrity comparison
- Change detection

---

### 4. Storage Analysis

**Scenario**: Understand what's taking up space on a drive

**Tool Usage**:
1. Generate file type report
2. See breakdown by file type and size
3. Identify largest files
4. Plan cleanup strategy

**Key Features Used**:
- File scanner
- Statistical analysis
- Size grouping
- Report generation

---

### 5. Data Recovery

**Scenario**: Accidentally deleted important documents

**Tool Usage**:
1. Create disk image (or scan folder directly)
2. Carve for specific file types
3. Recover files with original names
4. Restore needed files

**Key Features Used**:
- File carving (both modes)
- Metadata extraction
- Original filename recovery

---

## Output Structure

### Recovered Files Organization

```
recovered_files/
├── pdf/                    # PDF documents
│   ├── Annual_Report.pdf  ← Original name recovered!
│   └── pdf_offset_0x1FA340.pdf  ← No metadata available
├── docx/                   # DOCX documents (verified)
├── xlsx/                   # XLSX spreadsheets (verified)
├── doc/                    # Legacy DOC files
├── xls/                    # Legacy XLS files
├── images/                 # GIF, JPG, PNG images
├── office_zip/             # Unverified ZIP files
└── recovery_audit_log.csv  # Forensic audit log
```

### Audit Log Format

```csv
timestamp,file_type,offset_hex,file_size,sha256,verification_status,is_duplicate
2024-01-15T10:30:45.123Z,pdf,0x1FA340,245678,9d3f8a2b...,verified,No
2024-01-15T10:30:47.456Z,pdf,disk.dd:0x2B5C80,245678,9d3f8a2b...,verified,Yes
```

---

## Key Algorithms

### 1. Signature Matching Algorithm

**Time Complexity**: O(n×m) where:
- n = size of data to scan
- m = number of signatures

**Optimization**: Uses Python's built-in `find()` which is optimized

**Process**:
```
For each chunk of data:
  For each signature:
    Search for header pattern
    If found:
      Search for trailer pattern
      Extract file data
```

---

### 2. Duplicate Detection Algorithm

**Method**: SHA-256 hash comparison

**Process**:
```
For each recovered file:
  Compute SHA-256 hash
  If hash in seen_hashes:
    Mark as duplicate
  Else:
    Add hash to seen_hashes
    Mark as unique
```

**Efficiency**: O(1) hash lookup using Python sets

---

### 3. File Extraction Algorithm

**With Trailer**:
```
1. Find header at offset H
2. Search for trailer starting at H + header_length
3. If trailer found at offset T:
   Extract [H : T + trailer_length]
4. Verify size < max_size
```

**Without Trailer**:
```
1. Find header at offset H
2. Search for next signature in search window
3. If next signature found at N:
   Extract [H : N]
4. Else:
   Extract [H : H + max_size]
5. Verify size < max_size
```

---

## Security & Forensic Features

### 1. Cryptographic Hashing

- **Algorithm**: SHA-256 (NIST FIPS 180-4)
- **Purpose**: Prove file integrity
- **Output**: 64-character hexadecimal string

### 2. Append-Only Logging

- **Format**: CSV with timestamps
- **Immutability**: Logs are never modified
- **Legal Admissibility**: Suitable for court proceedings

### 3. Chain of Custody

- **Timestamping**: UTC ISO 8601 format
- **Offset Recording**: Hexadecimal disk locations
- **Hash Verification**: SHA-256 for every file
- **Status Tracking**: Verification status documented

### 4. False Positive Reduction

- **Office File Verification**: Checks internal ZIP structure
- **Metadata Extraction**: Verifies file content
- **Duplicate Filtering**: Prevents counting same file multiple times

---

## Performance Characteristics

### File Carving

- **Small Images** (< 1GB): < 1 minute
- **Medium Images** (1-10GB): 5-15 minutes
- **Large Images** (10-100GB): 1-3 hours

**Bottlenecks**:
- Disk I/O speed (primary)
- SHA-256 computation (secondary)
- Memory (for very large images)

### Live Scanning

- **Small Folders** (< 1,000 files): < 10 seconds
- **Medium Folders** (1,000-10,000 files): 30 seconds - 2 minutes
- **Large Folders** (> 10,000 files): 2-10 minutes

**Bottlenecks**:
- File system access speed
- Hash computation
- Number of files

### File Reporting

- **Small Folders**: < 5 seconds
- **Medium Folders**: 10-30 seconds
- **Large Folders**: 30 seconds - 2 minutes

**Optimization**: Can skip detailed file information for faster scanning

---

## Limitations & Considerations

### File Carving Limitations

1. **Fragmented Files**: Files split across multiple locations may not be fully recovered
2. **Overwritten Data**: If space has been reused, files are lost
3. **No Metadata**: Recovered files don't retain original timestamps/permissions
4. **Trailer-Less Files**: Legacy Office files use heuristics (less accurate)

### Live Scanning Limitations

1. **File System Only**: Scans file system, not disk images
2. **Permission Errors**: Some files may be inaccessible
3. **Large Files**: Very large files (> 1GB) slow down hashing
4. **Network Drives**: May be slow or inaccessible

### General Limitations

1. **Memory**: Very large disk images (> 10GB) may require memory mapping
2. **Performance**: Large directories take significant time
3. **False Positives**: Some files may match signatures but be corrupted

---

## Best Practices

### For File Carving

1. **Always Work with Copies**: Never analyze original evidence
2. **Verify Images**: Check disk image integrity before carving
3. **Use Deep Scan**: Enable deep scan for thorough recovery
4. **Check Logs**: Review audit logs for verification status

### For Live Scanning

1. **Regular Baselines**: Create baselines regularly
2. **Secure Storage**: Store baselines securely
3. **Document Changes**: Keep records of expected changes
4. **Automate**: Schedule regular integrity checks

### For File Reporting

1. **Choose Format**: Use JSON for automation, CSV for analysis
2. **Filter Extensions**: Use extension filtering for faster scans
3. **Limit Files**: Use `--max-files` for very large directories
4. **Save Reports**: Always save reports for future reference

---

## Integration & Extensibility

### Adding New File Types

**Simple Process**:
1. Add signature to `core/signatures.py`:
   ```python
   'newtype': FileSignature(
       file_type='newtype',
       header=bytes.fromhex('HEX_PATTERN'),
       trailer=bytes.fromhex('TRAILER_PATTERN')  # Optional
   )
   ```
2. Add output directory mapping in `carver.py`
3. Done! No other code changes needed.

### Extending Functionality

**Easy to Add**:
- New file type signatures
- Additional metadata extraction
- New report formats
- Additional verification methods

**Architecture Supports**:
- Modular design
- Clear interfaces
- Extensible classes
- Plugin-like structure

---

## Summary

The Software Recovery Tool is a **comprehensive file recovery and analysis system** that provides:

✅ **File Carving**: Recover deleted files from disk images and folders  
✅ **Live Scanning**: Monitor file systems for changes  
✅ **File Reporting**: Generate detailed file type analysis  
✅ **Forensic Integrity**: SHA-256 hashing and audit logging  
✅ **User-Friendly**: Both CLI and GUI interfaces  
✅ **Professional**: Cybersecurity-grade implementation  
✅ **Extensible**: Easy to add new features  

**Perfect For**:
- Digital forensics investigations
- Incident response
- Data recovery
- File system analysis
- Compliance auditing
- Educational purposes

The system combines multiple forensic techniques into a single, easy-to-use tool that maintains professional standards while being accessible to both experts and beginners.
