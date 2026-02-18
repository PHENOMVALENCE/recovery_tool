# Digital Forensics Recovery System

A production-quality Software Recovery & Integrity Monitoring System in Python with a professional desktop GUI using PySide6 (Qt).

## Features

### 1. Disk Image File Carving
- Accept raw disk images (`.dd`, `.img`, `.raw`, `.bin`)
- Chunked scanning (1MB blocks)
- Signature-based file carving for PDF, JPG, PNG, DOCX, XLSX
- Header + trailer detection
- DOCX/XLSX validation (word/document.xml, xl/workbook.xml)
- Output organized by file type
- SHA-256 hashing for every recovered file
- Duplicate detection via hash comparison
- CSV audit log (timestamp, type, offset, size, SHA-256, verification, duplicate status)

### 2. Integrity Monitoring
- Select folder for monitoring
- Create baseline (JSON: path, size, modified time, SHA-256)
- Compare current scan with baseline
- Detect new, modified, deleted, unchanged files
- Export integrity report (CSV)

### 3. Reporting
- Summary: total recovered, by type, total size, duplicates, verification failures
- Export summary to CSV

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

## Architecture

```
/core
    signatures.py   - File signatures for carving
    carver.py       - File carving engine
    verifier.py     - DOCX/XLSX validation
    hasher.py       - SHA-256 hashing
    logger.py       - Audit CSV logging
    integrity.py    - Baseline and comparison
    reports.py      - Summary and export

/ui
    main_window.py  - Main window with tabs
    theme.py        - Dark theme stylesheet
    dashboard_tab.py
    recovery_tab.py - Disk Recovery
    results_tab.py  - Results Viewer
    integrity_tab.py
    reports_tab.py

main.py
```

## Requirements

- Python 3.8+
- PySide6
- tqdm (optional)

## License

Internal/educational use.
