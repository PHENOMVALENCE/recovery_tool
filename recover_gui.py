#!/usr/bin/env python3
"""
Software Recovery Tool - GUI Interface

Professional Tkinter-based GUI for the file carving tool.
Uses threading to prevent GUI freezing during heavy scan operations.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import queue
import sys
from pathlib import Path

from core.signatures import get_signatures_by_types, list_available_types
from core.carver import FileCarver
from core.logger import RecoveryLogger
from core.live_scanner import LiveFileScanner
from core.file_scanner import FileScanReport
from utils.helpers import format_bytes


class GUILogger(RecoveryLogger):
    """
    Custom logger that extends RecoveryLogger to send log messages 
    to GUI queue for thread-safe updates.
    """
    
    def __init__(self, log_file_path: str, log_queue: queue.Queue):
        """
        Initialize GUI logger.
        
        Args:
            log_file_path: Path to CSV log file
            log_queue: Queue for thread-safe GUI updates
        """
        super().__init__(log_file_path)
        self.log_queue = log_queue
    
    def log_recovery(self, file_type: str, offset_hex: str, file_size: int, 
                    sha256: str, verification_status: str = 'unverified'):
        """Log recovery to both CSV and GUI."""
        # Log to CSV (parent class method)
        super().log_recovery(file_type, offset_hex, file_size, sha256, verification_status)
        
        # Check if duplicate
        is_duplicate = ',duplicate' in verification_status
        clean_status = verification_status.replace(',duplicate', '')
        
        # Send to GUI queue
        short_hash = sha256[:16] + '...' if len(sha256) > 16 else sha256
        duplicate_marker = " [DUPLICATE - Skipped]" if is_duplicate else ""
        message = f"[+] {file_type.upper()} found at {offset_hex} | Size: {format_bytes(file_size)} | SHA-256: {short_hash}{duplicate_marker}\n"
        self.log_queue.put(('log', message))
    
    def log_info(self, message: str):
        """Log info message to GUI."""
        self.log_queue.put(('log', f"[*] {message}\n"))
    
    def log_error(self, message: str):
        """Log error message to GUI."""
        self.log_queue.put(('log', f"[-] ERROR: {message}\n"))


class RecoveryToolGUI:
    """
    Main GUI application for the Software Recovery Tool.
    """
    
    def __init__(self, root):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("Software Recovery Tool - File Carving GUI")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        # Variables for file carving
        self.source_image_path = tk.StringVar()
        self.source_folder_path = tk.StringVar()
        self.carving_mode = tk.StringVar(value='image')  # 'image' or 'folder'
        self.output_folder_path = tk.StringVar()
        self.file_types_vars = {
            'pdf': tk.BooleanVar(value=True),
            'docx': tk.BooleanVar(value=True),
            'jpg': tk.BooleanVar(value=True)
        }
        
        # Variables for live scanning
        self.live_scan_path = tk.StringVar()
        self.baseline_path = tk.StringVar()
        self.save_baseline_path = tk.StringVar()
        self.live_extensions = tk.StringVar(value='pdf,docx,jpg')
        
        # Variables for report generation
        self.report_scan_path = tk.StringVar()
        self.report_output_path = tk.StringVar()
        self.report_format = tk.StringVar(value='text')
        self.report_scanning = False
        
        self.scanning = False
        self.live_scanning = False
        self.log_queue = queue.Queue()
        
        # Setup UI
        self.setup_ui()
        
        # Start queue processor for thread-safe GUI updates
        self.process_queue()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main container
        main_frame = tk.Frame(self.root, bg='#2c3e50', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="Software Recovery Tool",
            font=('Arial', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=(0, 10))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # File Carving Tab
        carving_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(carving_frame, text='File Carving')
        self.setup_carving_tab(carving_frame)
        
        # Live Scan Tab
        live_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(live_frame, text='Live Scan & Integrity')
        self.setup_live_scan_tab(live_frame)
    
    def setup_carving_tab(self, parent):
        """Setup the file carving tab."""
        # Title
        title_label = tk.Label(
            parent,
            text="File Carving - Recover Deleted Files",
            font=('Arial', 14, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=(10, 20))
        
        # Mode Selection (Image or Folder)
        mode_frame = tk.Frame(parent, bg='#2c3e50')
        mode_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            mode_frame,
            text="Scan Mode:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Radiobutton(
            mode_frame,
            text="Disk Image (.dd)",
            variable=self.carving_mode,
            value='image',
            command=self.update_source_ui,
            bg='#2c3e50',
            fg='white',
            selectcolor='#34495e',
            activebackground='#2c3e50',
            activeforeground='white',
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Radiobutton(
            mode_frame,
            text="Folder (Scan for Signatures)",
            variable=self.carving_mode,
            value='folder',
            command=self.update_source_ui,
            bg='#2c3e50',
            fg='white',
            selectcolor='#34495e',
            activebackground='#2c3e50',
            activeforeground='white',
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=10)
        
        # Source Selection Frame (will be updated based on mode)
        self.source_frame = tk.Frame(parent, bg='#2c3e50')
        self.source_frame.pack(fill=tk.X, pady=5, padx=20)
        
        self.source_label = tk.Label(
            self.source_frame,
            text="Source Image (.dd):",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        )
        self.source_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.source_entry = tk.Entry(
            self.source_frame,
            textvariable=self.source_image_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        self.source_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.source_browse_button = tk.Button(
            self.source_frame,
            text="Browse",
            command=self.browse_source,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        )
        self.source_browse_button.pack(side=tk.LEFT)
        
        # Initialize UI for image mode
        self.update_source_ui()
        
        # Output Folder Selection
        output_frame = tk.Frame(parent, bg='#2c3e50')
        output_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            output_frame,
            text="Output Folder:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        output_entry = tk.Entry(
            output_frame,
            textvariable=self.output_folder_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(
            output_frame,
            text="Browse",
            command=self.browse_output_folder,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)
        
        # File Types Selection
        types_frame = tk.LabelFrame(
            parent,
            text="File Types to Recover",
            font=('Arial', 11, 'bold'),
            bg='#2c3e50',
            fg='white',
            padx=10,
            pady=10
        )
        types_frame.pack(fill=tk.X, pady=10)
        
        tk.Checkbutton(
            types_frame,
            text="PDF Documents",
            variable=self.file_types_vars['pdf'],
            bg='#2c3e50',
            fg='white',
            selectcolor='#34495e',
            activebackground='#2c3e50',
            activeforeground='white',
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=20)
        
        tk.Checkbutton(
            types_frame,
            text="Word Documents (DOCX)",
            variable=self.file_types_vars['docx'],
            bg='#2c3e50',
            fg='white',
            selectcolor='#34495e',
            activebackground='#2c3e50',
            activeforeground='white',
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=20)
        
        tk.Checkbutton(
            types_frame,
            text="Images (JPG)",
            variable=self.file_types_vars['jpg'],
            bg='#2c3e50',
            fg='white',
            selectcolor='#34495e',
            activebackground='#2c3e50',
            activeforeground='white',
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=20)
        
        # Progress Bar
        progress_frame = tk.Frame(parent, bg='#2c3e50')
        progress_frame.pack(fill=tk.X, pady=10, padx=20)
        
        tk.Label(
            progress_frame,
            text="Progress:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            anchor='w'
        ).pack(fill=tk.X, pady=(0, 5))
        
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = tk.Label(
            progress_frame,
            textvariable=self.progress_var,
            font=('Arial', 9),
            bg='#2c3e50',
            fg='#95a5a6',
            anchor='w'
        )
        self.progress_label.pack(fill=tk.X)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=400
        )
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Control Buttons
        button_frame = tk.Frame(parent, bg='#2c3e50')
        button_frame.pack(fill=tk.X, pady=10, padx=20)
        
        self.start_button = tk.Button(
            button_frame,
            text="Start Recovery",
            command=self.start_recovery,
            bg='#27ae60',
            fg='white',
            font=('Arial', 12, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=30,
            pady=10
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="Stop",
            command=self.stop_recovery,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 12, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=30,
            pady=10,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Log Window
        log_frame = tk.LabelFrame(
            parent,
            text="Recovery Log",
            font=('Arial', 11, 'bold'),
            bg='#2c3e50',
            fg='white',
            padx=10,
            pady=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=20)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Consolas', 9),
            insertbackground='white',
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Initial log message
        self.log("Software Recovery Tool - GUI Interface Ready\n")
        self.log("=" * 60 + "\n")
    
    def setup_live_scan_tab(self, parent):
        """Setup the live scan tab."""
        # Title
        title_label = tk.Label(
            parent,
            text="Live Scan & File Integrity Check",
            font=('Arial', 14, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=(10, 20))
        
        # Scan Path Selection
        scan_path_frame = tk.Frame(parent, bg='#2c3e50')
        scan_path_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            scan_path_frame,
            text="Scan Path:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        scan_entry = tk.Entry(
            scan_path_frame,
            textvariable=self.live_scan_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        scan_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(
            scan_path_frame,
            text="Browse",
            command=self.browse_live_scan_path,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)
        
        # Baseline Selection
        baseline_frame = tk.Frame(parent, bg='#2c3e50')
        baseline_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            baseline_frame,
            text="Baseline File:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        baseline_entry = tk.Entry(
            baseline_frame,
            textvariable=self.baseline_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        baseline_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(
            baseline_frame,
            text="Browse",
            command=self.browse_baseline,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)
        
        # Save Baseline
        save_baseline_frame = tk.Frame(parent, bg='#2c3e50')
        save_baseline_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            save_baseline_frame,
            text="Save Baseline:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        save_baseline_entry = tk.Entry(
            save_baseline_frame,
            textvariable=self.save_baseline_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        save_baseline_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(
            save_baseline_frame,
            text="Browse",
            command=self.browse_save_baseline,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)
        
        # File Extensions Filter
        extensions_frame = tk.Frame(parent, bg='#2c3e50')
        extensions_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(
            extensions_frame,
            text="Extensions:",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        extensions_entry = tk.Entry(
            extensions_frame,
            textvariable=self.live_extensions,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        extensions_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        tk.Label(
            extensions_frame,
            text="(e.g., pdf,docx,jpg or leave empty for all)",
            font=('Arial', 8),
            bg='#2c3e50',
            fg='#95a5a6'
        ).pack(side=tk.LEFT, padx=10)
        
        # Control Buttons
        button_frame = tk.Frame(parent, bg='#2c3e50')
        button_frame.pack(fill=tk.X, pady=15, padx=20)
        
        self.live_start_button = tk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_live_scan,
            bg='#27ae60',
            fg='white',
            font=('Arial', 12, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=30,
            pady=10
        )
        self.live_start_button.pack(side=tk.LEFT, padx=5)
        
        self.live_stop_button = tk.Button(
            button_frame,
            text="Stop",
            command=self.stop_live_scan,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 12, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=30,
            pady=10,
            state=tk.DISABLED
        )
        self.live_stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress for live scan
        live_progress_frame = tk.Frame(parent, bg='#2c3e50')
        live_progress_frame.pack(fill=tk.X, pady=10, padx=20)
        
        self.live_progress_var = tk.StringVar(value="Ready")
        self.live_progress_label = tk.Label(
            live_progress_frame,
            textvariable=self.live_progress_var,
            font=('Arial', 9),
            bg='#2c3e50',
            fg='#95a5a6',
            anchor='w'
        )
        self.live_progress_label.pack(fill=tk.X)
        
        self.live_progress_bar = ttk.Progressbar(
            live_progress_frame,
            mode='indeterminate',
            length=400
        )
        self.live_progress_bar.pack(fill=tk.X, pady=(5, 0))
    
    def update_source_ui(self):
        """Update source UI based on selected mode."""
        mode = self.carving_mode.get()
        
        if mode == 'image':
            self.source_label.config(text="Source Image (.dd):")
            self.source_entry.config(textvariable=self.source_image_path)
            self.source_browse_button.config(command=self.browse_source_image)
        else:  # folder
            self.source_label.config(text="Source Folder:")
            self.source_entry.config(textvariable=self.source_folder_path)
            self.source_browse_button.config(command=self.browse_source_folder)
    
    def browse_source(self):
        """Browse source based on current mode."""
        if self.carving_mode.get() == 'image':
            self.browse_source_image()
        else:
            self.browse_source_folder()
    
    def browse_source_image(self):
        """Open file dialog to select source disk image."""
        filename = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[
                ("Disk Images", "*.dd *.img *.bin *.raw"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.source_image_path.set(filename)
            self.log(f"Source image selected: {filename}\n")
    
    def browse_source_folder(self):
        """Open directory dialog to select source folder."""
        folder = filedialog.askdirectory(title="Select Folder to Scan for File Signatures")
        if folder:
            self.source_folder_path.set(folder)
            self.log(f"Source folder selected: {folder}\n")
    
    def browse_output_folder(self):
        """Open directory dialog to select output folder."""
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_folder_path.set(folder)
            self.log(f"Output folder selected: {folder}\n")
    
    def browse_live_scan_path(self):
        """Open directory dialog to select folder/drive to scan."""
        folder = filedialog.askdirectory(title="Select Folder/Drive to Scan")
        if folder:
            self.live_scan_path.set(folder)
            self.log(f"Live scan path selected: {folder}\n")
    
    def browse_baseline(self):
        """Open file dialog to select baseline JSON file."""
        filename = filedialog.askopenfilename(
            title="Select Baseline File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.baseline_path.set(filename)
            self.log(f"Baseline file selected: {filename}\n")
    
    def browse_save_baseline(self):
        """Open file dialog to save baseline JSON file."""
        filename = filedialog.asksaveasfilename(
            title="Save Baseline As",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.save_baseline_path.set(filename)
            self.log(f"Baseline save path: {filename}\n")
    
    def browse_report_path(self):
        """Open directory dialog to select folder/drive for report."""
        folder = filedialog.askdirectory(title="Select Folder/Drive to Scan for Report")
        if folder:
            self.report_scan_path.set(folder)
            self.log(f"Report scan path selected: {folder}\n")
    
    def browse_report_output(self):
        """Open file dialog to save report."""
        format_ext = {
            'text': '.txt',
            'json': '.json',
            'csv': '.csv'
        }
        ext = format_ext.get(self.report_format.get(), '.txt')
        
        filename = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=ext,
            filetypes=[
                ("Text Files", "*.txt"),
                ("JSON Files", "*.json"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.report_output_path.set(filename)
            self.log(f"Report output path: {filename}\n")
    
    def log(self, message: str):
        """Add message to log window."""
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def process_queue(self):
        """Process messages from the queue for thread-safe GUI updates."""
        try:
            while True:
                msg_type, data = self.log_queue.get_nowait()
                
                if msg_type == 'log':
                    self.log(data)
                elif msg_type == 'progress':
                    bytes_processed, total_size, recovered_count = data
                    self.update_progress(bytes_processed, total_size, recovered_count)
                elif msg_type == 'status':
                    self.progress_var.set(data)
                    self.progress_label.config(fg='white')
                elif msg_type == 'complete':
                    self.on_recovery_complete(data)
                elif msg_type == 'live_progress':
                    file_count, current_file = data
                    self.live_progress_var.set(f"Scanned {file_count} files... {current_file[:50]}...")
                elif msg_type == 'live_complete':
                    self.on_live_scan_complete(data)
                elif msg_type == 'report_progress':
                    file_count, current_file = data
                    self.report_progress_var.set(f"Scanned {file_count:,} files... {current_file[:50]}...")
                elif msg_type == 'report_complete':
                    self.on_report_complete(data)
                
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def update_progress(self, bytes_processed: int, total_size: int, recovered_count: int):
        """Update progress bar."""
        if total_size > 0:
            percentage = (bytes_processed / total_size) * 100
            self.progress_bar['value'] = percentage
            self.progress_var.set(
                f"Processed: {format_bytes(bytes_processed)} / {format_bytes(total_size)} "
                f"({percentage:.1f}%) | Files Recovered: {recovered_count}"
            )
    
    def validate_inputs(self) -> bool:
        """Validate user inputs before starting recovery."""
        mode = self.carving_mode.get()
        
        if mode == 'image':
            if not self.source_image_path.get():
                messagebox.showerror("Error", "Please select a source image file.")
                return False
            
            if not Path(self.source_image_path.get()).exists():
                messagebox.showerror("Error", "Source image file does not exist.")
                return False
        else:  # folder mode
            if not self.source_folder_path.get():
                messagebox.showerror("Error", "Please select a source folder.")
                return False
            
            if not Path(self.source_folder_path.get()).exists():
                messagebox.showerror("Error", "Source folder does not exist.")
                return False
            
            if not Path(self.source_folder_path.get()).is_dir():
                messagebox.showerror("Error", "Source path is not a directory.")
                return False
        
        if not self.output_folder_path.get():
            messagebox.showerror("Error", "Please select an output folder.")
            return False
        
        # Check if at least one file type is selected
        if not any(var.get() for var in self.file_types_vars.values()):
            messagebox.showerror("Error", "Please select at least one file type to recover.")
            return False
        
        return True
    
    def start_recovery(self):
        """Start the recovery process in a separate thread."""
        if not self.validate_inputs():
            return
        
        if self.scanning:
            return
        
        # Clear previous log (optional - keep for history)
        # self.log_text.delete(1.0, tk.END)
        
        self.scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        
        # Get selected file types
        selected_types = [
            file_type for file_type, var in self.file_types_vars.items()
            if var.get()
        ]
        
        mode = self.carving_mode.get()
        source_path = self.source_image_path.get() if mode == 'image' else self.source_folder_path.get()
        mode_name = "Disk Image" if mode == 'image' else "Folder"
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"Starting recovery scan...\n")
        self.log(f"Mode: {mode_name}\n")
        self.log(f"Source: {source_path}\n")
        self.log(f"Output: {self.output_folder_path.get()}\n")
        self.log(f"File types: {', '.join(selected_types).upper()}\n")
        self.log("=" * 60 + "\n\n")
        
        # Start recovery in separate thread
        recovery_thread = threading.Thread(
            target=self.run_recovery,
            args=(selected_types,),
            daemon=True
        )
        recovery_thread.start()
    
    def run_recovery(self, selected_types: list):
        """Run recovery process (called in worker thread)."""
        try:
            # Get signatures for selected file types
            signatures = get_signatures_by_types(selected_types)
            
            if not signatures:
                self.log_queue.put(('log', "[-] Error: No valid file types selected\n"))
                self.log_queue.put(('complete', {'error': True}))
                return
            
            # Initialize GUI logger (handles both CSV and GUI logging)
            output_dir = Path(self.output_folder_path.get())
            log_file = output_dir / 'recovery_audit_log.csv'
            gui_logger = GUILogger(str(log_file), self.log_queue)
            
            # Initialize carver with GUI logger
            carver = FileCarver(
                signatures=signatures,
                output_dir=str(output_dir),
                logger=gui_logger  # GUI logger handles both CSV and GUI updates
            )
            
            mode = self.carving_mode.get()
            
            if mode == 'image':
                # Disk image mode
                image_path = self.source_image_path.get()
                image_size = Path(image_path).stat().st_size
                
                self.log_queue.put(('status', f'Scanning disk image: {Path(image_path).name}'))
                
                # Progress callback for carver
                def progress_callback(bytes_processed, total_size):
                    if not self.scanning:  # Check if stopped
                        return
                    self.log_queue.put(('progress', (bytes_processed, total_size, carver.recovered_count)))
                
                # Run carving on disk image
                stats = carver.carve(image_path, progress_callback=progress_callback)
            else:
                # Folder mode
                folder_path = self.source_folder_path.get()
                
                self.log_queue.put(('status', f'Scanning folder: {Path(folder_path).name}'))
                
                # Count total files for progress
                total_files = sum(1 for _ in Path(folder_path).rglob('*') if _.is_file())
                
                # Progress callback for folder carving
                def progress_callback(files_processed, total_files):
                    if not self.scanning:  # Check if stopped
                        return
                    # Convert to bytes processed for progress bar (approximate)
                    bytes_processed = files_processed * 1024 * 1024  # Estimate
                    total_bytes = total_files * 1024 * 1024
                    self.log_queue.put(('progress', (bytes_processed, total_bytes, carver.recovered_count)))
                
                # Run carving on folder
                stats = carver.carve_folder(folder_path, progress_callback=progress_callback)
            
            if self.scanning:  # Only if not stopped
                self.log_queue.put(('complete', stats))
            else:
                self.log_queue.put(('complete', {'stopped': True}))
            
        except Exception as e:
            error_msg = f"[-] Error during recovery: {str(e)}\n"
            self.log_queue.put(('log', error_msg))
            self.log_queue.put(('complete', {'error': True}))
    
    def on_recovery_complete(self, stats: dict):
        """Handle recovery completion."""
        self.scanning = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if stats.get('stopped'):
            self.log("\n[!] Recovery stopped by user\n")
            self.progress_var.set("Stopped")
            self.progress_label.config(fg='#e74c3c')
        elif stats.get('error'):
            self.progress_var.set("Error occurred")
            self.progress_label.config(fg='#e74c3c')
        else:
            total_recovered = stats.get('total_recovered', 0)
            unique_files = stats.get('unique_files', total_recovered)
            duplicate_files = stats.get('duplicate_files', 0)
            bytes_processed = stats.get('bytes_processed', 0)
            
            self.log("\n" + "=" * 60 + "\n")
            self.log(f"[✓] Recovery complete!\n")
            self.log(f"Total files found: {total_recovered}\n")
            self.log(f"  • Unique files: {unique_files}\n")
            if duplicate_files > 0:
                self.log(f"  • Duplicates: {duplicate_files}\n")
            self.log(f"Bytes processed: {format_bytes(bytes_processed)}\n")
            self.log("=" * 60 + "\n")
            
            # Show unique files in status
            status_text = f"Complete: {unique_files} unique file"
            if unique_files != 1:
                status_text += "s"
            if duplicate_files > 0:
                status_text += f" ({duplicate_files} duplicates)"
            self.progress_var.set(status_text)
            self.progress_label.config(fg='#27ae60')
            
            # Enhanced message box
            message = f"Recovery completed successfully!\n\n"
            message += f"Unique files recovered: {unique_files}\n"
            if duplicate_files > 0:
                message += f"Duplicate files found: {duplicate_files}\n"
            message += f"Total files found: {total_recovered}\n\n"
            message += f"Check the output folder for recovered files."
            
            messagebox.showinfo("Recovery Complete", message)
    
    def stop_recovery(self):
        """Stop the recovery process."""
        if self.scanning:
            self.scanning = False
            self.log("\n[!] Stopping recovery...\n")
    
    def start_live_scan(self):
        """Start live scan in a separate thread."""
        if not self.live_scan_path.get():
            messagebox.showerror("Error", "Please select a folder/drive to scan.")
            return
        
        if self.live_scanning:
            return
        
        self.live_scanning = True
        self.live_start_button.config(state=tk.DISABLED)
        self.live_stop_button.config(state=tk.NORMAL)
        self.live_progress_bar.start()
        
        # Get extensions
        extensions = None
        if self.live_extensions.get().strip():
            extensions = [ext.strip() for ext in self.live_extensions.get().split(',')]
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"Starting live scan...\n")
        self.log(f"Path: {self.live_scan_path.get()}\n")
        if extensions:
            self.log(f"Extensions: {', '.join(extensions)}\n")
        if self.baseline_path.get():
            self.log(f"Baseline: {self.baseline_path.get()}\n")
        self.log("=" * 60 + "\n\n")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(
            target=self.run_live_scan,
            args=(extensions,),
            daemon=True
        )
        scan_thread.start()
    
    def run_live_scan(self, extensions):
        """Run live scan (called in worker thread)."""
        try:
            scanner = LiveFileScanner(self.live_scan_path.get())
            
            file_count = [0]
            
            def progress_callback(count, current_file):
                file_count[0] = count
                self.log_queue.put(('live_progress', (count, current_file)))
            
            # Scan directory
            records = scanner.scan_directory(
                recursive=True,
                file_extensions=extensions,
                progress_callback=progress_callback
            )
            
            self.log_queue.put(('log', f"\n[+] Scan complete: {len(records)} files found\n"))
            
            # Save baseline if requested
            if self.save_baseline_path.get():
                scanner.save_baseline(self.save_baseline_path.get())
                self.log_queue.put(('log', f"[+] Baseline saved to: {self.save_baseline_path.get()}\n"))
            
            # Compare with baseline if provided
            if self.baseline_path.get():
                self.log_queue.put(('log', "\n[+] Comparing with baseline...\n"))
                comparison = scanner.compare_with_baseline(self.baseline_path.get())
                
                self.log_queue.put(('log', "\n" + "=" * 60 + "\n"))
                self.log_queue.put(('log', "INTEGRITY CHECK RESULTS\n"))
                self.log_queue.put(('log', "=" * 60 + "\n"))
                self.log_queue.put(('log', f"[+] Unchanged files: {comparison['unchanged_files']}\n"))
                self.log_queue.put(('log', f"[!] Altered files: {len(comparison['altered_files'])}\n"))
                self.log_queue.put(('log', f"[+] New files: {len(comparison['new_files'])}\n"))
                self.log_queue.put(('log', f"[-] Deleted files: {len(comparison['deleted_files'])}\n\n"))
                
                # Show altered files
                if comparison['altered_files']:
                    self.log_queue.put(('log', "ALTERED FILES:\n"))
                    self.log_queue.put(('log', "-" * 60 + "\n"))
                    for altered in comparison['altered_files'][:20]:  # Limit to 20
                        self.log_queue.put(('log', f"\n[!] {altered['file_path']}\n"))
                        self.log_queue.put(('log', f"    Change Type: {altered['change_type']}\n"))
                        if altered['change_type'] == 'content_altered':
                            self.log_queue.put(('log', f"    Baseline Hash: {altered['baseline_hash'][:32]}...\n"))
                            self.log_queue.put(('log', f"    Current Hash:  {altered['current_hash'][:32]}...\n"))
                            self.log_queue.put(('log', f"    Size: {format_bytes(altered['baseline_size'])} → {format_bytes(altered['current_size'])}\n"))
                
                # Show new files
                if comparison['new_files']:
                    self.log_queue.put(('log', "\nNEW FILES:\n"))
                    self.log_queue.put(('log', "-" * 60 + "\n"))
                    for new_file in comparison['new_files'][:10]:
                        self.log_queue.put(('log', f"[+] {new_file['file_path']} ({format_bytes(new_file['size'])})\n"))
                
                # Show deleted files
                if comparison['deleted_files']:
                    self.log_queue.put(('log', "\nDELETED FILES:\n"))
                    self.log_queue.put(('log', "-" * 60 + "\n"))
                    for deleted in comparison['deleted_files'][:10]:
                        self.log_queue.put(('log', f"[-] {deleted}\n"))
                
                self.log_queue.put(('log', "=" * 60 + "\n"))
            else:
                # Show detailed summary
                total_size = sum(r.size for r in records)
                readonly_count = sum(1 for r in records if r.is_readonly)
                hidden_count = sum(1 for r in records if r.is_hidden)
                
                self.log_queue.put(('log', f"\n" + "=" * 60 + "\n"))
                self.log_queue.put(('log', f"SCAN RESULTS - DETAILED FILE INFORMATION\n"))
                self.log_queue.put(('log', "=" * 60 + "\n"))
                self.log_queue.put(('log', f"Total files: {len(records)}\n"))
                self.log_queue.put(('log', f"Total size: {format_bytes(total_size)}\n"))
                self.log_queue.put(('log', f"Read-only files: {readonly_count}\n"))
                self.log_queue.put(('log', f"Hidden files: {hidden_count}\n"))
                
                # Group by extension
                by_extension = {}
                by_file_type = {}
                for record in records:
                    ext = record.extension or '(no extension)'
                    by_extension[ext] = by_extension.get(ext, 0) + 1
                    file_type = record.file_type or 'Unknown'
                    by_file_type[file_type] = by_file_type.get(file_type, 0) + 1
                
                self.log_queue.put(('log', "\nFiles by extension (top 10):\n"))
                for ext, count in sorted(by_extension.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.log_queue.put(('log', f"  {ext}: {count}\n"))
                
                self.log_queue.put(('log', "\nFiles by type (top 10):\n"))
                for file_type, count in sorted(by_file_type.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.log_queue.put(('log', f"  {file_type}: {count}\n"))
                
                # Show detailed properties for first 10 files
                self.log_queue.put(('log', "\n" + "=" * 60 + "\n"))
                self.log_queue.put(('log', "DETAILED FILE PROPERTIES (First 10 files)\n"))
                self.log_queue.put(('log', "=" * 60 + "\n"))
                for i, record in enumerate(records[:10], 1):
                    from datetime import datetime
                    filename = Path(record.file_path).name
                    self.log_queue.put(('log', f"\n[{i}] {filename}\n"))
                    self.log_queue.put(('log', f"    Path: {record.file_path}\n"))
                    self.log_queue.put(('log', f"    Size: {format_bytes(record.size)}\n"))
                    self.log_queue.put(('log', f"    Type: {record.file_type}\n"))
                    self.log_queue.put(('log', f"    Extension: {record.extension or 'None'}\n"))
                    self.log_queue.put(('log', f"    Modified: {datetime.fromtimestamp(record.modified_time).strftime('%Y-%m-%d %H:%M:%S')}\n"))
                    if record.created_time:
                        self.log_queue.put(('log', f"    Created: {datetime.fromtimestamp(record.created_time).strftime('%Y-%m-%d %H:%M:%S')}\n"))
                    if record.permissions:
                        self.log_queue.put(('log', f"    Permissions: {record.permissions}\n"))
                    if record.owner:
                        self.log_queue.put(('log', f"    Owner: {record.owner}\n"))
                    if record.attributes:
                        self.log_queue.put(('log', f"    Attributes: {record.attributes}\n"))
                    flags = []
                    if record.is_readonly:
                        flags.append('ReadOnly')
                    if record.is_hidden:
                        flags.append('Hidden')
                    if record.is_system:
                        flags.append('System')
                    if flags:
                        self.log_queue.put(('log', f"    Flags: {', '.join(flags)}\n"))
                    if record.sha256 and record.sha256 != 'not_computed':
                        self.log_queue.put(('log', f"    SHA-256: {record.sha256[:32]}...\n"))
                
                self.log_queue.put(('log', "=" * 60 + "\n"))
            
            self.log_queue.put(('live_complete', {'file_count': len(records)}))
            
        except Exception as e:
            error_msg = f"[-] Error during live scan: {str(e)}\n"
            self.log_queue.put(('log', error_msg))
            self.log_queue.put(('live_complete', {'error': True}))
    
    def stop_live_scan(self):
        """Stop the live scan process."""
        if self.live_scanning:
            self.live_scanning = False
            self.log("\n[!] Stopping live scan...\n")
    
    def on_live_scan_complete(self, stats: dict):
        """Handle live scan completion."""
        self.live_scanning = False
        self.live_start_button.config(state=tk.NORMAL)
        self.live_stop_button.config(state=tk.DISABLED)
        self.live_progress_bar.stop()
        
        if stats.get('error'):
            self.live_progress_var.set("Error occurred")
            self.live_progress_label.config(fg='#e74c3c')
        else:
            file_count = stats.get('file_count', 0)
            self.live_progress_var.set(f"Complete: {file_count} files scanned")
            self.live_progress_label.config(fg='#27ae60')
            
            messagebox.showinfo(
                "Scan Complete",
                f"Live scan completed successfully!\n\n"
                f"Files scanned: {file_count}\n"
                f"Check the log for details."
            )
    
    def start_report_generation(self):
        """Start report generation in a separate thread."""
        if not self.report_scan_path.get():
            messagebox.showerror("Error", "Please select a folder/drive to scan.")
            return
        
        if self.report_scanning:
            return
        
        self.report_scanning = True
        self.report_start_button.config(state=tk.DISABLED)
        self.report_progress_bar.start()
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"Starting file type report generation...\n")
        self.log(f"Path: {self.report_scan_path.get()}\n")
        self.log(f"Format: {self.report_format.get().upper()}\n")
        if self.report_output_path.get():
            self.log(f"Output: {self.report_output_path.get()}\n")
        self.log("=" * 60 + "\n\n")
        
        # Start report generation in separate thread
        report_thread = threading.Thread(
            target=self.run_report_generation,
            daemon=True
        )
        report_thread.start()
    
    def run_report_generation(self):
        """Run report generation (called in worker thread)."""
        try:
            scanner = FileScanReport(self.report_scan_path.get())
            
            file_count = [0]
            
            def progress_callback(count, current_file):
                file_count[0] = count
                self.log_queue.put(('report_progress', (count, current_file)))
            
            # Scan
            stats = scanner.scan(
                recursive=True,
                include_details=True,
                progress_callback=progress_callback
            )
            
            self.log_queue.put(('log', f"\n[+] Scan complete: {stats['total_files']:,} files found\n"))
            self.log_queue.put(('log', f"[+] Total size: {format_bytes(stats['total_size'])}\n"))
            
            # Generate report
            output_path = self.report_output_path.get()
            report_format = self.report_format.get()
            
            if output_path:
                scanner.save_report(output_path, format=report_format)
                self.log_queue.put(('log', f"[+] Report saved to: {output_path}\n"))
            else:
                # Display in log
                if report_format == 'text':
                    report_text = scanner.generate_text_report()
                    self.log_queue.put(('log', "\n" + report_text + "\n"))
                elif report_format == 'json':
                    report_json = scanner.generate_json_report()
                    self.log_queue.put(('log', "\n" + report_json + "\n"))
                else:
                    self.log_queue.put(('log', "[!] CSV format requires output file\n"))
            
            self.log_queue.put(('report_complete', {'file_count': stats['total_files']}))
            
        except Exception as e:
            error_msg = f"[-] Error during report generation: {str(e)}\n"
            self.log_queue.put(('log', error_msg))
            self.log_queue.put(('report_complete', {'error': True}))
    
    def on_report_complete(self, stats: dict):
        """Handle report generation completion."""
        self.report_scanning = False
        self.report_start_button.config(state=tk.NORMAL)
        self.report_progress_bar.stop()
        
        if stats.get('error'):
            self.report_progress_var.set("Error occurred")
            self.report_progress_label.config(fg='#e74c3c')
        else:
            file_count = stats.get('file_count', 0)
            self.report_progress_var.set(f"Complete: {file_count:,} files analyzed")
            self.report_progress_label.config(fg='#27ae60')
            
            output_path = self.report_output_path.get()
            if output_path:
                messagebox.showinfo(
                    "Report Complete",
                    f"File type report generated successfully!\n\n"
                    f"Files analyzed: {file_count:,}\n"
                    f"Report saved to: {output_path}"
                )
            else:
                messagebox.showinfo(
                    "Report Complete",
                    f"File type report generated successfully!\n\n"
                    f"Files analyzed: {file_count:,}\n"
                    f"Report displayed in log window."
                )


def main():
    """Main entry point for GUI application."""
    root = tk.Tk()
    app = RecoveryToolGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
