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
        
        # Send to GUI queue
        short_hash = sha256[:16] + '...' if len(sha256) > 16 else sha256
        message = f"[+] {file_type.upper()} found at {offset_hex} | Size: {format_bytes(file_size)} | SHA-256: {short_hash}\n"
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
        
        # Variables
        self.source_image_path = tk.StringVar()
        self.output_folder_path = tk.StringVar()
        self.file_types_vars = {
            'pdf': tk.BooleanVar(value=True),
            'docx': tk.BooleanVar(value=True),
            'jpg': tk.BooleanVar(value=True)
        }
        self.scanning = False
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
        title_label.pack(pady=(0, 20))
        
        # Source Image Selection
        source_frame = tk.Frame(main_frame, bg='#2c3e50')
        source_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            source_frame,
            text="Source Image (.dd):",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='white',
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        source_entry = tk.Entry(
            source_frame,
            textvariable=self.source_image_path,
            font=('Arial', 10),
            bg='#34495e',
            fg='white',
            insertbackground='white'
        )
        source_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(
            source_frame,
            text="Browse",
            command=self.browse_source_image,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief=tk.FLAT,
            padx=15
        ).pack(side=tk.LEFT)
        
        # Output Folder Selection
        output_frame = tk.Frame(main_frame, bg='#2c3e50')
        output_frame.pack(fill=tk.X, pady=5)
        
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
            main_frame,
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
        progress_frame = tk.Frame(main_frame, bg='#2c3e50')
        progress_frame.pack(fill=tk.X, pady=10)
        
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
        button_frame = tk.Frame(main_frame, bg='#2c3e50')
        button_frame.pack(fill=tk.X, pady=10)
        
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
            main_frame,
            text="Recovery Log",
            font=('Arial', 11, 'bold'),
            bg='#2c3e50',
            fg='white',
            padx=10,
            pady=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
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
    
    def browse_output_folder(self):
        """Open directory dialog to select output folder."""
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_folder_path.set(folder)
            self.log(f"Output folder selected: {folder}\n")
    
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
        if not self.source_image_path.get():
            messagebox.showerror("Error", "Please select a source image file.")
            return False
        
        if not Path(self.source_image_path.get()).exists():
            messagebox.showerror("Error", "Source image file does not exist.")
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
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"Starting recovery scan...\n")
        self.log(f"Source: {self.source_image_path.get()}\n")
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
            
            image_path = self.source_image_path.get()
            image_size = Path(image_path).stat().st_size
            
            self.log_queue.put(('status', f'Scanning disk image: {Path(image_path).name}'))
            
            # Progress callback for carver
            def progress_callback(bytes_processed, total_size):
                if not self.scanning:  # Check if stopped
                    return
                self.log_queue.put(('progress', (bytes_processed, total_size, carver.recovered_count)))
            
            # Run carving
            stats = carver.carve(image_path, progress_callback=progress_callback)
            
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
            bytes_processed = stats.get('bytes_processed', 0)
            
            self.log("\n" + "=" * 60 + "\n")
            self.log(f"[✓] Recovery complete!\n")
            self.log(f"Files recovered: {total_recovered}\n")
            self.log(f"Bytes processed: {format_bytes(bytes_processed)}\n")
            self.log("=" * 60 + "\n")
            
            self.progress_var.set(f"Complete: {total_recovered} files recovered")
            self.progress_label.config(fg='#27ae60')
            
            messagebox.showinfo(
                "Recovery Complete",
                f"Recovery completed successfully!\n\n"
                f"Files recovered: {total_recovered}\n"
                f"Check the output folder for recovered files."
            )
    
    def stop_recovery(self):
        """Stop the recovery process."""
        if self.scanning:
            self.scanning = False
            self.log("\n[!] Stopping recovery...\n")


def main():
    """Main entry point for GUI application."""
    root = tk.Tk()
    app = RecoveryToolGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
