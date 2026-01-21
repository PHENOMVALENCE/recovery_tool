"""
Progress Bar Utilities

Provides real-time progress feedback during file carving operations.
"""

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class ProgressTracker:
    """
    Progress tracker for file carving operations.
    
    Provides real-time feedback on scan progress.
    """
    
    def __init__(self, total_size: int, verbose: bool = True):
        """
        Initialize progress tracker.
        
        Args:
            total_size: Total size of disk image in bytes
            verbose: Whether to show progress bar
        """
        self.total_size = total_size
        self.verbose = verbose
        self.current_offset = 0
        self.recovered_count = 0
        self.current_file_type = None
        
        if TQDM_AVAILABLE and verbose:
            self.pbar = tqdm(
                total=total_size,
                unit='B',
                unit_scale=True,
                unit_divisor=1024,
                desc='Scanning',
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
            )
        else:
            self.pbar = None
    
    def update(self, bytes_processed: int, recovered_count: int = None):
        """
        Update progress.
        
        Args:
            bytes_processed: Number of bytes processed so far
            recovered_count: Optional number of files recovered
        """
        self.current_offset = bytes_processed
        
        if recovered_count is not None:
            self.recovered_count = recovered_count
        
        if self.pbar:
            self.pbar.update(bytes_processed - self.pbar.n)
        
        if recovered_count is not None and self.pbar:
            self.pbar.set_postfix({'Recovered': recovered_count})
    
    def set_current_file_type(self, file_type: str):
        """Set current file type being scanned."""
        self.current_file_type = file_type
        if self.pbar:
            self.pbar.set_description(f'Scanning ({file_type})')
    
    def close(self):
        """Close progress bar."""
        if self.pbar:
            self.pbar.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
