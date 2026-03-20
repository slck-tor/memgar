"""
Memgar Watch Mode
=================

Monitor files for changes and scan automatically.

Usage:
    from memgar.watcher import MemoryWatcher
    
    # Watch a file
    watcher = MemoryWatcher()
    watcher.watch("memories.txt")
    
    # CLI usage
    memgar watch memories.txt
    memgar watch ./data/ --pattern "*.txt"
"""

import os
import sys
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Callable, Set, Dict
from dataclasses import dataclass, field
import threading
import signal

from .scanner import MemoryScanner
from .models import Decision, AnalysisResult


@dataclass
class WatchEvent:
    """File watch event."""
    path: str
    event_type: str  # created, modified, deleted
    timestamp: datetime
    results: List[AnalysisResult] = field(default_factory=list)


@dataclass
class WatchStats:
    """Watch session statistics."""
    files_watched: int = 0
    total_scans: int = 0
    threats_found: int = 0
    start_time: Optional[datetime] = None
    last_scan: Optional[datetime] = None


class MemoryWatcher:
    """
    Watch files for changes and scan automatically.
    
    Example:
        watcher = MemoryWatcher(on_threat=lambda e: print(f"Threat: {e}"))
        watcher.watch("memories.txt")
        
        # Or watch directory
        watcher.watch_directory("./data", pattern="*.txt")
    """
    
    def __init__(
        self,
        mode: str = "protect",
        interval: float = 1.0,
        on_change: Optional[Callable[[WatchEvent], None]] = None,
        on_threat: Optional[Callable[[WatchEvent], None]] = None,
        verbose: bool = True,
    ):
        """
        Initialize watcher.
        
        Args:
            mode: Scan mode (protect, monitor, audit)
            interval: Check interval in seconds
            on_change: Callback for any file change
            on_threat: Callback when threat detected
            verbose: Print status messages
        """
        self._scanner = MemoryScanner(mode=mode)
        self._interval = interval
        self._on_change = on_change
        self._on_threat = on_threat
        self._verbose = verbose
        self._running = False
        self._stats = WatchStats()
        self._file_hashes: Dict[str, str] = {}
        self._watched_files: Set[str] = set()
        self._watch_thread: Optional[threading.Thread] = None
    
    def _log(self, message: str, level: str = "info") -> None:
        """Log message if verbose."""
        if not self._verbose:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        icons = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "🚫",
            "watch": "👁️",
            "scan": "🔍",
        }
        icon = icons.get(level, "")
        
        print(f"[{timestamp}] {icon} {message}")
    
    def _get_file_hash(self, filepath: str) -> str:
        """Get MD5 hash of file contents."""
        try:
            with open(filepath, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def _scan_file(self, filepath: str) -> List[AnalysisResult]:
        """Scan file and return results."""
        results = []
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            
            for line in lines:
                result = self._scanner.scan(line)
                results.append(result)
                
                if result.decision == Decision.BLOCK:
                    self._stats.threats_found += 1
            
            self._stats.total_scans += len(lines)
            self._stats.last_scan = datetime.now()
            
        except Exception as e:
            self._log(f"Error scanning {filepath}: {e}", "error")
        
        return results
    
    def _check_file(self, filepath: str) -> Optional[WatchEvent]:
        """Check if file changed and scan if needed."""
        current_hash = self._get_file_hash(filepath)
        previous_hash = self._file_hashes.get(filepath)
        
        if current_hash != previous_hash:
            self._file_hashes[filepath] = current_hash
            
            if previous_hash is None:
                event_type = "created"
            else:
                event_type = "modified"
            
            self._log(f"File {event_type}: {filepath}", "watch")
            
            # Scan file
            results = self._scan_file(filepath)
            
            event = WatchEvent(
                path=filepath,
                event_type=event_type,
                timestamp=datetime.now(),
                results=results,
            )
            
            # Check for threats
            threats = [r for r in results if r.decision != Decision.ALLOW]
            if threats:
                self._log(
                    f"Found {len(threats)} threats in {filepath}",
                    "warning"
                )
                if self._on_threat:
                    self._on_threat(event)
            else:
                self._log(
                    f"Scanned {len(results)} entries - all clear",
                    "success"
                )
            
            if self._on_change:
                self._on_change(event)
            
            return event
        
        return None
    
    def _watch_loop(self) -> None:
        """Main watch loop."""
        self._log(f"Watching {len(self._watched_files)} file(s)...", "watch")
        self._log(f"Press Ctrl+C to stop", "info")
        
        while self._running:
            for filepath in list(self._watched_files):
                if not os.path.exists(filepath):
                    self._log(f"File deleted: {filepath}", "warning")
                    self._watched_files.discard(filepath)
                    continue
                
                self._check_file(filepath)
            
            time.sleep(self._interval)
    
    def watch(
        self,
        filepath: str,
        blocking: bool = True,
    ) -> None:
        """
        Watch a single file.
        
        Args:
            filepath: Path to file
            blocking: Block main thread
        """
        filepath = str(Path(filepath).resolve())
        
        if not os.path.exists(filepath):
            self._log(f"File not found: {filepath}", "error")
            return
        
        self._watched_files.add(filepath)
        self._file_hashes[filepath] = self._get_file_hash(filepath)
        self._stats.files_watched += 1
        self._stats.start_time = datetime.now()
        self._running = True
        
        # Initial scan
        self._log(f"Initial scan of {filepath}", "scan")
        self._scan_file(filepath)
        
        if blocking:
            try:
                self._watch_loop()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._watch_thread = threading.Thread(target=self._watch_loop)
            self._watch_thread.daemon = True
            self._watch_thread.start()
    
    def watch_directory(
        self,
        directory: str,
        pattern: str = "*.txt",
        recursive: bool = False,
        blocking: bool = True,
    ) -> None:
        """
        Watch all matching files in directory.
        
        Args:
            directory: Directory path
            pattern: File pattern (glob)
            recursive: Watch subdirectories
            blocking: Block main thread
        """
        directory = Path(directory).resolve()
        
        if not directory.exists():
            self._log(f"Directory not found: {directory}", "error")
            return
        
        # Find matching files
        if recursive:
            files = list(directory.rglob(pattern))
        else:
            files = list(directory.glob(pattern))
        
        if not files:
            self._log(f"No files matching '{pattern}' in {directory}", "warning")
            return
        
        self._log(f"Found {len(files)} file(s) matching '{pattern}'", "info")
        
        for f in files:
            filepath = str(f.resolve())
            self._watched_files.add(filepath)
            self._file_hashes[filepath] = self._get_file_hash(filepath)
            self._stats.files_watched += 1
        
        self._stats.start_time = datetime.now()
        self._running = True
        
        # Initial scan
        self._log("Running initial scan...", "scan")
        for f in files:
            self._scan_file(str(f))
        
        if blocking:
            try:
                self._watch_loop()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._watch_thread = threading.Thread(target=self._watch_loop)
            self._watch_thread.daemon = True
            self._watch_thread.start()
    
    def add_file(self, filepath: str) -> None:
        """Add file to watch list."""
        filepath = str(Path(filepath).resolve())
        
        if os.path.exists(filepath):
            self._watched_files.add(filepath)
            self._file_hashes[filepath] = self._get_file_hash(filepath)
            self._stats.files_watched += 1
            self._log(f"Added to watch: {filepath}", "info")
    
    def remove_file(self, filepath: str) -> None:
        """Remove file from watch list."""
        filepath = str(Path(filepath).resolve())
        self._watched_files.discard(filepath)
        self._file_hashes.pop(filepath, None)
        self._log(f"Removed from watch: {filepath}", "info")
    
    def stop(self) -> None:
        """Stop watching."""
        self._running = False
        self._log("Watch stopped", "info")
        self._print_summary()
    
    def _print_summary(self) -> None:
        """Print session summary."""
        if not self._stats.start_time:
            return
        
        duration = datetime.now() - self._stats.start_time
        minutes = duration.total_seconds() / 60
        
        print("\n" + "=" * 50)
        print("📊 Watch Session Summary")
        print("=" * 50)
        print(f"  Duration: {minutes:.1f} minutes")
        print(f"  Files watched: {self._stats.files_watched}")
        print(f"  Total scans: {self._stats.total_scans}")
        print(f"  Threats found: {self._stats.threats_found}")
        print("=" * 50)
    
    @property
    def stats(self) -> WatchStats:
        """Get watch statistics."""
        return self._stats
    
    @property
    def is_running(self) -> bool:
        """Check if watcher is running."""
        return self._running


def watch_file(filepath: str, **kwargs) -> None:
    """
    Quick function to watch a file.
    
    Args:
        filepath: Path to file
        **kwargs: Arguments for MemoryWatcher
    """
    watcher = MemoryWatcher(**kwargs)
    watcher.watch(filepath)


def watch_directory(directory: str, pattern: str = "*.txt", **kwargs) -> None:
    """
    Quick function to watch a directory.
    
    Args:
        directory: Directory path
        pattern: File pattern
        **kwargs: Arguments for MemoryWatcher
    """
    watcher = MemoryWatcher(**kwargs)
    watcher.watch_directory(directory, pattern=pattern)
