"""
Memgar Scanner
==============

Batch scanning capabilities for memory files and directories.

Supports:
- JSON files (arrays or objects with memory entries)
- SQLite databases with memory tables
- Plain text files (one memory per line)
- Directory scanning with recursive option
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Generator

from memgar.analyzer import Analyzer
from memgar.models import (
    AnalysisResult,
    Decision,
    MemoryEntry,
    ScanResult,
    ThreatMatch,
)


class Scanner:
    """
    Batch scanner for memory files and directories.
    
    Scans various file formats for memory poisoning threats:
    - JSON files containing memory entries
    - SQLite databases with memory tables  
    - Plain text files (one entry per line)
    - Directories with recursive scanning
    
    Attributes:
        analyzer: The analyzer instance to use for scanning
        
    Example:
        >>> scanner = Scanner()
        >>> result = scanner.scan_file("./memories.json")
        >>> print(f"Found {result.threat_count} threats in {result.total} entries")
    """
    
    def __init__(self, analyzer: Analyzer | None = None) -> None:
        """
        Initialize the scanner.
        
        Args:
            analyzer: Optional analyzer instance. Creates default if not provided.
        """
        self.analyzer = analyzer or Analyzer()
    
    def scan_memories(self, memories: list[dict[str, Any] | str]) -> ScanResult:
        """
        Scan a list of memory entries.
        
        Args:
            memories: List of memory entries. Each entry can be:
                     - A string (the content itself)
                     - A dict with at least a 'content' key
        
        Returns:
            ScanResult with aggregated statistics and all detected threats
        """
        start_time = time.perf_counter()
        
        result = ScanResult()
        result.total = len(memories)
        
        for memory in memories:
            # Convert to MemoryEntry
            if isinstance(memory, str):
                entry = MemoryEntry(content=memory)
            elif isinstance(memory, dict):
                content = memory.get("content", "")
                if not content:
                    # Try other common field names
                    content = memory.get("text", memory.get("message", memory.get("value", "")))
                entry = MemoryEntry(
                    content=content,
                    source_type=memory.get("source_type", memory.get("type", "unknown")),
                    source_id=memory.get("source_id", memory.get("id", None)),
                )
            else:
                result.errors.append(f"Invalid memory entry type: {type(memory)}")
                continue
            
            # Skip empty entries
            if not entry.content.strip():
                result.clean += 1
                continue
            
            # Analyze
            try:
                analysis = self.analyzer.analyze(entry)
                result.results.append(analysis)
                
                # Update counts
                if analysis.decision == Decision.ALLOW:
                    if analysis.threats:
                        result.suspicious += 1
                    else:
                        result.clean += 1
                elif analysis.decision == Decision.BLOCK:
                    result.blocked += 1
                    result.threats.extend(analysis.threats)
                elif analysis.decision == Decision.QUARANTINE:
                    result.quarantined += 1
                    result.threats.extend(analysis.threats)
                    
            except Exception as e:
                result.errors.append(f"Analysis error: {str(e)}")
        
        result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        return result
    
    def scan_file(self, path: str) -> ScanResult:
        """
        Scan a file for memory poisoning threats.
        
        Automatically detects file format based on extension:
        - .json: JSON array or object
        - .db, .sqlite, .sqlite3: SQLite database
        - .txt, .log, others: Plain text (one entry per line)
        
        Args:
            path: Path to the file to scan
        
        Returns:
            ScanResult with analysis of all entries in the file
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return ScanResult(errors=[f"File not found: {path}"])
        
        if not path_obj.is_file():
            return ScanResult(errors=[f"Not a file: {path}"])
        
        extension = path_obj.suffix.lower()
        
        try:
            if extension == ".json":
                return self._scan_json_file(path)
            elif extension in (".db", ".sqlite", ".sqlite3"):
                return self._scan_sqlite_file(path)
            else:
                return self._scan_text_file(path)
        except Exception as e:
            return ScanResult(errors=[f"Error scanning {path}: {str(e)}"])
    
    def scan_directory(
        self, 
        path: str, 
        recursive: bool = True,
        extensions: list[str] | None = None
    ) -> ScanResult:
        """
        Scan a directory for memory files.
        
        Args:
            path: Path to the directory
            recursive: Whether to scan subdirectories
            extensions: File extensions to scan (default: json, txt, db)
        
        Returns:
            ScanResult with aggregated results from all files
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return ScanResult(errors=[f"Directory not found: {path}"])
        
        if not path_obj.is_dir():
            return ScanResult(errors=[f"Not a directory: {path}"])
        
        # Default extensions to scan
        if extensions is None:
            extensions = [".json", ".txt", ".db", ".sqlite", ".sqlite3", ".log"]
        
        # Collect all files
        files = []
        if recursive:
            for ext in extensions:
                files.extend(path_obj.rglob(f"*{ext}"))
        else:
            for ext in extensions:
                files.extend(path_obj.glob(f"*{ext}"))
        
        # Scan each file and merge results
        combined_result = ScanResult()
        
        for file_path in files:
            file_result = self.scan_file(str(file_path))
            combined_result = combined_result.merge(file_result)
        
        return combined_result
    
    def _scan_json_file(self, path: str) -> ScanResult:
        """Scan a JSON file for memory entries."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Handle different JSON structures
        memories: list[dict[str, Any] | str] = []
        
        if isinstance(data, list):
            # Array of memories
            memories = data
        elif isinstance(data, dict):
            # Try common patterns
            if "memories" in data:
                memories = data["memories"]
            elif "entries" in data:
                memories = data["entries"]
            elif "data" in data:
                memories = data["data"]
            elif "content" in data:
                # Single memory entry
                memories = [data]
            else:
                # Treat each value as a potential memory
                for key, value in data.items():
                    if isinstance(value, str):
                        memories.append({"content": value, "source_id": key})
                    elif isinstance(value, dict) and "content" in value:
                        memories.append(value)
        
        return self.scan_memories(memories)
    
    def _scan_sqlite_file(self, path: str) -> ScanResult:
        """Scan a SQLite database for memory entries."""
        memories: list[dict[str, Any]] = []
        
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row["name"] for row in cursor.fetchall()]
            
            # Common memory table names
            memory_tables = [
                t for t in tables 
                if any(keyword in t.lower() for keyword in 
                       ["memory", "message", "chat", "conversation", "history", "log"])
            ]
            
            # If no memory tables found, try all tables
            if not memory_tables:
                memory_tables = tables
            
            for table in memory_tables:
                try:
                    # Get column names
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row["name"] for row in cursor.fetchall()]
                    
                    # Find content column
                    content_col = None
                    for col_name in ["content", "text", "message", "value", "body", "data"]:
                        if col_name in columns:
                            content_col = col_name
                            break
                    
                    if not content_col:
                        continue
                    
                    # Get all rows
                    cursor.execute(f"SELECT * FROM {table}")
                    for row in cursor.fetchall():
                        content = row[content_col]
                        if content:
                            memories.append({
                                "content": str(content),
                                "source_type": f"sqlite:{table}",
                                "source_id": str(row.get("id", row.get("rowid", "")))
                            })
                except sqlite3.Error:
                    continue
                    
        finally:
            conn.close()
        
        return self.scan_memories(memories)
    
    def _scan_text_file(self, path: str) -> ScanResult:
        """Scan a plain text file (one memory per line)."""
        memories: list[str] = []
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # Skip comments and empty lines
                    memories.append(line)
        
        return self.scan_memories(memories)
    
    def stream_scan(
        self, 
        memories: list[dict[str, Any] | str]
    ) -> Generator[AnalysisResult, None, None]:
        """
        Generator that yields results as they're analyzed.
        
        Useful for progress tracking with large batches.
        
        Args:
            memories: List of memory entries to scan
        
        Yields:
            AnalysisResult for each entry as it's analyzed
        """
        for memory in memories:
            if isinstance(memory, str):
                entry = MemoryEntry(content=memory)
            elif isinstance(memory, dict):
                content = memory.get("content", memory.get("text", ""))
                entry = MemoryEntry(
                    content=content,
                    source_type=memory.get("source_type", "unknown"),
                    source_id=memory.get("source_id", None),
                )
            else:
                continue
            
            yield self.analyzer.analyze(entry)


class FileWatcher:
    """
    Watch files or directories for changes and scan new content.
    
    This is a basic implementation. In production, you'd use
    watchdog or similar library for efficient file watching.
    """
    
    def __init__(
        self, 
        scanner: Scanner | None = None,
        callback: Any | None = None
    ) -> None:
        """
        Initialize the file watcher.
        
        Args:
            scanner: Scanner instance to use
            callback: Function to call when threats are found
        """
        self.scanner = scanner or Scanner()
        self.callback = callback
        self._file_hashes: dict[str, str] = {}
    
    def check_file(self, path: str) -> ScanResult | None:
        """
        Check if a file has changed and scan it if so.
        
        Returns ScanResult if file changed, None if unchanged.
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return None
        
        # Simple change detection using mtime
        current_hash = str(path_obj.stat().st_mtime)
        
        if path in self._file_hashes:
            if self._file_hashes[path] == current_hash:
                return None
        
        self._file_hashes[path] = current_hash
        result = self.scanner.scan_file(path)
        
        if self.callback and result.threat_count > 0:
            self.callback(path, result)
        
        return result"""
Memgar Scanner
==============

Batch scanning capabilities for memory files and directories.

Supports:
- JSON files (arrays or objects with memory entries)
- SQLite databases with memory tables
- Plain text files (one memory per line)
- Directory scanning with recursive option
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Generator

from memgar.analyzer import Analyzer
from memgar.models import (
    AnalysisResult,
    Decision,
    MemoryEntry,
    ScanResult,
    ThreatMatch,
)


class Scanner:
    """
    Batch scanner for memory files and directories.
    
    Scans various file formats for memory poisoning threats:
    - JSON files containing memory entries
    - SQLite databases with memory tables  
    - Plain text files (one entry per line)
    - Directories with recursive scanning
    
    Attributes:
        analyzer: The analyzer instance to use for scanning
        
    Example:
        >>> scanner = Scanner()
        >>> result = scanner.scan_file("./memories.json")
        >>> print(f"Found {result.threat_count} threats in {result.total} entries")
    """
    
    def __init__(self, analyzer: Analyzer | None = None) -> None:
        """
        Initialize the scanner.
        
        Args:
            analyzer: Optional analyzer instance. Creates default if not provided.
        """
        self.analyzer = analyzer or Analyzer()
    
    def scan_memories(self, memories: list[dict[str, Any] | str]) -> ScanResult:
        """
        Scan a list of memory entries.
        
        Args:
            memories: List of memory entries. Each entry can be:
                     - A string (the content itself)
                     - A dict with at least a 'content' key
        
        Returns:
            ScanResult with aggregated statistics and all detected threats
        """
        start_time = time.perf_counter()
        
        result = ScanResult()
        result.total = len(memories)
        
        for memory in memories:
            # Convert to MemoryEntry
            if isinstance(memory, str):
                entry = MemoryEntry(content=memory)
            elif isinstance(memory, dict):
                content = memory.get("content", "")
                if not content:
                    # Try other common field names
                    content = memory.get("text", memory.get("message", memory.get("value", "")))
                entry = MemoryEntry(
                    content=content,
                    source_type=memory.get("source_type", memory.get("type", "unknown")),
                    source_id=memory.get("source_id", memory.get("id", None)),
                )
            else:
                result.errors.append(f"Invalid memory entry type: {type(memory)}")
                continue
            
            # Skip empty entries
            if not entry.content.strip():
                result.clean += 1
                continue
            
            # Analyze
            try:
                analysis = self.analyzer.analyze(entry)
                result.results.append(analysis)
                
                # Update counts
                if analysis.decision == Decision.ALLOW:
                    if analysis.threats:
                        result.suspicious += 1
                    else:
                        result.clean += 1
                elif analysis.decision == Decision.BLOCK:
                    result.blocked += 1
                    result.threats.extend(analysis.threats)
                elif analysis.decision == Decision.QUARANTINE:
                    result.quarantined += 1
                    result.threats.extend(analysis.threats)
                    
            except Exception as e:
                result.errors.append(f"Analysis error: {str(e)}")
        
        result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        return result
    
    def scan_file(self, path: str) -> ScanResult:
        """
        Scan a file for memory poisoning threats.
        
        Automatically detects file format based on extension:
        - .json: JSON array or object
        - .db, .sqlite, .sqlite3: SQLite database
        - .txt, .log, others: Plain text (one entry per line)
        
        Args:
            path: Path to the file to scan
        
        Returns:
            ScanResult with analysis of all entries in the file
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return ScanResult(errors=[f"File not found: {path}"])
        
        if not path_obj.is_file():
            return ScanResult(errors=[f"Not a file: {path}"])
        
        extension = path_obj.suffix.lower()
        
        try:
            if extension == ".json":
                return self._scan_json_file(path)
            elif extension in (".db", ".sqlite", ".sqlite3"):
                return self._scan_sqlite_file(path)
            else:
                return self._scan_text_file(path)
        except Exception as e:
            return ScanResult(errors=[f"Error scanning {path}: {str(e)}"])
    
    def scan_directory(
        self, 
        path: str, 
        recursive: bool = True,
        extensions: list[str] | None = None
    ) -> ScanResult:
        """
        Scan a directory for memory files.
        
        Args:
            path: Path to the directory
            recursive: Whether to scan subdirectories
            extensions: File extensions to scan (default: json, txt, db)
        
        Returns:
            ScanResult with aggregated results from all files
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return ScanResult(errors=[f"Directory not found: {path}"])
        
        if not path_obj.is_dir():
            return ScanResult(errors=[f"Not a directory: {path}"])
        
        # Default extensions to scan
        if extensions is None:
            extensions = [".json", ".txt", ".db", ".sqlite", ".sqlite3", ".log"]
        
        # Collect all files
        files = []
        if recursive:
            for ext in extensions:
                files.extend(path_obj.rglob(f"*{ext}"))
        else:
            for ext in extensions:
                files.extend(path_obj.glob(f"*{ext}"))
        
        # Scan each file and merge results
        combined_result = ScanResult()
        
        for file_path in files:
            file_result = self.scan_file(str(file_path))
            combined_result = combined_result.merge(file_result)
        
        return combined_result
    
    def _scan_json_file(self, path: str) -> ScanResult:
        """Scan a JSON file for memory entries."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Handle different JSON structures
        memories: list[dict[str, Any] | str] = []
        
        if isinstance(data, list):
            # Array of memories
            memories = data
        elif isinstance(data, dict):
            # Try common patterns
            if "memories" in data:
                memories = data["memories"]
            elif "entries" in data:
                memories = data["entries"]
            elif "data" in data:
                memories = data["data"]
            elif "content" in data:
                # Single memory entry
                memories = [data]
            else:
                # Treat each value as a potential memory
                for key, value in data.items():
                    if isinstance(value, str):
                        memories.append({"content": value, "source_id": key})
                    elif isinstance(value, dict) and "content" in value:
                        memories.append(value)
        
        return self.scan_memories(memories)
    
    def _scan_sqlite_file(self, path: str) -> ScanResult:
        """Scan a SQLite database for memory entries."""
        memories: list[dict[str, Any]] = []
        
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row["name"] for row in cursor.fetchall()]
            
            # Common memory table names
            memory_tables = [
                t for t in tables 
                if any(keyword in t.lower() for keyword in 
                       ["memory", "message", "chat", "conversation", "history", "log"])
            ]
            
            # If no memory tables found, try all tables
            if not memory_tables:
                memory_tables = tables
            
            for table in memory_tables:
                try:
                    # Get column names
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row["name"] for row in cursor.fetchall()]
                    
                    # Find content column
                    content_col = None
                    for col_name in ["content", "text", "message", "value", "body", "data"]:
                        if col_name in columns:
                            content_col = col_name
                            break
                    
                    if not content_col:
                        continue
                    
                    # Get all rows
                    cursor.execute(f"SELECT * FROM {table}")
                    for row in cursor.fetchall():
                        content = row[content_col]
                        if content:
                            memories.append({
                                "content": str(content),
                                "source_type": f"sqlite:{table}",
                                "source_id": str(row.get("id", row.get("rowid", "")))
                            })
                except sqlite3.Error:
                    continue
                    
        finally:
            conn.close()
        
        return self.scan_memories(memories)
    
    def _scan_text_file(self, path: str) -> ScanResult:
        """Scan a plain text file (one memory per line)."""
        memories: list[str] = []
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # Skip comments and empty lines
                    memories.append(line)
        
        return self.scan_memories(memories)
    
    def stream_scan(
        self, 
        memories: list[dict[str, Any] | str]
    ) -> Generator[AnalysisResult, None, None]:
        """
        Generator that yields results as they're analyzed.
        
        Useful for progress tracking with large batches.
        
        Args:
            memories: List of memory entries to scan
        
        Yields:
            AnalysisResult for each entry as it's analyzed
        """
        for memory in memories:
            if isinstance(memory, str):
                entry = MemoryEntry(content=memory)
            elif isinstance(memory, dict):
                content = memory.get("content", memory.get("text", ""))
                entry = MemoryEntry(
                    content=content,
                    source_type=memory.get("source_type", "unknown"),
                    source_id=memory.get("source_id", None),
                )
            else:
                continue
            
            yield self.analyzer.analyze(entry)


class FileWatcher:
    """
    Watch files or directories for changes and scan new content.
    
    This is a basic implementation. In production, you'd use
    watchdog or similar library for efficient file watching.
    """
    
    def __init__(
        self, 
        scanner: Scanner | None = None,
        callback: Any | None = None
    ) -> None:
        """
        Initialize the file watcher.
        
        Args:
            scanner: Scanner instance to use
            callback: Function to call when threats are found
        """
        self.scanner = scanner or Scanner()
        self.callback = callback
        self._file_hashes: dict[str, str] = {}
    
    def check_file(self, path: str) -> ScanResult | None:
        """
        Check if a file has changed and scan it if so.
        
        Returns ScanResult if file changed, None if unchanged.
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            return None
        
        # Simple change detection using mtime
        current_hash = str(path_obj.stat().st_mtime)
        
        if path in self._file_hashes:
            if self._file_hashes[path] == current_hash:
                return None
        
        self._file_hashes[path] = current_hash
        result = self.scanner.scan_file(path)
        
        if self.callback and result.threat_count > 0:
            self.callback(path, result)
        
        return result
