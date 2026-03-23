"""
Memgar Memory Auditor
=====================

Memory integrity auditing, snapshots, and rollback capabilities.

The Memory Auditor provides forensic capabilities for AI agent memory:

1. Snapshots: Capture memory state at points in time
2. Integrity Verification: Detect unauthorized modifications
3. Rollback: Restore to known-good state after compromise
4. Audit Trail: Track all memory operations

This is critical for memory poisoning defense because:
- Attackers inject poison that may not be detected immediately
- Root cause analysis requires knowing when compromise occurred
- Recovery requires ability to rollback to pre-compromise state

Usage:
    from memgar.auditor import MemoryAuditor
    
    auditor = MemoryAuditor(storage_path="./memory_snapshots")
    
    # Take periodic snapshots
    snapshot_id = auditor.snapshot(memory_store)
    
    # Verify integrity
    if not auditor.verify(memory_store, snapshot_id):
        # Memory was modified!
        auditor.rollback(memory_store, snapshot_id)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import gzip
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
from enum import Enum
import threading


class AuditEventType(Enum):
    """Types of audit events."""
    SNAPSHOT = "snapshot"
    VERIFY_SUCCESS = "verify_success"
    VERIFY_FAILURE = "verify_failure"
    ROLLBACK = "rollback"
    MEMORY_WRITE = "memory_write"
    MEMORY_DELETE = "memory_delete"
    THREAT_DETECTED = "threat_detected"
    INTEGRITY_ALERT = "integrity_alert"


@dataclass
class AuditEvent:
    """Single audit event."""
    timestamp: float
    event_type: AuditEventType
    details: Dict[str, Any] = field(default_factory=dict)
    snapshot_id: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "event_type": self.event_type.value,
            "details": self.details,
            "snapshot_id": self.snapshot_id,
            "session_id": self.session_id,
        }


@dataclass
class Snapshot:
    """Memory snapshot metadata."""
    id: str
    timestamp: float
    hash: str
    entry_count: int
    size_bytes: int
    session_id: Optional[str] = None
    description: str = ""
    filepath: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "hash": self.hash,
            "entry_count": self.entry_count,
            "size_bytes": self.size_bytes,
            "session_id": self.session_id,
            "description": self.description,
        }


@dataclass
class IntegrityReport:
    """Result of integrity verification."""
    is_valid: bool
    expected_hash: str
    actual_hash: str
    snapshot_id: str
    checked_at: float
    differences: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "snapshot_id": self.snapshot_id,
            "checked_at": datetime.fromtimestamp(self.checked_at).isoformat(),
            "differences": self.differences,
        }


class MemoryAuditor:
    """
    Memory integrity auditor for AI agents.
    
    Provides snapshot, verification, and rollback capabilities
    for agent memory stores.
    
    Args:
        storage_path: Directory for storing snapshots
        max_snapshots: Maximum snapshots to retain (default: 100)
        compress: Whether to compress snapshots (default: True)
        on_integrity_failure: Callback when integrity check fails
        session_id: Current session identifier
    
    Example:
        auditor = MemoryAuditor("./snapshots")
        
        # Snapshot before risky operation
        snap_id = auditor.snapshot(memory_data, "Before email import")
        
        # Process potentially dangerous content
        process_emails(memory_data)
        
        # Verify nothing was poisoned
        report = auditor.verify(memory_data, snap_id)
        if not report.is_valid:
            print(f"Memory modified! Differences: {report.differences}")
            # Optionally rollback
            memory_data = auditor.rollback(snap_id)
    """
    
    def __init__(
        self,
        storage_path: Union[str, Path] = "./memory_snapshots",
        max_snapshots: int = 100,
        compress: bool = True,
        on_integrity_failure: Optional[Callable[[IntegrityReport], None]] = None,
        session_id: Optional[str] = None,
    ):
        self.storage_path = Path(storage_path)
        self.max_snapshots = max_snapshots
        self.compress = compress
        self.on_integrity_failure = on_integrity_failure
        self.session_id = session_id
        
        self._snapshots: Dict[str, Snapshot] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.Lock()
        
        # Create storage directory
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Load existing snapshots
        self._load_snapshot_index()
    
    def _generate_snapshot_id(self) -> str:
        """Generate unique snapshot ID using SHA-256."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use SHA-256 instead of MD5 for better security practices
        unique = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        return f"snap_{timestamp}_{unique}"
    
    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash of data."""
        if isinstance(data, (dict, list)):
            # Sort keys for consistent hashing
            serialized = json.dumps(data, sort_keys=True, default=str)
        elif isinstance(data, str):
            serialized = data
        else:
            serialized = str(data)
        
        return hashlib.sha256(serialized.encode()).hexdigest()
    
    def _serialize(self, data: Any) -> bytes:
        """Serialize data for storage."""
        json_str = json.dumps(data, sort_keys=True, default=str, indent=2)
        return json_str.encode('utf-8')
    
    def _deserialize(self, data: bytes) -> Any:
        """Deserialize data from storage."""
        return json.loads(data.decode('utf-8'))
    
    def _get_snapshot_path(self, snapshot_id: str) -> Path:
        """Get file path for snapshot."""
        ext = ".json.gz" if self.compress else ".json"
        return self.storage_path / f"{snapshot_id}{ext}"
    
    def _save_snapshot_data(self, snapshot_id: str, data: Any) -> int:
        """Save snapshot data to file. Returns size in bytes."""
        filepath = self._get_snapshot_path(snapshot_id)
        serialized = self._serialize(data)
        
        if self.compress:
            with gzip.open(filepath, 'wb') as f:
                f.write(serialized)
        else:
            filepath.write_bytes(serialized)
        
        return filepath.stat().st_size
    
    def _load_snapshot_data(self, snapshot_id: str) -> Any:
        """Load snapshot data from file."""
        filepath = self._get_snapshot_path(snapshot_id)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")
        
        if self.compress:
            with gzip.open(filepath, 'rb') as f:
                return self._deserialize(f.read())
        else:
            return self._deserialize(filepath.read_bytes())
    
    def _load_snapshot_index(self) -> None:
        """Load snapshot index from storage."""
        index_path = self.storage_path / "index.json"
        if index_path.exists():
            try:
                with open(index_path) as f:
                    index_data = json.load(f)
                for snap_data in index_data.get("snapshots", []):
                    snap = Snapshot(
                        id=snap_data["id"],
                        timestamp=snap_data["timestamp"],
                        hash=snap_data["hash"],
                        entry_count=snap_data["entry_count"],
                        size_bytes=snap_data["size_bytes"],
                        session_id=snap_data.get("session_id"),
                        description=snap_data.get("description", ""),
                    )
                    self._snapshots[snap.id] = snap
            except (json.JSONDecodeError, KeyError):
                pass
    
    def _save_snapshot_index(self) -> None:
        """Save snapshot index to storage."""
        index_path = self.storage_path / "index.json"
        index_data = {
            "snapshots": [
                {
                    "id": s.id,
                    "timestamp": s.timestamp,
                    "hash": s.hash,
                    "entry_count": s.entry_count,
                    "size_bytes": s.size_bytes,
                    "session_id": s.session_id,
                    "description": s.description,
                }
                for s in sorted(self._snapshots.values(), key=lambda x: x.timestamp)
            ]
        }
        with open(index_path, 'w') as f:
            json.dump(index_data, f, indent=2)
    
    def _log_event(self, event_type: AuditEventType, details: Dict = None, snapshot_id: str = None) -> None:
        """Log an audit event."""
        event = AuditEvent(
            timestamp=time.time(),
            event_type=event_type,
            details=details or {},
            snapshot_id=snapshot_id,
            session_id=self.session_id,
        )
        self._audit_log.append(event)
    
    def _enforce_retention(self) -> None:
        """Remove old snapshots if exceeding max."""
        if len(self._snapshots) > self.max_snapshots:
            # Sort by timestamp, oldest first
            sorted_snaps = sorted(self._snapshots.values(), key=lambda x: x.timestamp)
            to_remove = sorted_snaps[:len(sorted_snaps) - self.max_snapshots]
            
            for snap in to_remove:
                filepath = self._get_snapshot_path(snap.id)
                if filepath.exists():
                    filepath.unlink()
                del self._snapshots[snap.id]
    
    def snapshot(
        self,
        memory_data: Any,
        description: str = "",
        snapshot_id: Optional[str] = None,
    ) -> str:
        """
        Take a snapshot of memory state.
        
        Args:
            memory_data: The memory data to snapshot (dict, list, or serializable)
            description: Optional description of this snapshot
            snapshot_id: Optional custom ID (auto-generated if not provided)
        
        Returns:
            Snapshot ID
        """
        with self._lock:
            snap_id = snapshot_id or self._generate_snapshot_id()
            
            # Compute hash
            data_hash = self._compute_hash(memory_data)
            
            # Count entries
            if isinstance(memory_data, dict):
                entry_count = len(memory_data)
            elif isinstance(memory_data, list):
                entry_count = len(memory_data)
            else:
                entry_count = 1
            
            # Save data
            size_bytes = self._save_snapshot_data(snap_id, memory_data)
            
            # Create snapshot record
            snapshot = Snapshot(
                id=snap_id,
                timestamp=time.time(),
                hash=data_hash,
                entry_count=entry_count,
                size_bytes=size_bytes,
                session_id=self.session_id,
                description=description,
                filepath=str(self._get_snapshot_path(snap_id)),
            )
            
            self._snapshots[snap_id] = snapshot
            self._save_snapshot_index()
            self._enforce_retention()
            
            self._log_event(
                AuditEventType.SNAPSHOT,
                {"entry_count": entry_count, "hash": data_hash, "description": description},
                snap_id,
            )
            
            return snap_id
    
    def verify(
        self,
        memory_data: Any,
        snapshot_id: str,
        detailed: bool = False,
    ) -> IntegrityReport:
        """
        Verify memory integrity against a snapshot.
        
        Args:
            memory_data: Current memory data
            snapshot_id: Snapshot ID to verify against
            detailed: If True, compute detailed differences
        
        Returns:
            IntegrityReport with verification results
        """
        with self._lock:
            if snapshot_id not in self._snapshots:
                raise ValueError(f"Snapshot not found: {snapshot_id}")
            
            snapshot = self._snapshots[snapshot_id]
            current_hash = self._compute_hash(memory_data)
            is_valid = current_hash == snapshot.hash
            
            differences = []
            if not is_valid and detailed:
                # Load original and compare
                try:
                    original = self._load_snapshot_data(snapshot_id)
                    differences = self._compute_differences(original, memory_data)
                except Exception as e:
                    differences = [f"Could not compute differences: {e}"]
            
            report = IntegrityReport(
                is_valid=is_valid,
                expected_hash=snapshot.hash,
                actual_hash=current_hash,
                snapshot_id=snapshot_id,
                checked_at=time.time(),
                differences=differences,
            )
            
            # Log event
            event_type = AuditEventType.VERIFY_SUCCESS if is_valid else AuditEventType.VERIFY_FAILURE
            self._log_event(event_type, report.to_dict(), snapshot_id)
            
            # Callback on failure
            if not is_valid and self.on_integrity_failure:
                try:
                    self.on_integrity_failure(report)
                except Exception:
                    pass
            
            return report
    
    def _compute_differences(self, original: Any, current: Any, path: str = "") -> List[str]:
        """Compute differences between original and current data."""
        differences = []
        
        if type(original) != type(current):
            differences.append(f"{path or 'root'}: type changed from {type(original).__name__} to {type(current).__name__}")
            return differences
        
        if isinstance(original, dict):
            all_keys = set(original.keys()) | set(current.keys())
            for key in all_keys:
                key_path = f"{path}.{key}" if path else key
                if key not in original:
                    differences.append(f"{key_path}: added")
                elif key not in current:
                    differences.append(f"{key_path}: removed")
                elif original[key] != current[key]:
                    if isinstance(original[key], (dict, list)):
                        differences.extend(self._compute_differences(original[key], current[key], key_path))
                    else:
                        differences.append(f"{key_path}: modified")
        
        elif isinstance(original, list):
            if len(original) != len(current):
                differences.append(f"{path or 'root'}: length changed from {len(original)} to {len(current)}")
            else:
                for i, (o, c) in enumerate(zip(original, current)):
                    if o != c:
                        differences.append(f"{path}[{i}]: modified")
        
        elif original != current:
            differences.append(f"{path or 'root'}: value changed")
        
        return differences[:100]  # Limit to 100 differences
    
    def rollback(self, snapshot_id: str) -> Any:
        """
        Load and return data from a snapshot for rollback.
        
        Args:
            snapshot_id: Snapshot ID to rollback to
        
        Returns:
            The memory data from the snapshot
        """
        with self._lock:
            if snapshot_id not in self._snapshots:
                raise ValueError(f"Snapshot not found: {snapshot_id}")
            
            data = self._load_snapshot_data(snapshot_id)
            
            self._log_event(
                AuditEventType.ROLLBACK,
                {"snapshot_id": snapshot_id},
                snapshot_id,
            )
            
            return data
    
    def list_snapshots(
        self,
        limit: int = 50,
        session_id: Optional[str] = None,
    ) -> List[Snapshot]:
        """List available snapshots."""
        with self._lock:
            snapshots = list(self._snapshots.values())
            
            if session_id:
                snapshots = [s for s in snapshots if s.session_id == session_id]
            
            # Sort by timestamp, newest first
            snapshots.sort(key=lambda x: x.timestamp, reverse=True)
            
            return snapshots[:limit]
    
    def get_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        """Get snapshot metadata by ID."""
        return self._snapshots.get(snapshot_id)
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot."""
        with self._lock:
            if snapshot_id not in self._snapshots:
                return False
            
            filepath = self._get_snapshot_path(snapshot_id)
            if filepath.exists():
                filepath.unlink()
            
            del self._snapshots[snapshot_id]
            self._save_snapshot_index()
            return True
    
    def get_latest_snapshot(self) -> Optional[Snapshot]:
        """Get the most recent snapshot."""
        snapshots = self.list_snapshots(limit=1)
        return snapshots[0] if snapshots else None
    
    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get recent audit events."""
        return self._audit_log[-limit:]
    
    def log_memory_operation(
        self,
        operation: str,
        content_preview: str = "",
        entry_id: str = None,
        threat_detected: bool = False,
        details: Dict = None,
    ) -> None:
        """
        Log a memory operation for audit trail.
        
        Args:
            operation: "write", "delete", "read"
            content_preview: Preview of content (will be truncated)
            entry_id: Memory entry identifier
            threat_detected: Whether a threat was detected
            details: Additional details
        """
        event_type = AuditEventType.THREAT_DETECTED if threat_detected else AuditEventType.MEMORY_WRITE
        if operation == "delete":
            event_type = AuditEventType.MEMORY_DELETE
        
        self._log_event(
            event_type,
            {
                "operation": operation,
                "content_preview": content_preview[:100],
                "entry_id": entry_id,
                "threat_detected": threat_detected,
                **(details or {}),
            },
        )
    
    def export_audit_log(self, filepath: Union[str, Path]) -> None:
        """Export audit log to file."""
        with open(filepath, 'w') as f:
            json.dump(
                [e.to_dict() for e in self._audit_log],
                f,
                indent=2,
            )
    
    def clear_audit_log(self) -> None:
        """Clear the in-memory audit log."""
        self._audit_log.clear()


class MemoryGuardWithAudit:
    """
    Wrapper that combines MemoryGuard with auditing.
    
    Automatically logs all memory operations and can take
    snapshots before risky operations.
    
    Example:
        from memgar.memory_guard import MemoryGuard
        from memgar.auditor import MemoryGuardWithAudit
        
        guard = MemoryGuardWithAudit(
            storage_path="./audit",
            auto_snapshot_interval=100,  # Snapshot every 100 operations
        )
        
        result = guard.process(content, memory_store)
        if result.allowed:
            memory_store.append(result.safe_content)
    """
    
    def __init__(
        self,
        storage_path: str = "./memory_audit",
        auto_snapshot_interval: int = 100,
        **guard_kwargs,
    ):
        from memgar.memory_guard import MemoryGuard
        
        self.guard = MemoryGuard(**guard_kwargs)
        self.auditor = MemoryAuditor(storage_path=storage_path)
        self.auto_snapshot_interval = auto_snapshot_interval
        self._operation_count = 0
    
    def process(
        self,
        content: str,
        memory_store: Any = None,
        **kwargs,
    ):
        """Process content with auditing."""
        # Log the operation
        self.auditor.log_memory_operation(
            operation="write",
            content_preview=content[:100],
        )
        
        # Process through guard
        result = self.guard.process(content, **kwargs)
        
        # Log if threat detected
        if not result.allowed:
            self.auditor.log_memory_operation(
                operation="write",
                content_preview=content[:100],
                threat_detected=True,
                details={"decision": result.decision.value},
            )
        
        # Auto-snapshot if interval reached
        self._operation_count += 1
        if memory_store and self._operation_count >= self.auto_snapshot_interval:
            self.auditor.snapshot(memory_store, f"Auto-snapshot at {self._operation_count} operations")
            self._operation_count = 0
        
        return result
