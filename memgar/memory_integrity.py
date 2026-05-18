"""
OWASP Agent Memory Guard — Memory Integrity layer.

Provides snapshot, hash-baseline verification, and rollback for MemoryEntry
objects so a compromised/poisoned entry can be detected and reverted to its
last known-good state.

Usage
-----
    from memgar import Analyzer, MemoryEntry
    from memgar.memory_integrity import MemoryIntegrityStore

    store = MemoryIntegrityStore()

    # Snapshot a safe entry after it passes analysis
    entry = MemoryEntry(content="User prefers dark mode", source_id="prefs-1")
    store.snapshot(entry)

    # Later — check whether the content has been tampered with
    violation = store.verify(entry)
    if violation:
        clean = store.rollback(violation.entry_id)

    # Convenience: batch-verify a list
    violations = store.verify_batch([entry1, entry2, entry3])
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MemorySnapshot:
    """One point-in-time snapshot of a safe MemoryEntry."""
    entry_id:      str        # stable identifier (caller-supplied or auto-derived)
    content_hash:  str        # SHA-256 of content at snapshot time
    content:       str        # original safe content
    source_type:   str
    source_id:     Optional[str]
    snapshot_ts:   float      # epoch seconds
    metadata:      dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["metadata"] = json.dumps(d["metadata"])
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MemorySnapshot":
        d = dict(d)
        d["metadata"] = json.loads(d.get("metadata") or "{}")
        return cls(**d)


@dataclass
class IntegrityViolation:
    """Returned by verify() when content no longer matches its baseline hash."""
    entry_id:       str
    expected_hash:  str
    actual_hash:    str
    snapshot_ts:    float     # when the baseline was taken
    detected_ts:    float     # when the tamper was detected
    content_at_snapshot: str  # the safe content to roll back to

    @property
    def age_seconds(self) -> float:
        return self.detected_ts - self.snapshot_ts


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------

def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _entry_id(entry) -> str:
    """Derive a stable entry_id from source_id or initial content hash."""
    if entry.source_id:
        return f"src:{entry.source_id}"
    return f"hash:{_hash(entry.content)}"


# ---------------------------------------------------------------------------
# MemoryIntegrityStore
# ---------------------------------------------------------------------------

class MemoryIntegrityStore:
    """
    Thread-safe store that maintains per-entry snapshots for integrity checking.

    Parameters
    ----------
    db_path:
        If given, snapshots are persisted to a SQLite file so they survive
        process restarts.  If None (default), they live in memory only.
    max_snapshots_per_entry:
        How many historical snapshots to keep per entry_id.  Oldest are pruned
        when the limit is exceeded.  Rollback returns the most recent one.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_snapshots_per_entry: int = 5,
    ) -> None:
        self._max = max_snapshots_per_entry
        self._lock = threading.Lock()
        # In-memory store: entry_id → list[MemorySnapshot] (newest last)
        self._store: Dict[str, List[MemorySnapshot]] = {}
        self._db: Optional[sqlite3.Connection] = None

        if db_path:
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._init_db()
            self._load_from_db()

    # ------------------------------------------------------------------ schema

    def _init_db(self) -> None:
        assert self._db
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS memory_snapshots (
                entry_id      TEXT NOT NULL,
                content_hash  TEXT NOT NULL,
                content       TEXT NOT NULL,
                source_type   TEXT NOT NULL,
                source_id     TEXT,
                snapshot_ts   REAL NOT NULL,
                metadata      TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (entry_id, snapshot_ts)
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_entry ON memory_snapshots(entry_id, snapshot_ts)"
        )
        self._db.commit()

    def _load_from_db(self) -> None:
        assert self._db
        rows = self._db.execute(
            "SELECT * FROM memory_snapshots ORDER BY entry_id, snapshot_ts"
        ).fetchall()
        for row in rows:
            snap = MemorySnapshot.from_dict(dict(row))
            self._store.setdefault(snap.entry_id, []).append(snap)

    def _persist(self, snap: MemorySnapshot) -> None:
        if not self._db:
            return
        d = snap.to_dict()
        self._db.execute(
            """INSERT OR REPLACE INTO memory_snapshots
               (entry_id, content_hash, content, source_type, source_id, snapshot_ts, metadata)
               VALUES (:entry_id, :content_hash, :content, :source_type, :source_id, :snapshot_ts, :metadata)""",
            d,
        )
        self._db.commit()

    def _prune_db(self, entry_id: str) -> None:
        if not self._db:
            return
        # Keep only the most recent max_snapshots rows
        self._db.execute(
            """DELETE FROM memory_snapshots
               WHERE entry_id = ? AND snapshot_ts NOT IN (
                   SELECT snapshot_ts FROM memory_snapshots
                   WHERE entry_id = ? ORDER BY snapshot_ts DESC LIMIT ?
               )""",
            (entry_id, entry_id, self._max),
        )
        self._db.commit()

    # ------------------------------------------------------------------ public

    def snapshot(self, entry, entry_id: Optional[str] = None) -> MemorySnapshot:
        """
        Take a snapshot of *entry* as a trusted baseline.

        Returns the created MemorySnapshot.
        """
        eid = entry_id or _entry_id(entry)
        snap = MemorySnapshot(
            entry_id=eid,
            content_hash=_hash(entry.content),
            content=entry.content,
            source_type=getattr(entry, "source_type", "unknown"),
            source_id=getattr(entry, "source_id", None),
            snapshot_ts=time.time(),
            metadata=dict(getattr(entry, "metadata", {})),
        )
        with self._lock:
            snaps = self._store.setdefault(eid, [])
            snaps.append(snap)
            if len(snaps) > self._max:
                snaps[:] = snaps[-self._max:]
            self._persist(snap)
            self._prune_db(eid)

        logger.debug("Snapshot taken: entry_id=%s hash=%s", eid, snap.content_hash[:12])
        return snap

    def verify(self, entry, entry_id: Optional[str] = None) -> Optional[IntegrityViolation]:
        """
        Compare *entry.content* against the most recent baseline snapshot.

        Returns an IntegrityViolation if content has changed, None if clean
        (or if no snapshot exists yet).
        """
        eid = entry_id or _entry_id(entry)
        current_hash = _hash(entry.content)

        with self._lock:
            snaps = self._store.get(eid, [])
            if not snaps:
                return None
            latest = snaps[-1]

        if current_hash == latest.content_hash:
            return None

        violation = IntegrityViolation(
            entry_id=eid,
            expected_hash=latest.content_hash,
            actual_hash=current_hash,
            snapshot_ts=latest.snapshot_ts,
            detected_ts=time.time(),
            content_at_snapshot=latest.content,
        )
        logger.warning(
            "INTEGRITY VIOLATION: entry_id=%s expected=%s actual=%s age=%.0fs",
            eid,
            latest.content_hash[:12],
            current_hash[:12],
            violation.age_seconds,
        )
        return violation

    def verify_batch(self, entries, entry_ids: Optional[List[str]] = None) -> List[IntegrityViolation]:
        """Verify a list of entries; returns only violations."""
        ids = entry_ids or [None] * len(entries)
        violations = []
        for entry, eid in zip(entries, ids):
            v = self.verify(entry, entry_id=eid)
            if v:
                violations.append(v)
        return violations

    def rollback(
        self, entry_id: str, steps_back: int = 1
    ) -> Optional[MemorySnapshot]:
        """
        Return the snapshot *steps_back* versions before the latest.

        steps_back=1 (default) → most recent snapshot (usually the right choice).
        steps_back=2 → second-most-recent (useful if latest was already compromised).

        Returns None if no snapshot exists.
        """
        with self._lock:
            snaps = self._store.get(entry_id, [])
            if not snaps:
                return None
            idx = max(0, len(snaps) - steps_back)
            snap = snaps[idx]

        logger.info(
            "Rollback: entry_id=%s → snapshot from %.0fs ago (hash=%s)",
            entry_id,
            time.time() - snap.snapshot_ts,
            snap.content_hash[:12],
        )
        return snap

    def has_snapshot(self, entry, entry_id: Optional[str] = None) -> bool:
        eid = entry_id or _entry_id(entry)
        with self._lock:
            return bool(self._store.get(eid))

    def snapshot_count(self, entry_id: str) -> int:
        with self._lock:
            return len(self._store.get(entry_id, []))

    def list_entry_ids(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())

    def clear(self, entry_id: Optional[str] = None) -> None:
        """Remove snapshots — all if entry_id is None, else just that entry."""
        with self._lock:
            if entry_id:
                self._store.pop(entry_id, None)
            else:
                self._store.clear()

    # ------------------------------------------------------------------ stats

    def stats(self) -> dict:
        with self._lock:
            total = sum(len(v) for v in self._store.values())
            return {
                "tracked_entries": len(self._store),
                "total_snapshots": total,
                "backend": "sqlite" if self._db else "memory",
            }
