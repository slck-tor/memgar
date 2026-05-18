"""
Memgar Memory Integrity Ledger
================================

Immutable, tamper-evident audit trail for AI agent memory entries.

Each entry in the ledger is cryptographically chained to the previous one
(hash chain / blockchain-style). Any modification — whether by a memory
poisoning attack, silent corruption, or unauthorized write — breaks the
chain and is immediately detectable.

Key capabilities:

    MemoryLedger        — append-only hash chain for memory entries
    LedgerEntry         — single chained entry (content + hash + prev_hash)
    LedgerVerifier      — verify chain integrity, detect tampering
    LedgerReport        — full tamper analysis with affected entry range
    ForensicsIntegration— bridge to memgar.forensics for unified reporting

Design:

    Entry N hash = SHA-256(content + prev_hash + timestamp + entry_id)

    [GENESIS]──hash0──>[Entry 1]──hash1──>[Entry 2]──hash2──>[Entry 3]
                          │                   │                   │
                        ok ✅              TAMPERED ❌           broken ❌
                                    (chain invalid from here)

Any tampering of Entry 2's content changes hash2, which invalidates Entry 3's
prev_hash reference, making all subsequent entries detectable as compromised.

Storage formats:
    - JSON file (.json)       — human-readable, portable
    - SQLite (.db)            — efficient for large stores, queryable
    - In-memory               — for runtime protection (no persistence)

CLI usage::

    memgar ledger init ./memory.ledger.json
    memgar ledger append ./memory.ledger.json "User prefers dark mode"
    memgar ledger verify ./memory.ledger.json
    memgar ledger status ./memory.ledger.json

Python usage::

    from memgar.memory_ledger import MemoryLedger

    ledger = MemoryLedger("./agent_memory.ledger.json")
    entry_id = ledger.append("User prefers dark mode")

    # Later — verify nothing was tampered
    report = ledger.verify()
    if not report.is_valid:
        print(f"TAMPERED: {report.tampered_count} entries compromised")
        print(f"First breach at entry #{report.first_breach_index}")
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS_HASH = "0" * 64   # SHA-256 of nothing — chain anchor
LEDGER_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class EntryStatus(str, Enum):
    VALID    = "valid"
    TAMPERED = "tampered"   # content hash mismatch
    BROKEN   = "broken"     # prev_hash chain break (upstream tamper)
    MISSING  = "missing"    # entry referenced but not found


@dataclass
class LedgerEntry:
    """
    A single entry in the memory integrity ledger.

    Fields that participate in the hash (immutable after creation):
        entry_id, content, prev_hash, timestamp, sequence

    The entry_hash is computed from these fields — if content changes,
    entry_hash will no longer match, detecting tampering.
    """
    entry_id:   str
    sequence:   int           # monotonically increasing position
    content:    str           # the memory content
    prev_hash:  str           # hash of the previous entry (GENESIS_HASH for first)
    timestamp:  str           # ISO 8601 UTC
    entry_hash: str           # SHA-256 of (entry_id + content + prev_hash + timestamp + sequence)
    metadata:   Dict[str, Any] = field(default_factory=dict)

    # Runtime-only (not stored, set during verification)
    status: EntryStatus = field(default=EntryStatus.VALID, compare=False)

    @property
    def is_valid(self) -> bool:
        return self.status == EntryStatus.VALID

    def compute_hash(self) -> str:
        """Recompute the entry hash from stored fields."""
        payload = (
            f"{self.entry_id}"
            f"|{self.sequence}"
            f"|{self.content}"
            f"|{self.prev_hash}"
            f"|{self.timestamp}"
        )
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def verify_self(self) -> bool:
        """Return True if the stored hash matches the computed hash."""
        return self.entry_hash == self.compute_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id":   self.entry_id,
            "sequence":   self.sequence,
            "content":    self.content,
            "prev_hash":  self.prev_hash,
            "timestamp":  self.timestamp,
            "entry_hash": self.entry_hash,
            "metadata":   self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LedgerEntry":
        return cls(
            entry_id   = d["entry_id"],
            sequence   = d["sequence"],
            content    = d["content"],
            prev_hash  = d["prev_hash"],
            timestamp  = d["timestamp"],
            entry_hash = d["entry_hash"],
            metadata   = d.get("metadata", {}),
        )

    def to_dict_safe(self) -> Dict[str, Any]:
        """to_dict with content truncated for display."""
        d = self.to_dict()
        d["content_preview"] = self.content[:120] + ("..." if len(self.content) > 120 else "")
        d.pop("content")
        d["status"] = self.status.value
        return d


@dataclass
class TamperEvent:
    """A detected tampering event in the ledger."""
    sequence:       int
    entry_id:       str
    tamper_type:    EntryStatus
    expected_hash:  str
    actual_hash:    str
    content_preview: str = ""
    timestamp:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence":       self.sequence,
            "entry_id":       self.entry_id,
            "tamper_type":    self.tamper_type.value,
            "expected_hash":  self.expected_hash,
            "actual_hash":    self.actual_hash,
            "content_preview": self.content_preview,
            "timestamp":      self.timestamp,
        }


@dataclass
class LedgerReport:
    """
    Result of a full ledger integrity verification.

    is_valid is True only if every entry in the chain is unmodified
    and all prev_hash links are intact.
    """
    is_valid:           bool
    total_entries:      int
    valid_count:        int
    tampered_count:     int
    broken_count:       int
    first_breach_index: Optional[int]      # sequence of first bad entry
    first_breach_id:    Optional[str]      # entry_id of first bad entry
    tamper_events:      List[TamperEvent] = field(default_factory=list)
    chain_head_hash:    str = ""           # hash of the last valid entry
    verified_at:        str = ""
    ledger_path:        str = ""

    @property
    def compromise_rate(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return round((self.tampered_count + self.broken_count) / self.total_entries * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid":           self.is_valid,
            "total_entries":      self.total_entries,
            "valid_count":        self.valid_count,
            "tampered_count":     self.tampered_count,
            "broken_count":       self.broken_count,
            "compromise_rate_pct": self.compromise_rate,
            "first_breach_index": self.first_breach_index,
            "first_breach_id":    self.first_breach_id,
            "chain_head_hash":    self.chain_head_hash,
            "verified_at":        self.verified_at,
            "ledger_path":        self.ledger_path,
            "tamper_events":      [e.to_dict() for e in self.tamper_events[:50]],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Storage backends
# ---------------------------------------------------------------------------

class _JsonStorage:
    """JSON file-based ledger storage."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def load_all(self) -> Tuple[Dict[str, Any], List[LedgerEntry]]:
        if not self.path.exists():
            return {}, []
        with self._lock:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        meta = data.get("meta", {})
        entries = [LedgerEntry.from_dict(e) for e in data.get("entries", [])]
        return meta, entries

    def save_all(self, meta: Dict[str, Any], entries: List[LedgerEntry]) -> None:
        with self._lock:
            data = {
                "meta": meta,
                "entries": [e.to_dict() for e in entries],
            }
            self.path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

    def append_entry(self, meta: Dict[str, Any], entry: LedgerEntry) -> None:
        _, entries = self.load_all()
        entries.append(entry)
        self.save_all(meta, entries)


class _SQLiteStorage:
    """SQLite-based ledger storage — efficient for large stores."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    sequence    INTEGER PRIMARY KEY,
                    entry_id    TEXT NOT NULL UNIQUE,
                    content     TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    timestamp   TEXT NOT NULL,
                    entry_hash  TEXT NOT NULL,
                    metadata    TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_entry_id ON ledger_entries(entry_id)")
            conn.commit()

    def load_all(self) -> Tuple[Dict[str, Any], List[LedgerEntry]]:
        with self._lock:
            with sqlite3.connect(str(self.path)) as conn:
                conn.row_factory = sqlite3.Row
                meta_rows = conn.execute("SELECT key, value FROM ledger_meta").fetchall()
                meta = {r["key"]: json.loads(r["value"]) for r in meta_rows}
                rows = conn.execute(
                    "SELECT * FROM ledger_entries ORDER BY sequence"
                ).fetchall()
                entries = [
                    LedgerEntry(
                        entry_id   = r["entry_id"],
                        sequence   = r["sequence"],
                        content    = r["content"],
                        prev_hash  = r["prev_hash"],
                        timestamp  = r["timestamp"],
                        entry_hash = r["entry_hash"],
                        metadata   = json.loads(r["metadata"]),
                    )
                    for r in rows
                ]
        return meta, entries

    def save_all(self, meta: Dict[str, Any], entries: List[LedgerEntry]) -> None:
        with self._lock:
            with sqlite3.connect(str(self.path)) as conn:
                conn.execute("DELETE FROM ledger_meta")
                conn.execute("DELETE FROM ledger_entries")
                for k, v in meta.items():
                    conn.execute(
                        "INSERT INTO ledger_meta(key, value) VALUES(?, ?)",
                        (k, json.dumps(v))
                    )
                for e in entries:
                    conn.execute(
                        "INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?)",
                        (e.sequence, e.entry_id, e.content, e.prev_hash,
                         e.timestamp, e.entry_hash, json.dumps(e.metadata))
                    )
                conn.commit()

    def append_entry(self, meta: Dict[str, Any], entry: LedgerEntry) -> None:
        with self._lock:
            with sqlite3.connect(str(self.path)) as conn:
                conn.execute(
                    "INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?)",
                    (entry.sequence, entry.entry_id, entry.content,
                     entry.prev_hash, entry.timestamp, entry.entry_hash,
                     json.dumps(entry.metadata))
                )
                for k, v in meta.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO ledger_meta(key, value) VALUES(?,?)",
                        (k, json.dumps(v))
                    )
                conn.commit()


class _MemoryStorage:
    """In-memory ledger storage — no persistence, runtime-only."""

    def __init__(self) -> None:
        self._meta: Dict[str, Any] = {}
        self._entries: List[LedgerEntry] = []
        self._lock = threading.Lock()

    def load_all(self) -> Tuple[Dict[str, Any], List[LedgerEntry]]:
        with self._lock:
            return dict(self._meta), list(self._entries)

    def save_all(self, meta: Dict[str, Any], entries: List[LedgerEntry]) -> None:
        with self._lock:
            self._meta = dict(meta)
            self._entries = list(entries)

    def append_entry(self, meta: Dict[str, Any], entry: LedgerEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            self._meta.update(meta)


def _make_storage(path: Optional[str]) -> Any:
    if path is None:
        return _MemoryStorage()
    p = Path(path)
    if p.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
        return _SQLiteStorage(p)
    return _JsonStorage(p)


# ---------------------------------------------------------------------------
# Core Ledger
# ---------------------------------------------------------------------------

class MemoryLedger:
    """
    Append-only, tamper-evident memory integrity ledger.

    Every entry is SHA-256 hashed and chained to the previous entry.
    Any modification — even a single character — breaks the chain and
    is detectable by verify().

    Usage::

        ledger = MemoryLedger("./agent.ledger.json")

        # Every time you write to agent memory, also append to ledger
        entry_id = ledger.append(
            content="User prefers dark mode",
            metadata={"source": "chat", "session": "abc123"},
        )

        # Periodically verify (or before any sensitive operation)
        report = ledger.verify()
        if not report.is_valid:
            print(f"⚠️  Memory tampered! First breach: entry #{report.first_breach_index}")
            # Trigger incident response...

    Args:
        path:               Storage path. Suffix determines format:
                            .json → JSON file
                            .db / .sqlite → SQLite
                            None → in-memory (no persistence)
        on_tamper:          Callback(LedgerReport) when tampering detected on verify().
        auto_verify_every:  Auto-verify after every N appends (0 = disabled).
    """

    def __init__(
        self,
        path: Optional[str] = None,
        on_tamper: Optional[Callable[["LedgerReport"], None]] = None,
        auto_verify_every: int = 0,
    ) -> None:
        self._storage = _make_storage(path)
        self._on_tamper = on_tamper
        self._auto_verify_every = auto_verify_every
        self._lock = threading.Lock()
        self._append_count = 0

        # Bootstrap meta if new ledger
        meta, entries = self._storage.load_all()
        if not meta:
            meta = {
                "version":    LEDGER_VERSION,
                "created_at": _now_iso(),
                "genesis":    GENESIS_HASH,
            }
            self._storage.save_all(meta, entries)

    # ── Public API ─────────────────────────────────────────────────────────

    def append(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        entry_id: Optional[str] = None,
    ) -> str:
        """
        Append a memory entry to the ledger.

        Args:
            content:    The memory content to record.
            metadata:   Optional key-value metadata (source, session, etc.).
            entry_id:   Optional custom ID (auto-generated if None).

        Returns:
            entry_id of the appended entry.
        """
        with self._lock:
            _, entries = self._storage.load_all()
            prev_hash = entries[-1].entry_hash if entries else GENESIS_HASH
            sequence  = len(entries)
            ts        = _now_iso()
            eid       = entry_id or _make_id(sequence, ts)

            entry = LedgerEntry(
                entry_id  = eid,
                sequence  = sequence,
                content   = content,
                prev_hash = prev_hash,
                timestamp = ts,
                entry_hash= "",         # computed below
                metadata  = metadata or {},
            )
            entry.entry_hash = entry.compute_hash()

            meta, _ = self._storage.load_all()
            meta["last_hash"]     = entry.entry_hash
            meta["entry_count"]   = sequence + 1
            meta["last_updated"]  = ts

            self._storage.append_entry(meta, entry)
            self._append_count += 1

        # Auto-verify
        if self._auto_verify_every > 0 and self._append_count % self._auto_verify_every == 0:
            report = self.verify()
            if not report.is_valid and self._on_tamper:
                self._on_tamper(report)

        return eid

    def verify(self, stop_at_first: bool = False) -> LedgerReport:
        """
        Verify the entire ledger chain integrity.

        Walks every entry from genesis → head:
        1. Recomputes each entry's hash — detects content tampering
        2. Checks prev_hash linkage — detects insertion/deletion/reordering

        Args:
            stop_at_first: Stop after the first tampered entry is found.

        Returns:
            LedgerReport with full tamper analysis.
        """
        _, entries = self._storage.load_all()

        valid_count    = 0
        tampered_count = 0
        broken_count   = 0
        tamper_events: List[TamperEvent] = []
        first_breach   = None
        prev_hash      = GENESIS_HASH
        chain_broken   = False

        for entry in entries:
            # 1. Content integrity — does stored hash match recomputed hash?
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                entry.status = EntryStatus.TAMPERED
                tampered_count += 1
                if first_breach is None:
                    first_breach = entry
                tamper_events.append(TamperEvent(
                    sequence      = entry.sequence,
                    entry_id      = entry.entry_id,
                    tamper_type   = EntryStatus.TAMPERED,
                    expected_hash = entry.entry_hash,
                    actual_hash   = computed,
                    content_preview = entry.content[:100],
                    timestamp     = entry.timestamp,
                ))
                chain_broken = True

            # 2. Chain linkage — does prev_hash match the previous entry?
            elif entry.prev_hash != prev_hash:
                entry.status = EntryStatus.BROKEN
                broken_count += 1
                if first_breach is None:
                    first_breach = entry
                tamper_events.append(TamperEvent(
                    sequence      = entry.sequence,
                    entry_id      = entry.entry_id,
                    tamper_type   = EntryStatus.BROKEN,
                    expected_hash = prev_hash,
                    actual_hash   = entry.prev_hash,
                    content_preview = entry.content[:100],
                    timestamp     = entry.timestamp,
                ))
                chain_broken = True

            else:
                entry.status = EntryStatus.VALID
                valid_count += 1

            # Advance chain
            prev_hash = entry.entry_hash

            if stop_at_first and chain_broken:
                # Mark remaining as broken
                broken_count += len(entries) - entry.sequence - 1
                break

        is_valid = tampered_count == 0 and broken_count == 0

        report = LedgerReport(
            is_valid           = is_valid,
            total_entries      = len(entries),
            valid_count        = valid_count,
            tampered_count     = tampered_count,
            broken_count       = broken_count,
            first_breach_index = first_breach.sequence if first_breach else None,
            first_breach_id    = first_breach.entry_id if first_breach else None,
            tamper_events      = tamper_events,
            chain_head_hash    = entries[-1].entry_hash if entries else GENESIS_HASH,
            verified_at        = _now_iso(),
            ledger_path        = str(getattr(getattr(self._storage, "path", None), "__str__", lambda: "memory")()),
        )

        if not is_valid and self._on_tamper:
            try:
                self._on_tamper(report)
            except Exception:
                pass

        return report

    def get_entry(self, entry_id: str) -> Optional[LedgerEntry]:
        """Retrieve a single entry by ID."""
        _, entries = self._storage.load_all()
        for e in entries:
            if e.entry_id == entry_id:
                return e
        return None

    def get_range(self, start: int = 0, end: Optional[int] = None) -> List[LedgerEntry]:
        """Retrieve entries by sequence range [start, end)."""
        _, entries = self._storage.load_all()
        return entries[start:end]

    def __len__(self) -> int:
        _, entries = self._storage.load_all()
        return len(entries)

    def __iter__(self) -> Iterator[LedgerEntry]:
        _, entries = self._storage.load_all()
        return iter(entries)

    @property
    def head_hash(self) -> str:
        """Hash of the most recent entry (or GENESIS_HASH if empty)."""
        _, entries = self._storage.load_all()
        return entries[-1].entry_hash if entries else GENESIS_HASH

    @property
    def meta(self) -> Dict[str, Any]:
        m, _ = self._storage.load_all()
        return m

    def status(self) -> Dict[str, Any]:
        """Quick status summary without full verification."""
        m, entries = self._storage.load_all()
        return {
            "entry_count":  len(entries),
            "head_hash":    entries[-1].entry_hash if entries else GENESIS_HASH,
            "last_updated": m.get("last_updated", ""),
            "version":      m.get("version", LEDGER_VERSION),
            "storage":      type(self._storage).__name__,
        }

    def export_json(self) -> str:
        """Export the full ledger as a JSON string."""
        m, entries = self._storage.load_all()
        return json.dumps({
            "meta":    m,
            "entries": [e.to_dict() for e in entries],
        }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Verifier (standalone — works on any ledger data)
# ---------------------------------------------------------------------------

class LedgerVerifier:
    """
    Standalone verifier — verify any list of LedgerEntry objects
    without loading a MemoryLedger instance.

    Used by forensics integration and external tooling.
    """

    @staticmethod
    def verify_entries(entries: List[LedgerEntry]) -> LedgerReport:
        """Verify a list of entries as a standalone chain."""
        ledger = MemoryLedger(path=None)  # in-memory
        meta, _ = ledger._storage.load_all()
        ledger._storage.save_all(meta, entries)
        return ledger.verify()

    @staticmethod
    def verify_json_file(path: str) -> LedgerReport:
        """Verify a JSON ledger file without modifying it."""
        ledger = MemoryLedger(path=path)
        return ledger.verify()

    @staticmethod
    def verify_sqlite_file(path: str) -> LedgerReport:
        """Verify a SQLite ledger file without modifying it."""
        ledger = MemoryLedger(path=path)
        return ledger.verify()


# ---------------------------------------------------------------------------
# Forensics Integration
# ---------------------------------------------------------------------------

class LedgerForensicsIntegration:
    """
    Bridge between MemoryLedger and memgar.forensics.

    Combines ledger tamper detection with content threat scanning
    to produce a unified security report.

    Usage::

        from memgar.memory_ledger import LedgerForensicsIntegration

        integration = LedgerForensicsIntegration(ledger_path="./agent.ledger.json")
        report = integration.full_audit()
        print(f"Tampered: {report['ledger']['tampered_count']}")
        print(f"Poisoned: {report['forensics']['poisoned_entries']}")
    """

    def __init__(
        self,
        ledger_path: str,
        analyzer=None,
    ) -> None:
        self._ledger = MemoryLedger(path=ledger_path)
        self._ledger_path = ledger_path
        self._analyzer = analyzer

    def full_audit(self) -> Dict[str, Any]:
        """
        Run both ledger integrity verification and content threat scanning.

        Returns combined report dict with:
            - ledger: LedgerReport dict (tamper detection)
            - forensics: ForensicReport dict (content threats)
            - summary: combined risk assessment
        """
        import os
        import tempfile

        # 1. Ledger integrity
        ledger_report = self._ledger.verify()

        # 2. Content forensics — extract entries to temp JSON
        _, entries = self._ledger._storage.load_all()
        content_list = [
            {"content": e.content, "timestamp": e.timestamp, "entry_id": e.entry_id}
            for e in entries
        ]

        from memgar.forensics import MemoryForensicsEngine
        engine = MemoryForensicsEngine(analyzer=self._analyzer)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(content_list, f)
            tmp_path = f.name

        try:
            forensics_report = engine.scan(tmp_path)
        finally:
            os.unlink(tmp_path)

        # 3. Combined risk
        tamper_risk = (
            "CRITICAL" if ledger_report.tampered_count > 0
            else "HIGH" if ledger_report.broken_count > 0
            else "NONE"
        )
        content_risk = (
            "CRITICAL" if forensics_report.critical_count > 0
            else "HIGH" if forensics_report.high_count > 0
            else "MEDIUM" if forensics_report.medium_count > 0
            else "NONE"
        )

        return {
            "ledger": ledger_report.to_dict(),
            "forensics": forensics_report.to_dict(),
            "summary": {
                "ledger_valid":       ledger_report.is_valid,
                "content_compromised": forensics_report.is_compromised,
                "tamper_risk":        tamper_risk,
                "content_risk":       content_risk,
                "total_entries":      len(entries),
                "tampered_entries":   ledger_report.tampered_count + ledger_report.broken_count,
                "poisoned_entries":   forensics_report.poisoned_entries,
                "verified_at":        ledger_report.verified_at,
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_id(sequence: int, timestamp: str) -> str:
    raw = f"{sequence}|{timestamp}|{time.perf_counter_ns()}"
    return "L" + hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def create_ledger(path: Optional[str] = None, **kwargs) -> MemoryLedger:
    """Factory — create a MemoryLedger with the given storage path."""
    return MemoryLedger(path=path, **kwargs)


def verify_ledger(path: str) -> LedgerReport:
    """Quick verify a ledger file. Returns LedgerReport."""
    return MemoryLedger(path=path).verify()
