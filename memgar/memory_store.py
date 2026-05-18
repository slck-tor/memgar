"""
Memgar MemoryStore — In-memory and persistent ring buffers for retroactive scanning
====================================================================================

MemoryStore (in-memory):
    Captures entries from the current session only.
    Lost on process restart.

PersistentMemoryStore (disk-backed):
    Appends every entry to a JSONL file on disk.
    Survives restarts — loads the full history on __init__.
    Enables retroactive scanning of entries from days/months ago.

bulk_scan():
    One-shot function: scan an arbitrary list of MemoryEntry objects
    (e.g. loaded from your database) and return all detected threats.

Usage — persistent store (survives restart):

    from memgar import Analyzer
    from memgar.memory_store import PersistentMemoryStore
    from memgar.hunter import start_hunter

    store = PersistentMemoryStore("~/.cache/memgar/memory.jsonl")
    analyzer = Analyzer(use_llm=False, memory_store=store)
    hunter = start_hunter(analyzer, store=store)

    # From now on, all analyzed entries are saved to disk.
    # On next startup, the store loads them from the JSONL file.
    # Hunter will retroactively scan 1-month-old entries.

Usage — bulk scan of your existing data:

    from memgar.memory_store import bulk_scan
    from memgar.models import MemoryEntry

    historical = [MemoryEntry(content=row["text"]) for row in db.query("...")]
    threats = bulk_scan(historical)   # returns list of detected threats

    for t in threats:
        print(f"RETROACTIVE THREAT: {t.content[:80]} (score={t.risk_score})")
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import List, NamedTuple

from memgar.models import MemoryEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory store (session-only)
# ---------------------------------------------------------------------------

class MemoryStore:
    """
    Thread-safe bounded in-memory store of analyzed MemoryEntry objects.

    Implemented as an OrderedDict ring buffer: oldest entries are evicted
    when max_entries is exceeded. Entries are deduplicated by content hash.

    Args:
        max_entries: Maximum entries to keep (default 10_000).
        ttl_seconds: If > 0, entries are evicted after N seconds. 0 = forever.
    """

    def __init__(self, max_entries: int = 10_000, ttl_seconds: int = 0):
        self._max = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._store: OrderedDict[str, tuple[MemoryEntry, float]] = OrderedDict()

    def add(self, entry: MemoryEntry) -> None:
        """Add or refresh an entry (idempotent on same content)."""
        key = _entry_key(entry)
        now = time.time()
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (entry, now)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def get_entries(self) -> List[MemoryEntry]:
        """Return all current entries (evicting expired ones first)."""
        now = time.time()
        with self._lock:
            if self._ttl > 0:
                expired = [k for k, (_, ts) in self._store.items() if now - ts >= self._ttl]
                for k in expired:
                    del self._store[k]
            return [entry for entry, _ in self._store.values()]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# Persistent disk-backed store (survives restarts)
# ---------------------------------------------------------------------------

class PersistentMemoryStore(MemoryStore):
    """
    MemoryStore that persists entries to a JSONL file.

    On __init__, loads all existing entries from disk (enabling retroactive
    scanning of months-old data). Every new entry is appended immediately.

    File format: one JSON object per line —
        {"content": "...", "source_id": "...", "ts": 1714000000.0}

    Args:
        path:         Path to the JSONL persistence file.
        max_entries:  In-memory cap (oldest evicted; disk file is not pruned).
        ttl_seconds:  In-memory TTL. 0 = keep all loaded entries in RAM.
        max_age_days: When loading from disk, ignore entries older than N days.
                      0 = load everything regardless of age (default).
    """

    def __init__(
        self,
        path: str | Path,
        max_entries: int = 100_000,
        ttl_seconds: int = 0,
        max_age_days: int = 0,
    ):
        super().__init__(max_entries=max_entries, ttl_seconds=ttl_seconds)
        self._path = Path(path).expanduser().resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_age_days = max_age_days
        self._file_lock = threading.Lock()

        loaded = self._load_from_disk()
        logger.info(
            "PersistentMemoryStore: loaded %d entries from %s",
            loaded, self._path,
        )

    # ------------------------------------------------------------------
    # Override add() to also write to disk
    # ------------------------------------------------------------------

    def add(self, entry: MemoryEntry) -> None:
        super().add(entry)
        self._append_to_disk(entry)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_from_disk(self) -> int:
        """Load entries from JSONL file into the in-memory store. Returns count loaded."""
        if not self._path.exists():
            return 0

        cutoff = 0.0
        if self._max_age_days > 0:
            cutoff = time.time() - self._max_age_days * 86400

        loaded = 0
        errors = 0
        try:
            with self._path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        ts = float(obj.get("ts", 0))
                        if cutoff > 0 and ts < cutoff:
                            continue
                        entry = MemoryEntry(
                            content=obj["content"],
                            source_id=obj.get("source_id") or None,
                        )
                        # Insert directly with original timestamp
                        key = _entry_key(entry)
                        with self._lock:
                            self._store[key] = (entry, ts)
                            while len(self._store) > self._max:
                                self._store.popitem(last=False)
                        loaded += 1
                    except (KeyError, ValueError, json.JSONDecodeError):
                        errors += 1
        except OSError as e:
            logger.warning("PersistentMemoryStore: could not read %s: %s", self._path, e)

        if errors:
            logger.warning("PersistentMemoryStore: skipped %d malformed lines", errors)
        return loaded

    def _append_to_disk(self, entry: MemoryEntry) -> None:
        """Append a single entry to the JSONL file (thread-safe)."""
        obj = {
            "content": entry.content,
            "source_id": entry.source_id or "",
            "ts": time.time(),
        }
        try:
            with self._file_lock:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except OSError as e:
            logger.warning("PersistentMemoryStore: write failed: %s", e)

    def compact(self) -> int:
        """
        Rewrite the JSONL file keeping only current in-memory entries.
        Call periodically to prune stale/evicted entries from disk.
        Returns the number of entries written.
        """
        entries = self.get_entries()
        try:
            with self._file_lock:
                tmp = self._path.with_suffix(".tmp")
                with tmp.open("w", encoding="utf-8") as f:
                    for entry in entries:
                        key = _entry_key(entry)
                        with self._lock:
                            _, ts = self._store.get(key, (None, time.time()))
                        obj = {
                            "content": entry.content,
                            "source_id": entry.source_id or "",
                            "ts": ts,
                        }
                        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
                tmp.replace(self._path)
            logger.info("PersistentMemoryStore: compacted to %d entries", len(entries))
            return len(entries)
        except OSError as e:
            logger.warning("PersistentMemoryStore: compact failed: %s", e)
            return 0


# ---------------------------------------------------------------------------
# Bulk scan — one-shot retroactive analysis of arbitrary entry lists
# ---------------------------------------------------------------------------

class ThreatResult(NamedTuple):
    """A single retroactive threat finding."""
    entry: MemoryEntry
    risk_score: int
    decision: object   # Decision enum
    threats: list
    explanation: str


def bulk_scan(
    entries: List[MemoryEntry],
    analyzer=None,
    threshold: float = 0.5,
    use_llm: bool = False,
) -> List[ThreatResult]:
    """
    Retroactively scan a list of MemoryEntry objects and return detected threats.

    Use this to scan entries loaded from your own database, a CSV export,
    or any other historical source — no need to run a persistent store first.

    Args:
        entries:    List of MemoryEntry objects to scan.
        analyzer:   Optional pre-configured Analyzer. Created automatically if None.
        threshold:  Risk score threshold (0.0–1.0). Default 0.5 (= score 50/100).
        use_llm:    Enable LLM layer for the scan (slower, more accurate).

    Returns:
        List of ThreatResult for every entry whose risk_score >= threshold * 100.

    Example:
        from memgar.memory_store import bulk_scan
        from memgar.models import MemoryEntry

        rows = db.execute("SELECT content, id FROM memories WHERE created > '2025-01-01'")
        entries = [MemoryEntry(content=r["content"], source_id=r["id"]) for r in rows]
        threats = bulk_scan(entries)

        for t in threats:
            print(f"THREAT (score={t.risk_score}): {t.entry.content[:80]}")
    """
    if analyzer is None:
        from memgar.analyzer import Analyzer
        analyzer = Analyzer(use_llm=use_llm)

    threshold_score = int(threshold * 100)
    results: List[ThreatResult] = []
    total = len(entries)

    for i, entry in enumerate(entries):
        try:
            result = analyzer.analyze(entry)
            if result.risk_score >= threshold_score:
                results.append(ThreatResult(
                    entry=entry,
                    risk_score=result.risk_score,
                    decision=result.decision,
                    threats=result.threats,
                    explanation=result.explanation,
                ))
        except Exception:
            logger.exception("bulk_scan: analysis failed for entry %d/%d", i + 1, total)

        if (i + 1) % 100 == 0:
            logger.info("bulk_scan: processed %d/%d entries (%d threats found)",
                        i + 1, total, len(results))

    logger.info("bulk_scan complete: %d/%d entries scanned, %d threats found",
                total, total, len(results))
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_key(entry: MemoryEntry) -> str:
    if entry.source_id:
        return entry.source_id
    return hashlib.sha256(entry.content.encode("utf-8", errors="replace")).hexdigest()[:24]


__all__ = ["MemoryStore", "PersistentMemoryStore", "bulk_scan", "ThreatResult"]
