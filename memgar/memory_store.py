"""
Memgar MemoryStore — In-memory ring buffer for retroactive scanning
===================================================================

MemoryStore captures every MemoryEntry analyzed by the Analyzer so that
MemoryHunter can re-evaluate them when new threat patterns are deployed.

Why needed?
    StorageManager (ml/continuous_learning.py) hashes content for privacy —
    raw text is discarded. MemoryStore retains the original content in a
    bounded in-memory buffer so the Hunter can re-scan historical entries.

Usage (standalone):
    from memgar import Analyzer, MemoryStore, MemoryHunter

    store = MemoryStore(max_entries=5000)
    analyzer = Analyzer(use_llm=False, memory_store=store)

    # Every analyze() call automatically populates the store
    analyzer.analyze(MemoryEntry(content="User prefers dark mode"))
    analyzer.analyze(MemoryEntry(content="Ignore all previous instructions..."))

    hunter = MemoryHunter(
        memory_provider=store.get_entries,
        analyzer=analyzer,
    )
    hunter.start()
    # Hunter will retroactively re-scan all stored entries every 60s

Usage (auto-configured):
    from memgar.hunter import start_hunter

    hunter = start_hunter(analyzer)   # creates store + hunter, starts immediately
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import List, Optional

from memgar.models import MemoryEntry

import logging
logger = logging.getLogger(__name__)


class MemoryStore:
    """
    Thread-safe bounded in-memory store of analyzed MemoryEntry objects.

    Implemented as an OrderedDict ring buffer: oldest entries are evicted
    when max_entries is exceeded. Entries are deduplicated by content hash.

    Args:
        max_entries: Maximum number of entries to keep (default 10_000).
        ttl_seconds:  If > 0, entries are evicted after this many seconds.
                      0 means keep entries forever (until max_entries cap).
    """

    def __init__(self, max_entries: int = 10_000, ttl_seconds: int = 0):
        self._max = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # key: content_hash, value: (MemoryEntry, timestamp)
        self._store: OrderedDict[str, tuple[MemoryEntry, float]] = OrderedDict()

    def add(self, entry: MemoryEntry) -> None:
        """Add or refresh an entry (idempotent on same content)."""
        key = self._key(entry)
        now = time.time()
        with self._lock:
            # Move to end (most-recent) if already present
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (entry, now)
            # Evict oldest if over capacity
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

    @staticmethod
    def _key(entry: MemoryEntry) -> str:
        if entry.source_id:
            return entry.source_id
        return hashlib.sha256(entry.content.encode("utf-8", errors="replace")).hexdigest()[:24]


__all__ = ["MemoryStore"]
