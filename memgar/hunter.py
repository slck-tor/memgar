"""
Memgar MemoryHunter — Active Background Scanner
================================================

Continuously scans a memory store for attacks that were not caught at write-time.

Why hunter mode?
    - Reactive detection (on-write) misses entries that were ingested before
      new threat patterns were deployed.
    - Hunter mode re-evaluates existing memory on a configurable interval,
      applying the latest patterns and centroids to all stored entries.

Usage:
    from memgar import MemoryHunter, Analyzer
    from memgar.siem import SIEMRouter

    def get_memories() -> list[MemoryEntry]:
        return db.fetch_all_memories()          # your store

    hunter = MemoryHunter(
        memory_provider=get_memories,
        analyzer=Analyzer(use_llm=False),
        siem_router=SIEMRouter(),               # optional — emits SIEM events
        agent_id="memory-store-01",
    )
    hunter.start()
    # ... runs every 60 s in the background ...
    hunter.stop()

    stats = hunter.stats()
    # HunterStats(total_scanned=142, threats_found=3, ...)

Configuration via HunterConfig (or env vars MEMGAR_HUNTER_*):
    scan_interval_seconds=60        — how often to scan
    rescan_clean_after_seconds=3600 — re-evaluate clean entries after 1h
    alert_threshold=0.7             — risk_score/100 threshold for SIEM emission
    max_entries_per_scan=1000       — cap per cycle to bound latency
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
import time
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from memgar.config import HunterConfig
from memgar.models import Decision, MemoryEntry

if TYPE_CHECKING:
    from memgar.analyzer import Analyzer
    from memgar.siem import SIEMRouter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class HunterStats:
    """Snapshot of hunter scanning statistics."""

    total_scanned: int = 0
    threats_found: int = 0
    entries_skipped: int = 0
    scan_cycles: int = 0
    last_scan_time: Optional[float] = None
    last_scan_duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Internal cache entry
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _CacheEntry:
    status: str   # "clean" or "threat"
    ts: float     # time.time() when recorded


# ---------------------------------------------------------------------------
# MemoryHunter
# ---------------------------------------------------------------------------

class MemoryHunter:
    """
    Background daemon that periodically scans a memory store for attacks.

    The scan cycle:
      1. Calls memory_provider() to get the current list of MemoryEntry objects.
      2. For each entry: if it was recently scanned and found clean (within the
         rescan TTL), it is skipped. Otherwise it is analyzed.
      3. Entries whose risk_score/100 >= alert_threshold trigger a SIEM event.
      4. Stats are updated atomically after each cycle.
    """

    def __init__(
        self,
        memory_provider: Callable[[], List[MemoryEntry]],
        analyzer: Optional["Analyzer"] = None,
        config: Optional[HunterConfig] = None,
        siem_router: Optional["SIEMRouter"] = None,
        agent_id: Optional[str] = None,
    ):
        self._provider = memory_provider
        self._config = config or HunterConfig()
        self._siem = siem_router
        self._agent_id = agent_id

        # Lazy-import to avoid circular imports at module load
        if analyzer is None:
            from memgar.analyzer import Analyzer as _Analyzer
            self._analyzer: "Analyzer" = _Analyzer(use_llm=False)
        else:
            self._analyzer = analyzer

        self._lock = threading.Lock()
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # entry_id → _CacheEntry
        self._scan_cache: Dict[str, _CacheEntry] = {}
        self._stats = HunterStats()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start the background scan loop (idempotent)."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="memgar-hunter",
        )
        self._thread.start()
        logger.info(
            "MemoryHunter started (interval=%ds, threshold=%.2f)",
            self._config.scan_interval_seconds,
            self._config.alert_threshold,
        )

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the background scan loop and wait for the thread to exit."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("MemoryHunter stopped")

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def stats(self) -> HunterStats:
        """Return a snapshot copy of current statistics (thread-safe)."""
        with self._lock:
            return dataclasses.replace(self._stats)

    # -------------------------------------------------------------------------
    # Scan loop
    # -------------------------------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._run_scan_cycle()
            except Exception:
                logger.exception("MemoryHunter: unhandled error in scan cycle")
            self._stop_event.wait(timeout=self._config.scan_interval_seconds)

    def _run_scan_cycle(self) -> None:
        """Execute one full scan pass over all entries from the provider."""
        t0 = time.monotonic()

        try:
            entries = self._provider()
        except Exception:
            logger.exception("MemoryHunter: memory_provider raised an exception")
            return

        if not entries:
            return

        if self._config.max_entries_per_scan > 0:
            entries = entries[: self._config.max_entries_per_scan]

        now = time.time()
        rescan_ttl = self._config.rescan_clean_after_seconds
        scanned = skipped = threats = 0

        for entry in entries:
            entry_id = _entry_id(entry)

            with self._lock:
                cached = self._scan_cache.get(entry_id)

            if cached is not None and cached.status == "clean":
                if (now - cached.ts) < rescan_ttl:
                    skipped += 1
                    continue

            try:
                result = self._analyzer.analyze(entry)
            except Exception:
                logger.exception("MemoryHunter: analysis failed for entry %s", entry_id)
                continue

            scanned += 1
            risk_normalized = result.risk_score / 100.0

            if risk_normalized >= self._config.alert_threshold and result.decision != Decision.ALLOW:
                threats += 1
                self._emit_threat(entry, entry_id, result)
                with self._lock:
                    self._scan_cache[entry_id] = _CacheEntry(status="threat", ts=now)
            else:
                with self._lock:
                    self._scan_cache[entry_id] = _CacheEntry(status="clean", ts=now)

        elapsed_ms = (time.monotonic() - t0) * 1000

        with self._lock:
            self._stats.total_scanned += scanned
            self._stats.threats_found += threats
            self._stats.entries_skipped += skipped
            self._stats.scan_cycles += 1
            self._stats.last_scan_time = now
            self._stats.last_scan_duration_ms = elapsed_ms

        logger.debug(
            "MemoryHunter cycle: scanned=%d threats=%d skipped=%d elapsed=%.1fms",
            scanned, threats, skipped, elapsed_ms,
        )

    # -------------------------------------------------------------------------
    # SIEM emission
    # -------------------------------------------------------------------------

    def _emit_threat(self, entry: MemoryEntry, entry_id: str, result) -> None:
        if self._siem is None:
            return
        try:
            from memgar.siem import SIEMEvent
            first = result.threats[0] if result.threats else None
            threat_id = first.threat.id if first else "HUNTER-DETECT"
            threat_name = first.threat.name if first else "Hunter Discovery"
            event = SIEMEvent.threat_detected(
                threat_id=threat_id,
                threat_name=threat_name,
                content=entry.content,
                risk_score=result.risk_score,
                agent_id=self._agent_id,
                severity=_severity(result.risk_score),
                extra={
                    "hunter_entry_id": entry_id,
                    "discovery_type": "retroactive_scan",
                },
            )
            self._siem.emit(event)
        except Exception:
            logger.exception("MemoryHunter: SIEM emit failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_id(entry: MemoryEntry) -> str:
    """Stable identifier for a memory entry."""
    if entry.source_id:
        return entry.source_id
    return hashlib.sha256(entry.content.encode("utf-8", errors="replace")).hexdigest()[:16]


def _severity(risk_score: int) -> str:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def start_hunter(
    analyzer: "Analyzer",
    config: Optional[HunterConfig] = None,
    siem_router: Optional["SIEMRouter"] = None,
    agent_id: Optional[str] = None,
) -> "MemoryHunter":
    """
    Convenience factory: attach a MemoryStore to an existing Analyzer and
    start a MemoryHunter that scans all entries the Analyzer has seen.

    Usage:
        from memgar import Analyzer
        from memgar.hunter import start_hunter

        analyzer = Analyzer(use_llm=False)
        hunter = start_hunter(analyzer)      # auto-starts in background

        # From this point on, every analyze() call is captured.
        # Hunter re-evaluates all entries every 60s with the latest patterns.

        hunter.stop()
    """
    from memgar.memory_store import MemoryStore

    if analyzer._memory_store is None:
        analyzer._memory_store = MemoryStore()

    hunter = MemoryHunter(
        memory_provider=analyzer._memory_store.get_entries,
        analyzer=analyzer,
        config=config or HunterConfig(),
        siem_router=siem_router,
        agent_id=agent_id,
    )
    hunter.start()
    return hunter


__all__ = ["MemoryHunter", "HunterStats", "start_hunter"]
