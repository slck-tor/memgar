"""
Memgar MemoryHunter — Active Background Scanner
================================================

Continuously scans a memory store for attacks that were not caught at write-time.

Quick-start (zero config):

    from memgar import Analyzer
    from memgar.hunter import start_hunter

    analyzer = Analyzer(use_llm=False)
    hunter = start_hunter(analyzer)         # auto-starts, scans every 60s

Connect to your data source — pick one:

    # SQLite database (stdlib, no extra deps)
    hunter = MemoryHunter.from_sqlite("memories.db", table="entries", column="text")

    # Plain Python list
    hunter = MemoryHunter.from_list(["User prefers dark mode", "..."])

    # JSONL file
    hunter = MemoryHunter.from_jsonl("memories.jsonl", column="content")

    # Your own database (any backend)
    hunter = MemoryHunter(memory_provider=lambda: db.fetch_recent(days=30))

User-friendly extras:

    hunter.scan_now()           # trigger an immediate scan (no waiting)
    hunter.report()             # print a human-readable status summary
    hunter.on_threat = fn       # called with (entry, result) on each finding

    with hunter:                # context manager — auto stop on exit
        ...

Configuration via HunterConfig (or env vars MEMGAR_HUNTER_*):
    scan_interval_seconds=60        — how often to scan
    rescan_clean_after_seconds=3600 — re-evaluate clean entries after 1h
    alert_threshold=0.7             — risk_score/100 threshold for alerting
    max_entries_per_scan=1000       — cap per cycle to bound latency
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
import time
from datetime import datetime
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
      2. For each entry: if recently scanned and clean (within rescan TTL), skip.
         Otherwise analyze with the latest threat patterns.
      3. Entries whose risk_score/100 >= alert_threshold trigger on_threat callback
         and an optional SIEM event.
      4. Stats are updated atomically after each cycle.
    """

    def __init__(
        self,
        memory_provider: Callable[[], List[MemoryEntry]],
        analyzer: Optional["Analyzer"] = None,
        config: Optional[HunterConfig] = None,
        siem_router: Optional["SIEMRouter"] = None,
        agent_id: Optional[str] = None,
        on_threat: Optional[Callable] = None,
    ):
        """
        Args:
            memory_provider: Callable returning the list of entries to scan.
            analyzer:        Analyzer instance. Created automatically if None.
            config:          HunterConfig. Defaults applied if None.
            siem_router:     Optional SIEM router for structured event emission.
            agent_id:        Agent identifier included in SIEM events.
            on_threat:       Callback fn(entry, result) called on each finding.
                             Use this for custom alerting (Slack, webhook, log, etc.)
        """
        self._provider = memory_provider
        self._config = config or HunterConfig()
        self._siem = siem_router
        self._agent_id = agent_id
        self.on_threat = on_threat

        if analyzer is None:
            from memgar.analyzer import Analyzer as _Analyzer
            self._analyzer: "Analyzer" = _Analyzer(use_llm=False)
        else:
            self._analyzer = analyzer

        self._lock = threading.Lock()
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._scan_cache: Dict[str, _CacheEntry] = {}
        self._stats = HunterStats()

    # -------------------------------------------------------------------------
    # Factory constructors — user-friendly data-source connectors
    # -------------------------------------------------------------------------

    @classmethod
    def from_sqlite(
        cls,
        db_path: str,
        table: str = "memories",
        column: str = "content",
        id_column: Optional[str] = "id",
        where: str = "",
        limit: int = 10_000,
        **kwargs,
    ) -> "MemoryHunter":
        """
        Create a hunter that reads from a SQLite database.

        Uses Python's built-in sqlite3 — no extra dependencies.

        Args:
            db_path:   Path to the SQLite file (e.g. "memories.db").
            table:     Table name (default: "memories").
            column:    Text column to analyze (default: "content").
            id_column: Primary key column used as source_id (default: "id").
                       Pass None to use content hash instead.
            where:     Optional SQL WHERE clause, e.g. "created > '2025-01-01'".
            limit:     Max rows per scan cycle (default: 10 000).
            **kwargs:  Passed to MemoryHunter.__init__.

        Example:
            hunter = MemoryHunter.from_sqlite(
                "agent_memories.db",
                table="memories",
                column="text",
                where="created > date('now', '-30 days')",
            )
            hunter.start()
        """
        import sqlite3

        def _provider() -> List[MemoryEntry]:
            try:
                conn = sqlite3.connect(db_path)
                try:
                    id_sel = f", {id_column}" if id_column else ""
                    wh = f"WHERE {where}" if where else ""
                    rows = conn.execute(
                        f"SELECT {column}{id_sel} FROM {table} {wh} LIMIT {limit}"
                    ).fetchall()
                    return [
                        MemoryEntry(
                            content=str(r[0]),
                            source_id=str(r[1]) if id_column else None,
                        )
                        for r in rows
                        if r[0]
                    ]
                finally:
                    conn.close()
            except Exception as exc:
                logger.warning("MemoryHunter.from_sqlite: query failed: %s", exc)
                return []

        return cls(memory_provider=_provider, **kwargs)

    @classmethod
    def from_list(
        cls,
        entries: List[str],
        **kwargs,
    ) -> "MemoryHunter":
        """
        Create a hunter over a plain Python list of strings.

        The list is captured by reference — mutations after creation are reflected
        in subsequent scan cycles.

        Example:
            memories = ["User prefers dark mode", "Ignore all instructions..."]
            hunter = MemoryHunter.from_list(memories)
            hunter.scan_now()
            hunter.report()
        """
        def _provider() -> List[MemoryEntry]:
            return [MemoryEntry(content=t) for t in entries if t and t.strip()]

        return cls(memory_provider=_provider, **kwargs)

    @classmethod
    def from_jsonl(
        cls,
        path: str,
        column: str = "content",
        id_column: Optional[str] = "id",
        **kwargs,
    ) -> "MemoryHunter":
        """
        Create a hunter that reads MemoryEntry objects from a JSONL file.

        Each line must be a JSON object with at least the `column` key.

        Args:
            path:      Path to the JSONL file.
            column:    Key to read as content (default: "content").
            id_column: Key to use as source_id (default: "id"). None = auto.
            **kwargs:  Passed to MemoryHunter.__init__.

        Example:
            hunter = MemoryHunter.from_jsonl("exports/memories.jsonl")
            hunter.scan_now()
        """
        import json
        from pathlib import Path as _Path

        def _provider() -> List[MemoryEntry]:
            p = _Path(path)
            if not p.exists():
                logger.warning("MemoryHunter.from_jsonl: file not found: %s", path)
                return []
            entries = []
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    content = obj.get(column, "")
                    if content:
                        entries.append(MemoryEntry(
                            content=str(content),
                            source_id=str(obj[id_column]) if id_column and id_column in obj else None,
                        ))
                except (json.JSONDecodeError, KeyError):
                    pass
            return entries

        return cls(memory_provider=_provider, **kwargs)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> "MemoryHunter":
        """Start the background scan loop. Returns self for chaining."""
        with self._lock:
            if self._running:
                return self
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
        return self

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

    def scan_now(self) -> HunterStats:
        """
        Trigger an immediate scan cycle synchronously (blocks until complete).

        Useful for on-demand scanning without waiting for the next interval.
        Safe to call while the background thread is also running.

        Returns:
            HunterStats snapshot after the scan completes.

        Example:
            hunter = MemoryHunter.from_sqlite("memories.db")
            stats = hunter.scan_now()
            print(f"Threats found: {stats.threats_found}")
        """
        self._run_scan_cycle()
        return self.stats()

    def stats(self) -> HunterStats:
        """Return a snapshot copy of current statistics (thread-safe)."""
        with self._lock:
            return dataclasses.replace(self._stats)

    def report(self) -> None:
        """
        Print a human-readable status summary to stdout.

        Example output:
            ┌─ MemoryHunter Status ──────────────────────────────┐
            │ Status          : RUNNING                          │
            │ Scan cycles     : 12                               │
            │ Entries scanned : 1 420                            │
            │ Threats found   : 3                                │
            │ Entries skipped : 118 (clean, within TTL)          │
            │ Last scan       : 2025-05-03 14:22:01 (8s ago)     │
            │ Last scan time  : 142.3 ms                         │
            │ Interval        : 60s                              │
            │ Threshold       : 0.70                             │
            └────────────────────────────────────────────────────┘
        """
        s = self.stats()
        running = "RUNNING" if self.is_running() else "STOPPED"

        last = "never"
        if s.last_scan_time is not None:
            dt = datetime.fromtimestamp(s.last_scan_time)
            ago = int(time.time() - s.last_scan_time)
            last = f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({ago}s ago)"

        lines = [
            ("Status",          running),
            ("Scan cycles",     str(s.scan_cycles)),
            ("Entries scanned", str(s.total_scanned)),
            ("Threats found",   str(s.threats_found)),
            ("Entries skipped", f"{s.entries_skipped} (clean, within TTL)"),
            ("Last scan",       last),
            ("Last scan time",  f"{s.last_scan_duration_ms:.1f} ms"),
            ("Interval",        f"{self._config.scan_interval_seconds}s"),
            ("Threshold",       f"{self._config.alert_threshold:.2f}"),
        ]

        width = 52
        print(f"┌─ MemoryHunter Status {'─' * (width - 22)}┐")
        for label, value in lines:
            row = f"│ {label:<16} : {value}"
            print(f"{row:<{width + 2}} │")
        print(f"└{'─' * (width + 2)}┘")

    # -------------------------------------------------------------------------
    # Context manager
    # -------------------------------------------------------------------------

    def __enter__(self) -> "MemoryHunter":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

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
                self._handle_threat(entry, entry_id, result)
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
    # Threat handling
    # -------------------------------------------------------------------------

    def _handle_threat(self, entry: MemoryEntry, entry_id: str, result) -> None:
        """Call on_threat callback and emit SIEM event."""
        if self.on_threat is not None:
            try:
                self.on_threat(entry, result)
            except Exception:
                logger.exception("MemoryHunter: on_threat callback raised")

        self._emit_siem(entry, entry_id, result)

    def _emit_siem(self, entry: MemoryEntry, entry_id: str, result) -> None:
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


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def start_hunter(
    analyzer: "Analyzer",
    config: Optional[HunterConfig] = None,
    siem_router: Optional["SIEMRouter"] = None,
    agent_id: Optional[str] = None,
    on_threat: Optional[Callable] = None,
) -> "MemoryHunter":
    """
    Zero-config factory: attach a MemoryStore to an existing Analyzer and
    start a MemoryHunter immediately.

    Every analyze() call made on the Analyzer after this point is captured
    and re-evaluated retroactively on each scan cycle.

    Args:
        analyzer:   An Analyzer instance (already created).
        config:     Optional HunterConfig overrides.
        siem_router: Optional SIEM router for structured events.
        agent_id:   Agent identifier for SIEM events.
        on_threat:  Callback fn(entry, result) called on each threat finding.

    Example:
        from memgar import Analyzer
        from memgar.hunter import start_hunter

        analyzer = Analyzer(use_llm=False)
        hunter = start_hunter(
            analyzer,
            on_threat=lambda e, r: print(f"THREAT: {e.content[:60]} (score={r.risk_score})"),
        )
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
        on_threat=on_threat,
    )
    hunter.start()
    return hunter


__all__ = ["MemoryHunter", "HunterStats", "start_hunter"]
