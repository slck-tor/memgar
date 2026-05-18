"""Fleet-wide signal aggregator and reputation scorer.

The aggregator receives anonymised telemetry events from self-hosted memgar
instances and maintains running statistics per-source and per-pattern. It
emits two derived products:

  1. **Reputation scores** — `reputation(source_id) → float in [0, 1]`.
     Sources that produce many high-risk hits across many tenants get a
     low reputation; sources with consistent low-risk activity get a high
     one. The score adjusts the trust weight memgar's Layer 3 already
     applies.

  2. **Sector baselines** — per-pattern hit rate by industry sector
     (`legal`, `health`, `finance`, …). Used by clients to compare their
     own deployment against the cohort average ("you're seeing 4× more
     `XSESS-003` than the legal sector average").

All inputs are SHA-256 hashes — the aggregator never sees the raw
content. Two tenants seeing the same poisoned chunk produce the same
`signal_hash`, which is how reputation aggregates work across customers
without leaking data.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple


@dataclass
class TelemetryRecord:
    """Wire format of a single telemetry hit (after server-side validation)."""

    tenant_id: str
    received_at: float
    signal_hash: str                 # sha256(content) on the client side
    source_id_hash: str              # sha256(source_id) — also anonymised
    pattern_id: str                  # threat ID (not hashed — public catalog)
    risk_score: int                  # 0-100
    decision: str                    # "allow" | "sanitize" | "quarantine" | "block"
    sector: Optional[str] = None     # e.g. "legal" / "health" / "ecom" (opt-in)

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "received_at": self.received_at,
            "signal_hash": self.signal_hash,
            "source_id_hash": self.source_id_hash,
            "pattern_id": self.pattern_id,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "sector": self.sector,
        }


@dataclass
class SourceStats:
    """Running stats per `source_id_hash`."""

    source_id_hash: str
    distinct_tenants: set = field(default_factory=set)
    total_hits: int = 0
    blocked_hits: int = 0
    quarantined_hits: int = 0
    sum_risk: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def mean_risk(self) -> float:
        return self.sum_risk / self.total_hits if self.total_hits else 0.0

    @property
    def block_rate(self) -> float:
        if self.total_hits == 0:
            return 0.0
        return (self.blocked_hits + self.quarantined_hits) / self.total_hits

    @property
    def tenant_count(self) -> int:
        return len(self.distinct_tenants)


# ─── Aggregator ────────────────────────────────────────────────────────


class SignalAggregator:
    """In-memory aggregator with bounded history + reputation derivation.

    The default storage is bounded (last N events, configurable) so the
    aggregator can run in a single process without unbounded memory growth.
    For multi-node deployments, swap the storage layer with Redis or
    Postgres by implementing `_store_event` and `_query_source`.
    """

    def __init__(
        self,
        *,
        history_size: int = 100_000,
        min_observations_for_reputation: int = 5,
        cross_tenant_penalty_per_extra_tenant: float = 0.03,
        decay_half_life_seconds: float = 7 * 24 * 3600,
    ) -> None:
        self.history_size = history_size
        self.min_observations = min_observations_for_reputation
        self.cross_tenant_penalty = cross_tenant_penalty_per_extra_tenant
        self.decay_half_life = decay_half_life_seconds
        self._lock = threading.Lock()
        self._events: Deque[TelemetryRecord] = deque(maxlen=history_size)
        self._by_source: Dict[str, SourceStats] = {}
        self._by_pattern_sector: Dict[Tuple[str, str], int] = defaultdict(int)
        self._totals_by_pattern: Dict[str, int] = defaultdict(int)
        self._totals_by_sector: Dict[str, int] = defaultdict(int)

    # ─── Ingest ──────────────────────────────────────────────────────

    def ingest(self, record: TelemetryRecord) -> None:
        with self._lock:
            self._events.append(record)
            stats = self._by_source.setdefault(
                record.source_id_hash,
                SourceStats(source_id_hash=record.source_id_hash),
            )
            stats.distinct_tenants.add(record.tenant_id)
            stats.total_hits += 1
            stats.sum_risk += record.risk_score
            if record.decision == "block":
                stats.blocked_hits += 1
            elif record.decision == "quarantine":
                stats.quarantined_hits += 1
            if stats.first_seen == 0.0:
                stats.first_seen = record.received_at
            stats.last_seen = record.received_at

            self._totals_by_pattern[record.pattern_id] += 1
            if record.sector:
                self._by_pattern_sector[(record.pattern_id, record.sector)] += 1
                self._totals_by_sector[record.sector] += 1

    def ingest_many(self, records: Iterable[TelemetryRecord]) -> int:
        n = 0
        for r in records:
            self.ingest(r)
            n += 1
        return n

    # ─── Reputation ──────────────────────────────────────────────────

    def reputation(self, source_id_hash: str, *, now: Optional[float] = None) -> float:
        """Return a [0, 1] reputation score. 1 = trustworthy, 0 = malicious.

        Components:
          - 1 − (mean_risk / 100)      base benignness
          - cross-tenant penalty       multiple customers seeing this source
          - block-rate penalty         hard-blocked content is the loudest signal
          - time-decay                 old observations weigh less

        Insufficient data → 0.5 (neutral). Caller can short-circuit to
        local Layer 3 trust when reputation is neutral.
        """
        stats = self._by_source.get(source_id_hash)
        if stats is None or stats.total_hits < self.min_observations:
            return 0.5
        now = now or time.time()

        base = 1.0 - (stats.mean_risk / 100.0)

        # Each additional tenant that's seen this source compounds suspicion
        cross_penalty = self.cross_tenant_penalty * max(0, stats.tenant_count - 1)

        block_penalty = 0.4 * stats.block_rate

        # Time decay — observations older than `decay_half_life` lose half their weight
        age = now - stats.last_seen
        decay = 0.5 ** (age / self.decay_half_life) if self.decay_half_life > 0 else 1.0

        raw = max(0.0, base - cross_penalty - block_penalty) * decay
        # Re-anchor toward 0.5 when decayed (old data shouldn't push to extremes)
        anchored = decay * raw + (1.0 - decay) * 0.5
        return max(0.0, min(1.0, anchored))

    def source_card(self, source_id_hash: str) -> Optional[dict]:
        """Dashboard-ready summary of a source's observed behaviour."""
        stats = self._by_source.get(source_id_hash)
        if stats is None:
            return None
        return {
            "source_id_hash": stats.source_id_hash,
            "reputation": self.reputation(source_id_hash),
            "total_hits": stats.total_hits,
            "tenant_count": stats.tenant_count,
            "mean_risk": stats.mean_risk,
            "block_rate": stats.block_rate,
            "first_seen": stats.first_seen,
            "last_seen": stats.last_seen,
        }

    # ─── Sector baselines ────────────────────────────────────────────

    def sector_baseline(self, sector: str, pattern_id: str) -> Optional[float]:
        """Return per-1000-hits frequency of `pattern_id` in `sector`."""
        sector_total = self._totals_by_sector.get(sector, 0)
        if sector_total == 0:
            return None
        hits = self._by_pattern_sector.get((pattern_id, sector), 0)
        return 1000.0 * hits / sector_total

    def top_patterns_for_sector(self, sector: str, n: int = 10) -> List[dict]:
        rows = [
            (pid, count)
            for (pid, sec), count in self._by_pattern_sector.items()
            if sec == sector
        ]
        rows.sort(key=lambda row: -row[1])
        return [{"pattern_id": pid, "hits": count} for pid, count in rows[:n]]

    # ─── Summary ─────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            "event_count": len(self._events),
            "distinct_sources": len(self._by_source),
            "distinct_patterns": len(self._totals_by_pattern),
            "distinct_sectors": len(self._totals_by_sector),
            "top_patterns": [
                {"pattern_id": pid, "hits": count}
                for pid, count in sorted(
                    self._totals_by_pattern.items(),
                    key=lambda kv: -kv[1],
                )[:10]
            ],
        }


__all__ = [
    "TelemetryRecord",
    "SourceStats",
    "SignalAggregator",
]
