"""
Memgar Secure Retrieval Layer
==============================

Layer 3 of the Schneider defense architecture:
  - Trust-weighted ranking: provenance scores adjust relevance
  - Temporal decay: older memories lose influence (combined with trust)
  - Retrieval anomaly detection: flags suspicious access patterns

Components:
    TemporalDecayEngine      - 4 decay shapes (exp, linear, step, hybrid)
    TrustWeightedScorer      - provenance + decay composite scoring
    RetrievalAnomalyMonitor  - frequency, narrow-pattern, spread, spike detection
    SecureMemoryRetriever    - full pipeline over MemoryLedger
    RetrievalExplainer       - human-readable score breakdown

Usage::

    from memgar.secure_retriever import SecureMemoryRetriever
    from memgar.memory_ledger import MemoryLedger

    ledger = MemoryLedger("./agent_memory.json")
    retriever = SecureMemoryRetriever(ledger=ledger)

    results = retriever.retrieve(
        query="user preferences",
        top_k=5,
        similarity_fn=my_embed_fn,   # optional semantic search
    )
    for doc in results.documents:
        print(doc.content, doc.final_score)

    report = retriever.anomaly_report()
    print(report)
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DecayShape(str, Enum):
    EXPONENTIAL = "exponential"
    LINEAR      = "linear"
    STEP        = "step"
    HYBRID      = "hybrid"          # exponential + access reinforcement


class AnomalyType(str, Enum):
    HIGH_FREQUENCY   = "high_frequency"
    NARROW_PATTERN   = "narrow_pattern"
    UNTRUSTED_SPREAD = "untrusted_spread"
    SUDDEN_SPIKE     = "sudden_spike"
    RECENCY_EXPLOIT  = "recency_exploit"


# ---------------------------------------------------------------------------
# Temporal Decay Engine
# ---------------------------------------------------------------------------

class TemporalDecayEngine:
    """
    Time-based memory weight reduction with 4 decay shapes.

    Anti-recency-exploit: low-trust memories cannot benefit from the
    recency boost. This prevents the attack where an attacker injects
    fresh malicious memories that temporarily outweigh stable legitimate ones.

    Args:
        half_life_days:  Exponential half-life (default: 30)
        shape:           Decay curve shape
        min_factor:      Minimum weight floor, never drops to zero (default: 0.1)
        recency_boost:   Extra weight for fresh high-trust entries (default: 0.15)
        trust_gate:      Minimum trust score to receive recency boost (default: 0.6)
        step_thresholds: [(days, factor)] for STEP shape
    """

    _STEP_DEFAULTS: List[Tuple[float, float]] = [
        (7.0,         1.00),
        (30.0,        0.80),
        (90.0,        0.55),
        (180.0,       0.35),
        (float("inf"), 0.15),
    ]

    def __init__(
        self,
        half_life_days:  float = 30.0,
        shape:           DecayShape = DecayShape.EXPONENTIAL,
        min_factor:      float = 0.10,
        recency_boost:   float = 0.15,
        trust_gate:      float = 0.60,
        step_thresholds: Optional[List[Tuple[float, float]]] = None,
    ) -> None:
        self.half_life    = half_life_days
        self.shape        = shape
        self.min_factor   = min_factor
        self.recency_boost = recency_boost
        self.trust_gate   = trust_gate
        self.steps        = step_thresholds or self._STEP_DEFAULTS

    def factor(
        self,
        created_at:    datetime,
        trust_score:   float = 1.0,
        access_count:  int = 0,
        last_accessed: Optional[datetime] = None,
    ) -> float:
        """
        Returns decay factor in [min_factor, 1.0].
        1.0 = fresh, full weight. min_factor = oldest possible weight.
        """
        now = datetime.now(tz=timezone.utc)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (now - created_at).total_seconds() / 86400.0)

        if self.shape == DecayShape.EXPONENTIAL:
            base = math.pow(0.5, age_days / self.half_life)

        elif self.shape == DecayShape.LINEAR:
            base = max(0.0, 1.0 - age_days / (self.half_life * 2))

        elif self.shape == DecayShape.STEP:
            base = self.min_factor
            for threshold, f in self.steps:
                if age_days <= threshold:
                    base = f
                    break

        else:  # HYBRID: exponential + access reinforcement
            base = math.pow(0.5, age_days / self.half_life)
            if access_count > 0:
                base = min(1.0, base + math.log1p(access_count) * 0.08)

        base = max(self.min_factor, base)

        # Recency boost for fresh, high-trust entries only
        if age_days < 1.0:
            if trust_score >= self.trust_gate:
                base = min(1.0, base + self.recency_boost)
            else:
                # Penalize fresh low-trust — prevents recency exploit
                base = base * 0.82

        return round(base, 4)

    def schedule(self, days: int = 90, step: int = 7) -> List[Tuple[int, float]]:
        """Returns [(day, factor)] for debugging/visualization."""
        now = datetime.now(tz=timezone.utc)
        from datetime import timedelta
        return [
            (d, self.factor(now - timedelta(days=d), trust_score=0.8))
            for d in range(0, days + 1, step)
        ]


# ---------------------------------------------------------------------------
# Trust-Weighted Scorer
# ---------------------------------------------------------------------------

_SOURCE_TRUST: Dict[str, float] = {
    "system":      0.95,
    "user_input":  0.70,
    "tool_output": 0.75,
    "agent":       0.65,
    "api":         0.50,
    "document":    0.45,
    "email":       0.40,
    "webpage":     0.25,
    "unknown":     0.20,
}


@dataclass
class ScoredEntry:
    """A memory entry with composite trust-weighted score."""
    entry_id:        str
    content:         str
    base_score:      float   # raw similarity/keyword score [0, 1]
    trust_weight:    float   # provenance-derived weight [0, 1]
    decay_factor:    float   # temporal decay [min_factor, 1]
    anomaly_penalty: float   # [0, 1]; multiplied: 0 = no penalty, 1 = zero score
    final_score:     float   # composite [0, 1]
    source_type:     str
    trust_score:     float
    age_days:        float
    created_at:      Optional[str]
    is_filtered:     bool
    is_anomalous:    bool
    should_review:   bool
    explanation:     str
    metadata:        Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id":        self.entry_id,
            "content_preview": self.content[:100],
            "base_score":      round(self.base_score, 4),
            "trust_weight":    round(self.trust_weight, 4),
            "decay_factor":    round(self.decay_factor, 4),
            "anomaly_penalty": round(self.anomaly_penalty, 4),
            "final_score":     round(self.final_score, 4),
            "source_type":     self.source_type,
            "trust_score":     round(self.trust_score, 3),
            "age_days":        round(self.age_days, 1),
            "is_filtered":     self.is_filtered,
            "is_anomalous":    self.is_anomalous,
            "should_review":   self.should_review,
            "explanation":     self.explanation,
        }


@dataclass
class RetrievalResult:
    """Result of a secure retrieval operation."""
    documents:        List[ScoredEntry]
    query:            str
    total_candidates: int
    filtered_count:   int
    anomaly_count:    int
    retrieval_ms:     float
    retrieved_at:     str

    @property
    def has_anomalies(self) -> bool:
        return self.anomaly_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_preview":      self.query[:80],
            "documents_returned": len(self.documents),
            "total_candidates":   self.total_candidates,
            "filtered":           self.filtered_count,
            "anomalies":          self.anomaly_count,
            "retrieval_ms":       round(self.retrieval_ms, 1),
            "retrieved_at":       self.retrieved_at,
            "documents":          [d.to_dict() for d in self.documents],
        }


class TrustWeightedScorer:
    """
    Computes composite final score from similarity, trust, decay, and anomaly.

    Formula:
        trust_adjusted   = base * (1 - alpha + alpha * trust_weight)
        temporal_adjusted = trust_adjusted * (1 - beta + beta * decay_factor)
        final_score       = temporal_adjusted * (1 - anomaly_penalty)

    alpha = trust_weight_factor   (default 0.35)
    beta  = temporal_weight_factor (default 0.20)

    Setting alpha=0 degrades to pure similarity ranking (backward compat).
    Setting alpha=1 makes trust equally important as relevance.
    Multiplicative interpolation avoids extreme values.

    Args:
        trust_weight_factor:     Weight of trust in final score (default: 0.35)
        temporal_weight_factor:  Weight of temporal decay (default: 0.20)
        min_trust_threshold:     Entries below this are filtered (default: 0.15)
        filter_flagged:          Filter flagged entries (default: True)
        filter_high_risk:        Filter high-risk entries (default: True)
        high_risk_threshold:     Risk score at which entry is filtered (default: 70)
    """

    def __init__(
        self,
        trust_weight_factor:    float = 0.35,
        temporal_weight_factor: float = 0.20,
        min_trust_threshold:    float = 0.15,
        filter_flagged:         bool = True,
        filter_high_risk:       bool = True,
        high_risk_threshold:    int = 70,
    ) -> None:
        self.alpha        = trust_weight_factor
        self.beta         = temporal_weight_factor
        self.min_trust    = min_trust_threshold
        self.filt_flagged = filter_flagged
        self.filt_risk    = filter_high_risk
        self.risk_thresh  = high_risk_threshold

    def score(
        self,
        entry_id:        str,
        content:         str,
        base_score:      float,
        metadata:        Dict[str, Any],
        decay_engine:    TemporalDecayEngine,
        anomaly_penalty: float = 0.0,
    ) -> Tuple[ScoredEntry, bool]:
        """
        Score a single entry.

        Returns:
            (ScoredEntry, should_filter)
        """
        trust_score    = float(metadata.get("trust_score", 0.5))
        source_type    = str(metadata.get("source_type", "unknown"))
        risk_score     = int(metadata.get("risk_score", 0))
        is_flagged     = bool(metadata.get("flagged", False))
        was_sanitized  = bool(metadata.get("was_sanitized", False))
        access_count   = int(metadata.get("access_count", 0))
        source_verified = bool(metadata.get("source_verified", False))
        created_at_str = metadata.get("created_at") or metadata.get("timestamp")

        # Effective trust: metadata value takes precedence over source-type default
        src_default    = _SOURCE_TRUST.get(source_type.lower(), 0.20)
        effective_trust = trust_score if trust_score != 0.5 else src_default
        effective_trust = max(0.0, min(1.0, effective_trust))

        # Trust weight: mapped to [0.5, 1.0]
        trust_weight = 0.5 + effective_trust * 0.5
        if source_verified:
            trust_weight = min(1.0, trust_weight + 0.10)
        if was_sanitized:
            trust_weight *= 0.90

        # Parse timestamp
        created_at = _parse_dt(created_at_str)
        last_accessed = _parse_dt(metadata.get("last_accessed_at"))
        age_days = 0.0
        if created_at:
            age_days = (datetime.now(tz=timezone.utc) - created_at).total_seconds() / 86400.0
        age_days = max(0.0, age_days)

        # Temporal decay
        decay = decay_engine.factor(
            created_at   = created_at or datetime.now(tz=timezone.utc),
            trust_score  = effective_trust,
            access_count = access_count,
            last_accessed = last_accessed,
        )

        # Composite score
        trust_adj    = base_score * (1 - self.alpha + self.alpha * trust_weight)
        temporal_adj = trust_adj  * (1 - self.beta  + self.beta  * decay)
        final        = max(0.0, min(1.0, temporal_adj * (1.0 - anomaly_penalty)))

        # Filter decision
        should_filter = False
        filter_reason = ""
        if self.filt_flagged and is_flagged:
            should_filter = True
            filter_reason = "flagged"
        elif self.filt_risk and risk_score >= self.risk_thresh:
            should_filter = True
            filter_reason = f"high_risk={risk_score}"
        elif effective_trust < self.min_trust:
            should_filter = True
            filter_reason = f"low_trust={effective_trust:.2f}"

        explanation = (
            f"base={base_score:.3f}"
            f" trust={effective_trust:.2f}→w={trust_weight:.3f}"
            f" decay={decay:.3f}(age={age_days:.0f}d)"
            + (f" anomaly_pen={anomaly_penalty:.2f}" if anomaly_penalty > 0 else "")
            + (f" [FILTERED:{filter_reason}]" if should_filter else "")
            + f" → final={final:.3f}"
        )

        scored = ScoredEntry(
            entry_id        = entry_id,
            content         = content,
            base_score      = base_score,
            trust_weight    = trust_weight,
            decay_factor    = decay,
            anomaly_penalty = anomaly_penalty,
            final_score     = final,
            source_type     = source_type,
            trust_score     = effective_trust,
            age_days        = age_days,
            created_at      = created_at_str,
            is_filtered     = should_filter,
            is_anomalous    = anomaly_penalty > 0,
            should_review   = is_flagged or anomaly_penalty > 0,
            explanation     = explanation,
            metadata        = metadata,
        )
        return scored, should_filter


# ---------------------------------------------------------------------------
# Retrieval Anomaly Monitor
# ---------------------------------------------------------------------------

@dataclass
class AnomalyEvent:
    entry_id:     str
    anomaly_type: AnomalyType
    severity:     str    # low / medium / high / critical
    detail:       str
    detected_at:  str


class RetrievalAnomalyMonitor:
    """
    Detects anomalous memory access patterns at retrieval time.

    Schneider: "Poisoned memories often have distinctive retrieval signatures:
    they activate on narrow query ranges designed to match attacker-chosen
    targets. A memory that suddenly starts appearing in many unrelated
    contexts warrants investigation."

    Detected patterns:

        HIGH_FREQUENCY   — entry retrieved far above baseline rate
        NARROW_PATTERN   — high retrieval count but very few unique queries
                           → trigger-word signature (e.g., "yes", "confirm")
        UNTRUSTED_SPREAD — low-trust entry appearing across many topic contexts
                           → cross-context injection attempt
        SUDDEN_SPIKE     — retrieval rate spikes in last 5 minutes
        RECENCY_EXPLOIT  — fresh entry + low trust + high frequency

    Args:
        window_seconds:           Analysis window (default: 3600 = 1h)
        frequency_threshold:      Retrievals before HIGH_FREQUENCY fires (default: 10)
        narrow_pattern_threshold: Max unique queries before NARROW fires (default: 3)
        spread_threshold:         Min unique queries for SPREAD (default: 5)
        spike_factor:             Rate multiplier for SPIKE (default: 3x)
        low_trust_threshold:      Trust below this = "low trust" (default: 0.35)
    """

    def __init__(
        self,
        window_seconds:           float = 3600.0,
        frequency_threshold:      int   = 10,
        narrow_pattern_threshold: int   = 3,
        spread_threshold:         int   = 5,
        spike_factor:             float = 3.0,
        low_trust_threshold:      float = 0.35,
        recency_hours:            float = 1.0,
    ) -> None:
        self._window     = window_seconds
        self._freq_t     = frequency_threshold
        self._narrow_t   = narrow_pattern_threshold
        self._spread_t   = spread_threshold
        self._spike_f    = spike_factor
        self._low_trust  = low_trust_threshold
        self._recency_h  = recency_hours

        # entry_id → deque[(ts, query_lower, trust_score)]
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._events:  List[AnomalyEvent] = []

    def record(
        self,
        entry_id:    str,
        query:       str,
        trust_score: float,
        ts:          Optional[float] = None,
    ) -> None:
        self._history[entry_id].append((
            ts or time.time(),
            query.lower().strip()[:120],
            trust_score,
        ))

    def check(self, entry_id: str) -> List[AnomalyEvent]:
        """Check for anomalies for entry_id. Returns new events detected."""
        now    = time.time()
        cutoff = now - self._window
        h = [(ts, q, t) for ts, q, t in self._history[entry_id] if ts >= cutoff]
        if not h:
            return []

        new_events: List[AnomalyEvent] = []

        # A) HIGH_FREQUENCY
        if len(h) >= self._freq_t:
            new_events.append(AnomalyEvent(
                entry_id     = entry_id,
                anomaly_type = AnomalyType.HIGH_FREQUENCY,
                severity     = "high" if len(h) >= self._freq_t * 2 else "medium",
                detail       = f"Retrieved {len(h)}x in {self._window/3600:.0f}h (threshold={self._freq_t})",
                detected_at  = _now(),
            ))

        # B) NARROW_PATTERN — high count, very few unique queries → trigger word
        unique_q = set(q for _, q, _ in h)
        if len(h) >= 5 and len(unique_q) <= self._narrow_t:
            avg_len = sum(len(q.split()) for q in unique_q) / max(1, len(unique_q))
            if avg_len <= 4:
                new_events.append(AnomalyEvent(
                    entry_id     = entry_id,
                    anomaly_type = AnomalyType.NARROW_PATTERN,
                    severity     = "critical",
                    detail       = (
                        f"Only {len(unique_q)} unique queries in {len(h)} retrievals"
                        f" (avg_query_len={avg_len:.1f}) — possible trigger-word pattern"
                    ),
                    detected_at  = _now(),
                ))

        # C) UNTRUSTED_SPREAD — low-trust entry spanning many contexts
        avg_trust = sum(t for _, _, t in h) / len(h)
        if avg_trust < self._low_trust and len(unique_q) >= self._spread_t:
            new_events.append(AnomalyEvent(
                entry_id     = entry_id,
                anomaly_type = AnomalyType.UNTRUSTED_SPREAD,
                severity     = "high",
                detail       = (
                    f"Low-trust entry (avg_trust={avg_trust:.2f}) appearing in"
                    f" {len(unique_q)} different query contexts"
                ),
                detected_at  = _now(),
            ))

        # D) SUDDEN_SPIKE — last 5 min vs rest of window
        recent  = [ts for ts, _, _ in h if ts >= now - 300]
        older   = [ts for ts, _, _ in h if ts < now - 300]
        if len(recent) >= 3 and older:
            r_rate = len(recent) / 5.0
            o_rate = len(older) / max(1, (self._window - 300) / 60.0)
            if o_rate > 0 and r_rate / o_rate >= self._spike_f:
                new_events.append(AnomalyEvent(
                    entry_id     = entry_id,
                    anomaly_type = AnomalyType.SUDDEN_SPIKE,
                    severity     = "high",
                    detail       = f"Rate spike: {r_rate:.1f}/min vs {o_rate:.1f}/min baseline",
                    detected_at  = _now(),
                ))

        # E) RECENCY_EXPLOIT — fresh + low trust + moderate frequency
        recent_h = [ts for ts, _, _ in h if ts >= now - self._recency_h * 3600]
        if avg_trust < self._low_trust and len(recent_h) >= max(3, self._freq_t // 3):
            new_events.append(AnomalyEvent(
                entry_id     = entry_id,
                anomaly_type = AnomalyType.RECENCY_EXPLOIT,
                severity     = "high",
                detail       = (
                    f"Fresh low-trust entry retrieved {len(recent_h)}x in last"
                    f" {self._recency_h:.0f}h (trust={avg_trust:.2f})"
                ),
                detected_at  = _now(),
            ))

        # Deduplicate: only add new event types not already in self._events
        known = {(e.entry_id, e.anomaly_type.value) for e in self._events}
        for ev in new_events:
            key = (ev.entry_id, ev.anomaly_type.value)
            if key not in known:
                self._events.append(ev)
                known.add(key)

        return new_events

    def penalty_for(self, entry_id: str) -> float:
        """Returns anomaly penalty [0.0, 0.5] for use in score computation."""
        events = [e for e in self._events if e.entry_id == entry_id]
        if not events:
            return 0.0
        severity_weight = {"low": 0.05, "medium": 0.15, "high": 0.30, "critical": 0.50}
        return min(0.50, max(severity_weight.get(e.severity, 0.15) for e in events))

    def all_events(self) -> List[AnomalyEvent]:
        return list(self._events)

    def suspicious_entries(self) -> List[str]:
        return list({e.entry_id for e in self._events})

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = defaultdict(int)
        for e in self._events:
            by_type[e.anomaly_type.value] += 1
        return {
            "total_events":      len(self._events),
            "unique_entries":    len(self.suspicious_entries()),
            "by_type":           dict(by_type),
            "critical":          sum(1 for e in self._events if e.severity == "critical"),
            "high":              sum(1 for e in self._events if e.severity == "high"),
        }


# ---------------------------------------------------------------------------
# Secure Memory Retriever
# ---------------------------------------------------------------------------

class SecureMemoryRetriever:
    """
    Trust-aware retrieval over MemoryLedger.

    Implements the full Layer 3 pipeline:
        1. Fetch all candidate entries from ledger
        2. Run optional similarity function (keyword or semantic)
        3. Apply trust-weighted scoring (provenance + temporal decay)
        4. Check for retrieval anomalies and apply penalties
        5. Filter out low-trust / flagged / high-risk entries
        6. Re-rank by final composite score
        7. Return top-k with full explanation

    Args:
        ledger:                  MemoryLedger instance
        decay_engine:            TemporalDecayEngine (default: exponential 30d)
        scorer:                  TrustWeightedScorer (default: alpha=0.35 beta=0.20)
        anomaly_monitor:         RetrievalAnomalyMonitor (default: enabled)
        top_k:                   Default result count (default: 10)
        similarity_fn:           Optional fn(query, content) -> float [0,1]
                                 If None, uses keyword overlap scoring
        min_final_score:         Filter entries below this final score (default: 0.0)
    """

    def __init__(
        self,
        ledger:            Any,
        decay_engine:      Optional[TemporalDecayEngine] = None,
        scorer:            Optional[TrustWeightedScorer] = None,
        anomaly_monitor:   Optional[RetrievalAnomalyMonitor] = None,
        top_k:             int = 10,
        similarity_fn:     Optional[Callable[[str, str], float]] = None,
        min_final_score:   float = 0.0,
    ) -> None:
        self._ledger  = ledger
        self._decay   = decay_engine or TemporalDecayEngine()
        self._scorer  = scorer or TrustWeightedScorer()
        self._monitor = anomaly_monitor or RetrievalAnomalyMonitor()
        self._top_k   = top_k
        self._sim_fn  = similarity_fn or _keyword_similarity
        self._min_score = min_final_score
        self._stats: Dict[str, int] = {
            "total_queries": 0, "total_candidates": 0,
            "filtered": 0, "anomalies": 0,
        }

    def retrieve(
        self,
        query:          str,
        top_k:          Optional[int] = None,
        agent_id:       Optional[str] = None,
        min_base_score: float = 0.0,
    ) -> RetrievalResult:
        """
        Retrieve memory entries using trust-weighted ranking.

        Args:
            query:          Search query
            top_k:          Number of results (overrides default)
            agent_id:       Requesting agent (logged for audit)
            min_base_score: Pre-filter entries with base similarity below this

        Returns:
            RetrievalResult with ranked ScoredEntry list
        """
        t0 = time.perf_counter()
        k  = top_k or self._top_k
        self._stats["total_queries"] += 1

        # 1. Fetch all entries from ledger
        all_entries = self._ledger.get_range(0, None)
        self._stats["total_candidates"] += len(all_entries)

        scored:   List[ScoredEntry] = []
        filtered: int = 0
        anomalies_detected: int = 0

        # 2. Score each entry
        for entry in all_entries:
            metadata = dict(entry.metadata or {})
            # Inject timestamp from ledger if not already in metadata
            if "created_at" not in metadata and "timestamp" not in metadata:
                metadata["created_at"] = entry.timestamp
            elif "created_at" not in metadata:
                metadata["created_at"] = metadata.get("timestamp", entry.timestamp)

            # Base similarity score
            base = self._sim_fn(query, entry.content)
            if base < min_base_score:
                filtered += 1
                continue

            # Anomaly check + penalty
            trust_score = float(metadata.get("trust_score", 0.5))
            self._monitor.record(entry.entry_id, query, trust_score)
            self._monitor.check(entry.entry_id)
            penalty = self._monitor.penalty_for(entry.entry_id)
            if penalty > 0:
                anomalies_detected += 1

            # Trust-weighted score
            scored_entry, should_filter = self._scorer.score(
                entry_id        = entry.entry_id,
                content         = entry.content,
                base_score      = base,
                metadata        = metadata,
                decay_engine    = self._decay,
                anomaly_penalty = penalty,
            )

            if should_filter:
                filtered += 1
                self._stats["filtered"] += 1
                continue

            if scored_entry.final_score >= self._min_score:
                scored.append(scored_entry)

        # 3. Re-rank by final score
        scored.sort(key=lambda x: x.final_score, reverse=True)

        # 4. Update stats
        self._stats["anomalies"] += anomalies_detected

        ms = (time.perf_counter() - t0) * 1000

        return RetrievalResult(
            documents        = scored[:k],
            query            = query,
            total_candidates = len(all_entries),
            filtered_count   = filtered,
            anomaly_count    = anomalies_detected,
            retrieval_ms     = ms,
            retrieved_at     = _now(),
        )

    def explain(self, query: str, entry_id: str) -> str:
        """Return a human-readable score explanation for a single entry."""
        entry = self._ledger.get_entry(entry_id)
        if not entry:
            return f"Entry {entry_id} not found."
        metadata = dict(entry.metadata or {})
        if "created_at" not in metadata:
            metadata["created_at"] = entry.timestamp
        base = self._sim_fn(query, entry.content)
        penalty = self._monitor.penalty_for(entry_id)
        scored, filtered = self._scorer.score(
            entry_id=entry_id, content=entry.content,
            base_score=base, metadata=metadata,
            decay_engine=self._decay, anomaly_penalty=penalty,
        )
        lines = [
            f"Entry:     {entry_id}",
            f"Content:   {entry.content[:80]}",
            f"Base sim:  {base:.4f}  (query='{query[:40]}')",
            f"Trust:     {scored.trust_score:.3f}  (weight={scored.trust_weight:.3f})",
            f"Decay:     {scored.decay_factor:.3f}  (age={scored.age_days:.1f}d)",
            f"Anomaly:   penalty={scored.anomaly_penalty:.3f}",
            f"Filtered:  {scored.is_filtered}",
            f"Final:     {scored.final_score:.4f}",
            f"Detail:    {scored.explanation}",
        ]
        return "\n".join(lines)

    def anomaly_report(self) -> str:
        """Return anomaly monitor summary as formatted string."""
        s = self._monitor.summary()
        lines = [
            "Retrieval Anomaly Report",
            f"  Total events:    {s['total_events']}",
            f"  Unique entries:  {s['unique_entries']}",
            f"  Critical:        {s['critical']}",
            f"  High:            {s['high']}",
            "  By type:",
        ]
        for t, n in s.get("by_type", {}).items():
            lines.append(f"    {t}: {n}")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        return {**self._stats, "anomaly_summary": self._monitor.summary()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _keyword_similarity(query: str, content: str) -> float:
    """
    Lightweight keyword overlap similarity [0, 1].
    Used when no embedding function is provided.
    """
    if not query or not content:
        return 0.0
    stop = {"the", "a", "an", "is", "are", "was", "were", "in", "on",
            "at", "to", "for", "of", "and", "or", "it", "this", "that"}
    q_words = {w.lower().strip(".,;:!?") for w in query.split()} - stop
    c_words = {w.lower().strip(".,;:!?") for w in content.split()} - stop
    if not q_words:
        return 0.5
    overlap = len(q_words & c_words)
    # Jaccard-like with length normalization
    score = overlap / (len(q_words) + 0.5)
    return round(min(1.0, score), 4)


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse ISO timestamp string to timezone-aware datetime."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_retriever(
    ledger:           Any,
    half_life_days:   float = 30.0,
    decay_shape:      DecayShape = DecayShape.EXPONENTIAL,
    trust_weight:     float = 0.35,
    temporal_weight:  float = 0.20,
    filter_high_risk: bool = True,
    top_k:            int = 10,
    similarity_fn:    Optional[Callable[[str, str], float]] = None,
) -> SecureMemoryRetriever:
    """
    Create a SecureMemoryRetriever with sensible defaults.

    Usage::

        from memgar.secure_retriever import create_retriever
        from memgar.memory_ledger import MemoryLedger

        retriever = create_retriever(MemoryLedger("./memory.json"))
        results = retriever.retrieve("user preferences", top_k=5)
    """
    return SecureMemoryRetriever(
        ledger        = ledger,
        decay_engine  = TemporalDecayEngine(half_life_days=half_life_days, shape=decay_shape),
        scorer        = TrustWeightedScorer(
            trust_weight_factor    = trust_weight,
            temporal_weight_factor = temporal_weight,
            filter_high_risk       = filter_high_risk,
        ),
        anomaly_monitor = RetrievalAnomalyMonitor(),
        top_k           = top_k,
        similarity_fn   = similarity_fn,
    )
