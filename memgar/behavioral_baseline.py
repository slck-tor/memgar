"""
Memgar Behavioral Baseline Engine
===================================

Layer 4 of the Schneider defense architecture:
  behavioral monitoring with learned normal behavior and deviation detection.

Schneider (2026):
    "Behavioral baselines establish what normal agent behavior looks like
     for your use case. Deviations from baseline trigger alerts for human
     review. If an agent starts defending beliefs it should never have
     learned or taking actions inconsistent with its baseline behavior,
     you need the ability to immediately quarantine that agent."

The key distinction from circuit_breaker.py:
    circuit_breaker   = reactive threshold  (fires AFTER N threats)
    behavioral_baseline = deviation from learned normal  (fires when
                          behavior diverges from what was normal for THIS agent)

An agent processing 0 threats/hour baseline that suddenly sees 2 threats
is more suspicious than an agent processing 10 threats/hour that sees 12.
Absolute thresholds miss this. z-score deviation detection catches it.

Architecture:
    SignalObservation     - a single measured value at a point in time
    BaselineWindow        - rolling window of observations per signal
    EWMBaseline           - exponentially weighted mean/std per signal
    DeviationScore        - z-score based deviation for one signal
    BehaviorSnapshot      - point-in-time vector of all signal values
    BehavioralBaseline    - the full engine: learn + detect + respond
    BaselineIntegration   - hooks to feed observations from other modules
    DeviationReport       - human-readable deviation analysis

Usage::

    from memgar.behavioral_baseline import BehavioralBaseline, BaselineIntegration

    baseline = BehavioralBaseline(agent_id="agt_abc123")
    hooks = BaselineIntegration(baseline)

    # Feed observations automatically from existing modules
    hooks.on_scan(risk_score=15, decision="allow", threat_count=0)
    hooks.on_memory_write(trust_score=0.8, source_type="user_input", approved=True)
    hooks.on_retrieval(anomaly_count=0, filtered_count=1, avg_trust=0.7)
    hooks.on_token_event(event="issue", scope_denied=False)

    # Snapshot current behavior and compare to baseline
    report = baseline.check()
    if report.level == DeviationLevel.CRITICAL:
        circuit_breaker.force_trip()
        print(report.summary())
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeviationLevel(str, Enum):
    NORMAL     = "normal"      # within expected range
    ELEVATED   = "elevated"    # mild deviation, watch
    SUSPICIOUS = "suspicious"  # significant deviation, alert
    CRITICAL   = "critical"    # severe deviation, halt


class SignalCategory(str, Enum):
    THREAT      = "threat"       # scan/analysis signals
    MEMORY      = "memory"       # write/read patterns
    IDENTITY    = "identity"     # auth/token signals
    COST        = "cost"         # DoW / resource signals
    APPROVAL    = "approval"     # HITL signals
    RETRIEVAL   = "retrieval"    # retrieval patterns


# Thresholds: z-score at which each deviation level fires
_Z_THRESHOLDS = {
    DeviationLevel.ELEVATED:   2.0,
    DeviationLevel.SUSPICIOUS: 3.5,
    DeviationLevel.CRITICAL:   5.0,
}

# Minimum observations before baseline is considered stable
_MIN_STABLE_OBSERVATIONS = 10


# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------

@dataclass
class SignalSpec:
    """Definition of one behavioral signal."""
    name:        str
    category:    SignalCategory
    description: str
    unit:        str          # "per_minute", "ratio", "score", "count"
    higher_is_worse: bool     # True = higher values = more suspicious
    weight:      float = 1.0  # contribution to composite score


# All observable signals across the agent stack
SIGNAL_REGISTRY: Dict[str, SignalSpec] = {
    # Threat analysis signals
    "scan_risk_score":         SignalSpec("scan_risk_score",   SignalCategory.THREAT, "Average risk score per scan",                   "score",      True,  1.5),
    "scan_block_rate":         SignalSpec("scan_block_rate",   SignalCategory.THREAT, "Fraction of scans resulting in BLOCK decision",  "ratio",      True,  2.0),
    "threat_rate":             SignalSpec("threat_rate",       SignalCategory.THREAT, "Threat events per minute",                       "per_minute", True,  1.5),
    "unique_threat_types":     SignalSpec("unique_threat_types", SignalCategory.THREAT, "Distinct threat categories per window",         "count",      True,  1.0),

    # Memory write signals
    "write_rate":              SignalSpec("write_rate",        SignalCategory.MEMORY, "Memory writes per minute",                       "per_minute", False, 1.0),
    "write_avg_trust":         SignalSpec("write_avg_trust",   SignalCategory.MEMORY, "Average trust score of written entries",         "score",      False, 1.2),
    "write_reject_rate":       SignalSpec("write_reject_rate", SignalCategory.MEMORY, "Fraction of writes rejected by guardian",        "ratio",      True,  2.0),
    "write_low_trust_rate":    SignalSpec("write_low_trust_rate", SignalCategory.MEMORY, "Fraction of writes from low-trust sources",  "ratio",      True,  1.5),

    # Retrieval signals
    "retrieval_rate":          SignalSpec("retrieval_rate",    SignalCategory.RETRIEVAL, "Retrievals per minute",                       "per_minute", False, 0.8),
    "retrieval_anomaly_rate":  SignalSpec("retrieval_anomaly_rate", SignalCategory.RETRIEVAL, "Fraction of retrievals with anomalies", "ratio",      True,  2.0),
    "retrieval_filter_rate":   SignalSpec("retrieval_filter_rate",  SignalCategory.RETRIEVAL, "Fraction of candidates filtered",      "ratio",      True,  1.0),
    "retrieval_avg_trust":     SignalSpec("retrieval_avg_trust",     SignalCategory.RETRIEVAL, "Average trust of retrieved entries",   "score",      False, 1.0),

    # Identity / auth signals
    "token_issue_rate":        SignalSpec("token_issue_rate",  SignalCategory.IDENTITY, "Tokens issued per minute",                    "per_minute", False, 0.8),
    "scope_denial_rate":       SignalSpec("scope_denial_rate", SignalCategory.IDENTITY, "Fraction of scope checks that fail",          "ratio",      True,  2.5),
    "delegation_depth_avg":    SignalSpec("delegation_depth_avg", SignalCategory.IDENTITY, "Average delegation chain depth",           "score",      True,  1.5),

    # Cost / DoW signals
    "cost_rate":               SignalSpec("cost_rate",         SignalCategory.COST, "Estimated API cost per minute",                   "per_minute", True,  1.5),
    "token_usage_rate":        SignalSpec("token_usage_rate",  SignalCategory.COST, "Tokens consumed per minute",                      "per_minute", True,  1.2),

    # HITL / approval signals
    "approval_request_rate":   SignalSpec("approval_request_rate", SignalCategory.APPROVAL, "HITL approval requests per minute",      "per_minute", False, 0.8),
    "approval_denial_rate":    SignalSpec("approval_denial_rate",  SignalCategory.APPROVAL, "Fraction of HITL requests denied",       "ratio",      True,  2.0),
    "approval_timeout_rate":   SignalSpec("approval_timeout_rate", SignalCategory.APPROVAL, "Fraction of HITL requests that timeout", "ratio",      True,  1.5),
}


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

@dataclass
class SignalObservation:
    """A single measured value for one signal."""
    signal_name: str
    value:       float
    timestamp:   float = field(default_factory=time.time)
    metadata:    Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# EWM Baseline (per signal)
# ---------------------------------------------------------------------------

class EWMBaseline:
    """
    Exponentially Weighted Mean/Variance for a single signal.

    Uses Welford's online algorithm with exponential weighting:
    - Recent observations count more than old ones
    - Adapts to slow drift in normal behavior
    - Keeps rolling window of raw observations for z-score stability

    Args:
        alpha:       EWM smoothing factor (0 < alpha <= 1)
                     Higher = more weight on recent observations
        window_size: Max raw observations to keep for variance estimation
    """

    def __init__(self, alpha: float = 0.02, window_size: int = 200) -> None:
        self._alpha   = alpha
        self._window  = deque(maxlen=window_size)
        self._ewm     = 0.0
        self._ewv     = 0.0    # exponentially weighted variance
        self._n       = 0
        self._initialized = False

    def update(self, value: float) -> None:
        self._window.append(value)
        self._n += 1

        if not self._initialized:
            self._ewm = value
            self._ewv = 0.0
            self._initialized = True
            return

        diff       = value - self._ewm
        self._ewm  = self._ewm + self._alpha * diff
        self._ewv  = (1 - self._alpha) * (self._ewv + self._alpha * diff * diff)

    @property
    def mean(self) -> float:
        return self._ewm

    @property
    def std(self) -> float:
        return math.sqrt(max(0.0, self._ewv))

    @property
    def count(self) -> int:
        return self._n

    @property
    def is_stable(self) -> bool:
        return self._n >= _MIN_STABLE_OBSERVATIONS

    def z_score(self, value: float) -> float:
        """Z-score of value relative to learned normal. 0 if not stable."""
        if not self.is_stable:
            return 0.0
        s = self.std
        if s < 1e-9:
            # Near-zero variance: any nonzero difference = max deviation
            return 0.0 if abs(value - self._ewm) < 1e-9 else 10.0
        return abs(value - self._ewm) / s

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean":   round(self._ewm, 4),
            "std":    round(self.std, 4),
            "count":  self._n,
            "stable": self.is_stable,
        }


# ---------------------------------------------------------------------------
# Deviation score for one signal
# ---------------------------------------------------------------------------

@dataclass
class SignalDeviation:
    """Deviation analysis for a single signal."""
    signal_name:  str
    category:     SignalCategory
    observed:     float
    baseline_mean: float
    baseline_std:  float
    z_score:      float
    level:        DeviationLevel
    weight:       float
    weighted_z:   float     # z_score * weight
    direction:    str       # "above" / "below" / "normal"
    explanation:  str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal":         self.signal_name,
            "category":       self.category.value,
            "observed":       round(self.observed, 4),
            "baseline_mean":  round(self.baseline_mean, 4),
            "baseline_std":   round(self.baseline_std, 4),
            "z_score":        round(self.z_score, 2),
            "level":          self.level.value,
            "direction":      self.direction,
            "explanation":    self.explanation,
        }


# ---------------------------------------------------------------------------
# Behavior Snapshot
# ---------------------------------------------------------------------------

@dataclass
class BehaviorSnapshot:
    """Current values for all active signals."""
    agent_id:   str
    signals:    Dict[str, float]
    captured_at: float = field(default_factory=time.time)
    window_secs: float = 300.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id":    self.agent_id,
            "captured_at": _iso(self.captured_at),
            "window_secs": self.window_secs,
            "signals":     {k: round(v, 4) for k, v in self.signals.items()},
        }


# ---------------------------------------------------------------------------
# Deviation Report
# ---------------------------------------------------------------------------

@dataclass
class DeviationReport:
    """Full deviation analysis result."""
    agent_id:        str
    level:           DeviationLevel
    composite_score: float    # weighted sum of z-scores
    deviations:      List[SignalDeviation]
    baseline_stable: bool
    triggered_at:    str
    observation_window_secs: float

    @property
    def critical_signals(self) -> List[SignalDeviation]:
        return [d for d in self.deviations if d.level == DeviationLevel.CRITICAL]

    @property
    def suspicious_signals(self) -> List[SignalDeviation]:
        return [d for d in self.deviations if d.level in (DeviationLevel.SUSPICIOUS, DeviationLevel.CRITICAL)]

    def summary(self) -> str:
        lines = [
            f"Behavioral Deviation Report — Agent: {self.agent_id}",
            f"Level: {self.level.value.upper()}  Score: {self.composite_score:.2f}",
            f"Baseline stable: {self.baseline_stable}",
            f"Window: {self.observation_window_secs:.0f}s",
            "",
        ]
        if not self.deviations:
            lines.append("  No active signals.")
        else:
            for d in sorted(self.deviations, key=lambda x: x.z_score, reverse=True)[:8]:
                marker = {
                    DeviationLevel.CRITICAL:   "CRITICAL",
                    DeviationLevel.SUSPICIOUS: "SUSPICIOUS",
                    DeviationLevel.ELEVATED:   "ELEVATED",
                    DeviationLevel.NORMAL:     "ok",
                }[d.level]
                lines.append(f"  [{marker:<10}] {d.signal_name:<28} z={d.z_score:.2f}  obs={d.observed:.3f}  mean={d.baseline_mean:.3f}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id":               self.agent_id,
            "level":                  self.level.value,
            "composite_score":        round(self.composite_score, 3),
            "baseline_stable":        self.baseline_stable,
            "triggered_at":           self.triggered_at,
            "observation_window_secs": self.observation_window_secs,
            "critical_count":         len(self.critical_signals),
            "suspicious_count":       len(self.suspicious_signals),
            "deviations":             [d.to_dict() for d in self.deviations],
        }


# ---------------------------------------------------------------------------
# Behavioral Baseline Engine
# ---------------------------------------------------------------------------

class BehavioralBaseline:
    """
    Learns normal agent behavior and detects deviations.

    Maintains per-signal EWM baselines. On each check(), computes z-scores
    for all active signals and returns a DeviationReport.

    The composite_score is a weighted sum of z-scores. Weights are defined
    in SIGNAL_REGISTRY. Security-critical signals (scan_block_rate,
    scope_denial_rate, write_reject_rate) have higher weights.

    Args:
        agent_id:            Agent being monitored
        observation_window:  Seconds of recent data to aggregate for a snapshot
        alpha:               EWM smoothing factor (default: 0.05 = slow adaptation)
        on_deviation:        Callback(DeviationReport) on SUSPICIOUS or CRITICAL
        auto_trip_breaker:   CircuitBreaker to trip on CRITICAL (optional)
    """

    def __init__(
        self,
        agent_id:             str = "default",
        observation_window:   float = 300.0,
        alpha:                float = 0.02,
        on_deviation:         Optional[Callable[[DeviationReport], None]] = None,
        auto_trip_breaker:    Optional[Any] = None,
        forensics_path:       Optional[str] = None,
        retrain_interval_secs: float = 3600.0,
    ) -> None:
        self.agent_id    = agent_id
        self._window     = observation_window
        self._alpha      = alpha
        self._on_dev     = on_deviation
        self._breaker    = auto_trip_breaker

        # Per-signal EWM baselines
        self._baselines: Dict[str, EWMBaseline] = {
            name: EWMBaseline(alpha=alpha)
            for name in SIGNAL_REGISTRY
        }

        # Raw observation buffer: signal_name → deque[(ts, value)]
        self._obs: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))

        # Report history
        self._reports: deque = deque(maxlen=500)

        # Freeze flag: once True, new observations do NOT update EWM
        # This prevents attack observations from shifting the learned baseline
        self._frozen = False

        # Forensics auto-trigger: path to memory store scanned on CRITICAL
        self._forensics_path   = forensics_path
        self._last_forensics:  Optional[float] = None  # ts of last investigation
        self._forensics_cooldown = 300.0  # min seconds between auto-invocations

        # Retrain scheduler: drift with legitimate behavior change
        self._retrain_interval = retrain_interval_secs
        self._last_retrain:    float = time.time()

        # Stats
        self._check_count = 0
        self._alert_count = 0

    # ── Observation recording ───────────────────────────────────────────────

    def observe(self, signal_name: str, value: float, ts: Optional[float] = None) -> None:
        """
        Record a single signal observation.

        While the baseline is not yet stable, observations are used to learn
        the EWM mean/std. Once stable (frozen), observations are recorded for
        detection but do NOT update the EWM — preventing attack observations
        from shifting the learned normal behavior.

        Call retrain() to explicitly update the EWM with recent observations.
        """
        if signal_name not in SIGNAL_REGISTRY:
            return
        t = ts or time.time()
        self._obs[signal_name].append((t, value))
        bl = self._baselines[signal_name]
        # Auto-freeze once all active signals reach stability
        if not self._frozen:
            bl.update(value)
            # Check if we should freeze
            if bl.is_stable and self.is_stable():
                self._frozen = True

    def observe_many(self, observations: Dict[str, float]) -> None:
        for name, value in observations.items():
            self.observe(name, value)

    # ── Snapshot computation ────────────────────────────────────────────────

    def snapshot(self, detection_window: Optional[float] = None) -> BehaviorSnapshot:
        """Aggregate recent observations into current signal values.

        Uses a SHORT detection window (default: 20% of observation_window, min 30s)
        to capture rapid behavioral changes while the EWM baseline reflects
        long-term normal behavior.

        This separation prevents the "adapting baseline" problem where attack
        observations shift the mean, masking the deviation.
        """
        now = time.time()
        # Short detection window: captures recent behavior only
        detect_window = detection_window or max(30.0, self._window * 0.20)
        cutoff = now - detect_window
        signals: Dict[str, float] = {}

        for name, buf in self._obs.items():
            recent = [v for ts, v in buf if ts >= cutoff]
            if recent:
                signals[name] = sum(recent) / len(recent)

        return BehaviorSnapshot(
            agent_id    = self.agent_id,
            signals     = signals,
            captured_at = now,
            window_secs = detect_window,
        )

    # ── Deviation check ─────────────────────────────────────────────────────

    def check(self) -> DeviationReport:
        """
        Compute deviation from learned baseline for all active signals.

        Returns DeviationReport. If level is SUSPICIOUS or CRITICAL,
        fires on_deviation callback and optionally trips circuit breaker.
        """
        self._check_count += 1
        snap = self.snapshot()

        deviations: List[SignalDeviation] = []
        composite   = 0.0
        total_weight = 0.0
        any_stable   = False

        for name, value in snap.signals.items():
            spec     = SIGNAL_REGISTRY.get(name)
            bl       = self._baselines.get(name)
            if spec is None or bl is None:
                continue

            z   = bl.z_score(value)
            wz  = z * spec.weight

            # Determine deviation level
            level = DeviationLevel.NORMAL
            for lv in (DeviationLevel.CRITICAL, DeviationLevel.SUSPICIOUS, DeviationLevel.ELEVATED):
                if z >= _Z_THRESHOLDS[lv]:
                    level = lv
                    break

            direction = "normal"
            if bl.is_stable and z >= _Z_THRESHOLDS[DeviationLevel.ELEVATED]:
                if value > bl.mean:
                    direction = "above" if spec.higher_is_worse else "above_benign"
                else:
                    direction = "below" if not spec.higher_is_worse else "below_benign"

            explanation = (
                f"{name}: observed={value:.3f}"
                f" baseline={bl.mean:.3f}±{bl.std:.3f}"
                f" z={z:.2f}"
                + (f" [{level.value}]" if level != DeviationLevel.NORMAL else "")
            )

            dev = SignalDeviation(
                signal_name   = name,
                category      = spec.category,
                observed      = value,
                baseline_mean = bl.mean,
                baseline_std  = bl.std,
                z_score       = z,
                level         = level,
                weight        = spec.weight,
                weighted_z    = wz,
                direction     = direction,
                explanation   = explanation,
            )
            deviations.append(dev)

            if bl.is_stable:
                composite    += wz
                total_weight += spec.weight
                any_stable    = True

        # Normalize composite score
        if total_weight > 0:
            composite = composite / total_weight
        else:
            composite = 0.0

        # Overall level: driven by worst individual signal or composite
        worst_individual = max(
            (d.level for d in deviations),
            key=lambda l: list(DeviationLevel).index(l),
            default=DeviationLevel.NORMAL,
        )
        composite_level = DeviationLevel.NORMAL
        for lv in (DeviationLevel.CRITICAL, DeviationLevel.SUSPICIOUS, DeviationLevel.ELEVATED):
            if composite >= _Z_THRESHOLDS[lv]:
                composite_level = lv
                break

        # Take the worse of the two
        level_order = list(DeviationLevel)
        overall = max(worst_individual, composite_level,
                      key=lambda l: level_order.index(l))

        report = DeviationReport(
            agent_id                 = self.agent_id,
            level                    = overall,
            composite_score          = composite,
            deviations               = deviations,
            baseline_stable          = any_stable,
            triggered_at             = _iso(),
            observation_window_secs  = self._window,
        )
        self._reports.append(report)

        # Callbacks
        if overall in (DeviationLevel.SUSPICIOUS, DeviationLevel.CRITICAL):
            self._alert_count += 1
            if self._on_dev:
                try:
                    self._on_dev(report)
                except Exception:
                    pass

        if overall == DeviationLevel.CRITICAL and self._breaker is not None:
            try:
                self._breaker.force_trip()
            except Exception:
                pass

        # Forensics auto-trigger on CRITICAL
        # Schneider: "when an agent starts defending beliefs it should never have
        # learned, quarantine that agent" — start forensic investigation immediately.
        if overall == DeviationLevel.CRITICAL and self._forensics_path is not None:
            now_ts = time.time()
            if (self._last_forensics is None or
                    now_ts - self._last_forensics >= self._forensics_cooldown):
                self._last_forensics = now_ts
                self._trigger_forensics(report)

        # Retrain scheduler: periodically unfreeze baseline so it can
        # drift with legitimate behavioral change (new project, new user prefs).
        # Only runs when NOT in an attack — level must be NORMAL or ELEVATED.
        if overall in (DeviationLevel.NORMAL, DeviationLevel.ELEVATED):
            now_ts = time.time()
            if now_ts - self._last_retrain >= self._retrain_interval:
                self._last_retrain = now_ts
                self.retrain()
                logger.info(
                    "[Baseline] Scheduled retrain completed for agent=%s "
                    "(interval=%.0fs)",
                    self.agent_id, self._retrain_interval,
                )

        return report

    # ── Baseline management ──────────────────────────────────────────────────

    def reset(self, signal_name: Optional[str] = None) -> None:
        """Reset baseline for one signal or all signals. Also unfreezes baseline."""
        if signal_name:
            if signal_name in self._baselines:
                self._baselines[signal_name] = EWMBaseline(alpha=self._alpha)
                self._obs[signal_name].clear()
        else:
            for name in SIGNAL_REGISTRY:
                self._baselines[name] = EWMBaseline(alpha=self._alpha)
                self._obs[name].clear()
            self._frozen = False

    def baseline_state(self) -> Dict[str, Any]:
        """Return current baseline statistics for all signals."""
        return {
            name: bl.to_dict()
            for name, bl in self._baselines.items()
            if bl.count > 0
        }

    def _trigger_forensics(self, report: "DeviationReport") -> None:
        """
        Auto-trigger memory forensics investigation on CRITICAL deviation.

        Loads MemoryForensicsEngine from memgar.forensics and scans the
        configured forensics_path. The report is attached as context.

        Runs in a daemon thread to avoid blocking check().
        """
        import threading

        def _run() -> None:
            try:
                import importlib.util, os
                forensics_file = os.path.join(
                    os.path.dirname(__file__), "forensics"
                )
                spec = importlib.util.spec_from_file_location(
                    "memgar.forensics", forensics_file
                )
                if spec is None or spec.loader is None:
                    logger.warning("[Baseline] forensics module not loadable")
                    return
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                engine = mod.MemoryForensicsEngine()
                forensic_report = engine.scan(
                    path  = self._forensics_path,
                    clean = False,
                )
                logger.critical(
                    "[Baseline→Forensics] CRITICAL deviation triggered auto-investigation "
                    "| agent=%s | composite=%.2f | compromised=%s | entries=%d",
                    self.agent_id,
                    report.composite_score,
                    forensic_report.is_compromised,
                    forensic_report.total_entries,
                )
                if forensic_report.is_compromised:
                    logger.critical(
                        "[Baseline→Forensics] %d poisoned entries found "
                        "(%.1f%% compromise rate) in %s",
                        forensic_report.poisoned_count,
                        forensic_report.compromise_rate * 100,
                        self._forensics_path,
                    )
            except Exception as exc:
                logger.warning(
                    "[Baseline→Forensics] auto-investigation failed: %s", exc
                )

        t = threading.Thread(target=_run, daemon=True, name=f"memgar-forensics-{self.agent_id}")
        t.start()

    def retrain(self, window_fraction: float = 1.0) -> int:
        """
        Update EWM baselines using recent observations.

        Call periodically (e.g., hourly) to let baselines drift with
        legitimate behavioral changes. Does NOT auto-run — explicit call only.

        Args:
            window_fraction: Fraction of observation_window to use (default: all)

        Returns:
            Number of signals updated
        """
        now    = time.time()
        cutoff = now - self._window * window_fraction
        updated = 0
        for name, buf in self._obs.items():
            recent = [v for ts, v in buf if ts >= cutoff]
            if recent:
                for v in recent[-20:]:  # at most 20 most recent
                    self._baselines[name].update(v)
                updated += 1
        self._frozen = self.is_stable()
        return updated

    def is_stable(self) -> bool:
        """True if at least half the active signals have stable baselines."""
        active = [bl for bl in self._baselines.values() if bl.count > 0]
        if not active:
            return False
        stable = sum(1 for bl in active if bl.is_stable)
        return stable >= len(active) // 2

    def stats(self) -> Dict[str, Any]:
        stable_signals = sum(1 for bl in self._baselines.values() if bl.is_stable)
        return {
            "agent_id":       self.agent_id,
            "checks":         self._check_count,
            "alerts":         self._alert_count,
            "stable_signals": stable_signals,
            "total_signals":  len(SIGNAL_REGISTRY),
            "is_stable":      self.is_stable(),
            "frozen":         self._frozen,
        }

    def recent_reports(self, n: int = 10) -> List[DeviationReport]:
        return list(self._reports)[-n:]


# ---------------------------------------------------------------------------
# Baseline Integration Hooks
# ---------------------------------------------------------------------------

class BaselineIntegration:
    """
    Feeds behavioral observations from all Memgar modules into the baseline.

    Attach to module callbacks or call manually after each operation.

    Usage::

        baseline = BehavioralBaseline(agent_id="agt_abc")
        hooks = BaselineIntegration(baseline)

        # After a scan
        hooks.on_scan(risk_score=25, decision="block", threat_count=1)

        # After a memory write
        hooks.on_memory_write(trust_score=0.8, source_type="email", approved=True)

        # After retrieval
        hooks.on_retrieval(anomaly_count=0, filtered_count=1, avg_trust=0.75)

        # After identity event
        hooks.on_token_event("issue", scope_denied=False, delegation_depth=0)

        # After HITL event
        hooks.on_hitl("approved", timed_out=False)

        # Check current state
        report = hooks.check()
    """

    def __init__(self, baseline: BehavioralBaseline) -> None:
        self._b = baseline

    def on_scan(
        self,
        risk_score:    int,
        decision:      str,
        threat_count:  int,
        threat_ids:    Optional[List[str]] = None,
    ) -> None:
        self._b.observe("scan_risk_score",     float(risk_score))
        self._b.observe("scan_block_rate",     1.0 if decision == "block" else 0.0)
        self._b.observe("threat_rate",         float(threat_count))
        self._b.observe("unique_threat_types", float(len(set(threat_ids or []))))

    def on_memory_write(
        self,
        trust_score:  float,
        source_type:  str,
        approved:     bool,
        rejected:     bool = False,
    ) -> None:
        _SOURCE_TRUST_MAP = {
            "system": 0.95, "user_input": 0.70, "email": 0.40,
            "webpage": 0.25, "unknown": 0.20,
        }
        self._b.observe("write_rate",           1.0)  # one write event
        self._b.observe("write_avg_trust",      trust_score)
        self._b.observe("write_reject_rate",    1.0 if rejected else 0.0)
        low_trust = 1.0 if trust_score < 0.4 else 0.0
        self._b.observe("write_low_trust_rate", low_trust)

    def on_retrieval(
        self,
        anomaly_count:   int,
        filtered_count:  int,
        avg_trust:       float,
        total_candidates: int = 1,
    ) -> None:
        self._b.observe("retrieval_rate",         1.0)
        denom = max(1, total_candidates)
        self._b.observe("retrieval_anomaly_rate", float(anomaly_count) / denom)
        self._b.observe("retrieval_filter_rate",  float(filtered_count) / denom)
        self._b.observe("retrieval_avg_trust",    avg_trust)

    def on_token_event(
        self,
        event:            str,        # "issue" / "verify" / "revoke" / "deny"
        scope_denied:     bool = False,
        delegation_depth: int = 0,
    ) -> None:
        if event == "issue":
            self._b.observe("token_issue_rate", 1.0)
        self._b.observe("scope_denial_rate",    1.0 if scope_denied else 0.0)
        self._b.observe("delegation_depth_avg", float(delegation_depth))

    def on_cost_event(
        self,
        cost_delta:      float,
        tokens_consumed: int = 0,
    ) -> None:
        self._b.observe("cost_rate",        cost_delta)
        self._b.observe("token_usage_rate", float(tokens_consumed))

    def on_hitl(
        self,
        outcome:   str,    # "approved" / "denied" / "timeout" / "requested"
        timed_out: bool = False,
    ) -> None:
        self._b.observe("approval_request_rate", 1.0 if outcome == "requested" else 0.0)
        self._b.observe("approval_denial_rate",  1.0 if outcome == "denied"    else 0.0)
        self._b.observe("approval_timeout_rate", 1.0 if timed_out              else 0.0)

    def check(self) -> DeviationReport:
        """Convenience: delegate to baseline.check()."""
        return self._b.check()

    def observe(self, signal_name: str, value: float) -> None:
        """Direct observation for custom signals."""
        self._b.observe(signal_name, value)


# ---------------------------------------------------------------------------
# Multi-agent baseline registry
# ---------------------------------------------------------------------------

class BaselineRegistry:
    """
    Manages baselines for a fleet of agents.

    Each agent gets its own learned baseline — deviations are
    agent-relative, not fleet-absolute.

    Usage::

        registry = BaselineRegistry()
        registry.get_or_create("agt_abc").observe("scan_risk_score", 12.0)
        report = registry.check_all()
    """

    def __init__(self, **baseline_kwargs) -> None:
        self._kwargs  = baseline_kwargs
        self._agents: Dict[str, BehavioralBaseline] = {}

    def get_or_create(self, agent_id: str) -> BehavioralBaseline:
        if agent_id not in self._agents:
            self._agents[agent_id] = BehavioralBaseline(
                agent_id=agent_id, **self._kwargs
            )
        return self._agents[agent_id]

    def check_all(self) -> Dict[str, DeviationReport]:
        return {aid: bl.check() for aid, bl in self._agents.items()}

    def critical_agents(self) -> List[str]:
        reports = self.check_all()
        return [
            aid for aid, r in reports.items()
            if r.level == DeviationLevel.CRITICAL
        ]

    def fleet_summary(self) -> Dict[str, Any]:
        reports = self.check_all()
        level_counts: Dict[str, int] = defaultdict(int)
        for r in reports.values():
            level_counts[r.level.value] += 1
        return {
            "total_agents": len(self._agents),
            "level_counts": dict(level_counts),
            "critical":     level_counts.get("critical", 0),
            "suspicious":   level_counts.get("suspicious", 0),
        }

    def all_agents(self) -> List[str]:
        return list(self._agents.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(ts: Optional[float] = None) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(tz=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_baseline(
    agent_id:              str = "default",
    observation_window:    float = 300.0,
    alpha:                 float = 0.02,
    auto_trip_breaker:     Optional[Any] = None,
    on_deviation:          Optional[Callable[[DeviationReport], None]] = None,
    forensics_path:        Optional[str] = None,
    retrain_interval_secs: float = 3600.0,
) -> Tuple[BehavioralBaseline, BaselineIntegration]:
    """
    Create a BehavioralBaseline and its integration hooks.

    Returns:
        (baseline, hooks)

    Usage::

        baseline, hooks = create_baseline(agent_id="agt_abc")
        hooks.on_scan(risk_score=10, decision="allow", threat_count=0)
        report = hooks.check()
    """
    bl = BehavioralBaseline(
        agent_id              = agent_id,
        observation_window    = observation_window,
        alpha                 = alpha,
        auto_trip_breaker     = auto_trip_breaker,
        on_deviation          = on_deviation,
        forensics_path        = forensics_path,
        retrain_interval_secs = retrain_interval_secs,
    )
    return bl, BaselineIntegration(bl)
