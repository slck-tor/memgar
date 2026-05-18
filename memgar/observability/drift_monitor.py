"""
Production drift monitor.

Tracks the rolling distribution of risk scores and computes the
Population Stability Index (PSI) to detect when the score distribution
shifts — a signal that an adversary is probing the system or that the
model has decayed.

Designed to run as an opt-in background daemon thread started alongside
the Prometheus metrics server.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from memgar.siem import SIEMRouter

logger = logging.getLogger(__name__)

_SCORE_BINS = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
_PSI_EPS = 1e-4

# PSI thresholds → severity level
_PSI_LEVELS = [
    (0.25, 4),  # critical
    (0.20, 3),  # high
    (0.15, 2),  # medium
    (0.10, 1),  # low
    (0.00, 0),  # none
]


def _psi(baseline: List[float], current: List[float]) -> float:
    """Compute Population Stability Index between two distributions."""
    value = 0.0
    for b, c in zip(baseline, current):
        b = max(b, _PSI_EPS)
        c = max(c, _PSI_EPS)
        value += (c - b) * math.log(c / b)
    return value


def _normalize_hist(scores: List[int]) -> List[float]:
    """Bin scores into _SCORE_BINS and return a normalized probability vector."""
    n = len(scores)
    if n == 0:
        return [1.0 / (len(_SCORE_BINS) - 1)] * (len(_SCORE_BINS) - 1)
    counts = [0] * (len(_SCORE_BINS) - 1)
    for s in scores:
        s = max(0, min(100, s))
        bin_idx = min(s // 10, len(counts) - 1)
        counts[bin_idx] += 1
    return [c / n for c in counts]


class DriftMonitor:
    """Background PSI drift detector with optional SIEM alert emission."""

    def __init__(
        self,
        window_size: int = 1000,
        psi_threshold: float = 0.20,
        check_interval_s: float = 60.0,
        siem_router: Optional["SIEMRouter"] = None,
    ) -> None:
        self._window_size = window_size
        self._psi_threshold = psi_threshold
        self._check_interval = check_interval_s
        self._siem_router = siem_router

        # Rolling buffer: 2× window so we always have baseline + current halves.
        self._buffer: deque = deque(maxlen=window_size * 2)
        self._lock = threading.Lock()
        self._last_check_count = 0
        self._last_psi = 0.0

    def record_score(self, risk_score: int) -> None:
        """Thread-safe score ingestion. Triggers PSI check when window fills."""
        with self._lock:
            self._buffer.append(int(risk_score))
            total = len(self._buffer)

        # Check every window_size new observations.
        if total >= self._window_size * 2 and (total - self._last_check_count) >= self._window_size:
            self._last_check_count = total
            self._check_psi()

    def set_baseline(self, scores: List[int]) -> None:
        """Pre-populate the baseline half of the buffer."""
        with self._lock:
            self._buffer.clear()
            for s in scores[-self._window_size:]:
                self._buffer.append(s)

    def _check_psi(self) -> float:
        with self._lock:
            buf = list(self._buffer)

        half = len(buf) // 2
        if half < 10:
            return 0.0

        baseline_scores = buf[:half]
        current_scores = buf[half:]

        baseline_hist = _normalize_hist(baseline_scores)
        current_hist = _normalize_hist(current_scores)
        psi_value = _psi(baseline_hist, current_hist)
        self._last_psi = psi_value

        severity = 0
        for threshold, level in _PSI_LEVELS:
            if psi_value >= threshold:
                severity = level
                break

        # Update Prometheus gauge (non-fatal).
        try:
            from memgar.observability.metrics import DRIFT_SEVERITY_GAUGE
            if DRIFT_SEVERITY_GAUGE is not None:
                DRIFT_SEVERITY_GAUGE.set(severity)
        except Exception:
            pass

        if psi_value >= self._psi_threshold and self._siem_router is not None:
            try:
                self._siem_router.emit_drift_alert(
                    psi=psi_value,
                    severity_level=severity,
                    window_size=len(current_scores),
                    threshold=self._psi_threshold,
                )
            except Exception as exc:
                logger.debug("SIEM drift alert failed: %s", exc)

        if severity >= 2:
            logger.warning(
                "Score distribution drift detected: PSI=%.4f severity=%d (threshold=%.2f)",
                psi_value, severity, self._psi_threshold,
            )
        return psi_value

    def run_background(self) -> None:
        """Heartbeat loop — run in a daemon thread."""
        logger.debug("DriftMonitor background thread started (interval=%ss)", self._check_interval)
        while True:
            time.sleep(self._check_interval)
            try:
                self._check_psi()
            except Exception as exc:
                logger.debug("DriftMonitor heartbeat error: %s", exc)
