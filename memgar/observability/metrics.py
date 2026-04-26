"""
Prometheus metric definitions for memgar.

All objects are initialized lazily — importing this module does NOT start a
metrics server and does NOT fail if prometheus_client is absent.  Callers
guard with `if metric is not None:` before recording.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_registry: Optional[Any] = None
_metrics_initialized = False

# Module-level references — set to None until _init_metrics() is called.
ANALYSES_TOTAL: Optional[Any] = None
ANALYSIS_LATENCY: Optional[Any] = None
RISK_SCORE_HISTOGRAM: Optional[Any] = None
DRIFT_SEVERITY_GAUGE: Optional[Any] = None
MODEL_VERSION_INFO: Optional[Any] = None


def get_metrics_registry() -> Any:
    global _registry
    if _registry is None:
        from prometheus_client import CollectorRegistry
        _registry = CollectorRegistry()
    return _registry


def _init_metrics() -> bool:
    """Create Prometheus metric objects. Returns True on success."""
    global _metrics_initialized
    global ANALYSES_TOTAL, ANALYSIS_LATENCY, RISK_SCORE_HISTOGRAM
    global DRIFT_SEVERITY_GAUGE, MODEL_VERSION_INFO

    if _metrics_initialized:
        return True
    try:
        from prometheus_client import Counter, Gauge, Histogram

        reg = get_metrics_registry()

        ANALYSES_TOTAL = Counter(
            "memgar_analyses_total",
            "Total number of content analyses performed",
            ["decision"],
            registry=reg,
        )
        ANALYSIS_LATENCY = Histogram(
            "memgar_analysis_latency_seconds",
            "Analysis latency in seconds",
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5],
            registry=reg,
        )
        RISK_SCORE_HISTOGRAM = Histogram(
            "memgar_risk_score",
            "Distribution of risk scores (0-100)",
            buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
            registry=reg,
        )
        DRIFT_SEVERITY_GAUGE = Gauge(
            "memgar_drift_severity",
            "Current score-distribution drift severity (0=none … 4=critical)",
            registry=reg,
        )
        MODEL_VERSION_INFO = Gauge(
            "memgar_model_version",
            "ML model version currently in use (info metric, always 1)",
            ["version"],
            registry=reg,
        )
        _metrics_initialized = True
        return True
    except ImportError:
        logger.debug(
            "prometheus_client not installed — metrics disabled. "
            "Enable with: pip install 'memgar[observability]'"
        )
        return False
    except Exception as exc:
        logger.debug("Failed to initialize Prometheus metrics: %s", exc)
        return False


def init_metrics() -> bool:
    """Public entry-point; call once from start_metrics_server()."""
    return _init_metrics()
