"""
Memgar Observability
====================

Opt-in Prometheus metrics server and production drift detection.

Usage:
    import memgar
    memgar.start_metrics_server(port=9090)

    # Then scrape http://localhost:9090/metrics

Metrics exposed:
    memgar_analyses_total{decision}     Counter
    memgar_analysis_latency_seconds     Histogram
    memgar_risk_score                   Histogram
    memgar_drift_severity               Gauge  (0=none → 4=critical)
    memgar_model_version{version}       Gauge  (info)

Requires: pip install 'memgar[observability]'
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_started = False
_start_lock = threading.Lock()
_drift_monitor: Optional["DriftMonitor"] = None  # type: ignore[name-defined]


def start_metrics_server(
    port: int = 9090,
    psi_threshold: float = 0.20,
    window_size: int = 1000,
) -> None:
    """Start the Prometheus /metrics HTTP server on *port* (idempotent).

    Raises ImportError if prometheus_client is not installed.
    """
    global _started, _drift_monitor

    with _start_lock:
        if _started:
            logger.debug("Metrics server already running — ignoring duplicate call")
            return

        try:
            import prometheus_client
        except ImportError as exc:
            raise ImportError(
                "Observability requires prometheus_client. "
                "Install with: pip install 'memgar[observability]'"
            ) from exc

        from memgar.observability.metrics import get_metrics_registry, init_metrics

        init_metrics()
        registry = get_metrics_registry()
        prometheus_client.start_http_server(port, registry=registry)

        # Stamp the model version info metric.
        try:
            from memgar import __version__ as _app_version
            from memgar.observability.metrics import MODEL_VERSION_INFO
            if MODEL_VERSION_INFO is not None:
                MODEL_VERSION_INFO.labels(version=_app_version).set(1)
        except Exception:
            pass

        # Start drift monitor background thread using config-supplied thresholds.
        from memgar.observability.drift_monitor import DriftMonitor

        _drift_monitor = DriftMonitor(window_size=window_size, psi_threshold=psi_threshold)
        t = threading.Thread(target=_drift_monitor.run_background, daemon=True, name="memgar-drift-monitor")
        t.start()

        _started = True
        logger.info("Memgar metrics server started on port %d", port)


def get_metrics_registry() -> "Any":  # type: ignore[name-defined]
    from memgar.observability.metrics import get_metrics_registry as _get
    return _get()


from typing import Any  # noqa: E402

from memgar.observability.drift_monitor import DriftMonitor  # noqa: E402, F401
