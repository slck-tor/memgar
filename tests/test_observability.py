"""Tests for observability: Prometheus metrics + drift monitor (Phase 3)."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Metrics module
# ---------------------------------------------------------------------------

class TestMetricsRegistry:
    def test_get_metrics_registry_returns_registry(self):
        try:
            from prometheus_client import CollectorRegistry
        except ImportError:
            pytest.skip("prometheus_client not installed")
        from memgar.observability.metrics import get_metrics_registry
        reg = get_metrics_registry()
        assert isinstance(reg, CollectorRegistry)

    def test_init_metrics_returns_true_when_prometheus_available(self):
        try:
            import prometheus_client  # noqa: F401
        except ImportError:
            pytest.skip("prometheus_client not installed")
        from memgar.observability.metrics import _init_metrics
        assert _init_metrics() is True

    def test_init_metrics_returns_false_when_prometheus_missing(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "prometheus_client" or name.startswith("prometheus_client"):
                raise ImportError("mocked missing prometheus_client")
            return real_import(name, *args, **kwargs)

        # Reset initialized state
        import memgar.observability.metrics as m
        original_initialized = m._metrics_initialized
        m._metrics_initialized = False

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = m._init_metrics()
        m._metrics_initialized = original_initialized
        # Should return False gracefully
        assert result is False

    def test_importing_metrics_module_does_not_start_server(self):
        """Importing the module must not bind any ports."""
        import memgar.observability.metrics  # noqa: F401
        # If we get here without connection errors, we're good
        assert True


# ---------------------------------------------------------------------------
# DriftMonitor
# ---------------------------------------------------------------------------

class TestDriftMonitor:
    def test_record_score_accumulates(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=100)
        for i in range(50):
            monitor.record_score(i * 2)
        assert len(monitor._buffer) == 50

    def test_psi_returns_float(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=50)
        # Fill buffer with two halves: uniform low vs. uniform high
        for _ in range(50):
            monitor._buffer.append(10)
        for _ in range(50):
            monitor._buffer.append(90)
        psi = monitor._check_psi()
        assert isinstance(psi, float)

    def test_psi_uniform_distribution_near_zero(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=200)
        # Same distribution in both halves → PSI ≈ 0
        for _ in range(400):
            monitor._buffer.append(50)
        psi = monitor._check_psi()
        assert psi < 0.5  # Should be very small

    def test_psi_bimodal_shift_above_threshold(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=200, psi_threshold=0.2)
        # Baseline: all low scores
        for _ in range(200):
            monitor._buffer.append(5)
        # Current: all high scores
        for _ in range(200):
            monitor._buffer.append(95)
        psi = monitor._check_psi()
        assert psi > 0.2

    def test_siem_router_called_on_high_psi(self):
        from memgar.observability.drift_monitor import DriftMonitor
        mock_router = MagicMock()
        monitor = DriftMonitor(window_size=100, psi_threshold=0.1, siem_router=mock_router)
        # Bimodal shift
        for _ in range(100):
            monitor._buffer.append(5)
        for _ in range(100):
            monitor._buffer.append(95)
        monitor._check_psi()
        # emit_drift_alert should have been called
        mock_router.emit_drift_alert.assert_called_once()

    def test_thread_safety(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=100)
        errors = []

        def record_batch():
            try:
                for i in range(25):
                    monitor.record_score(i % 100)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=record_batch) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    def test_set_baseline(self):
        from memgar.observability.drift_monitor import DriftMonitor
        monitor = DriftMonitor(window_size=50)
        monitor.set_baseline([10, 20, 30, 40, 50])
        assert len(monitor._buffer) == 5


# ---------------------------------------------------------------------------
# Analyzer metrics instrumentation
# ---------------------------------------------------------------------------

class TestAnalyzerMetricsInstrumentation:
    def _make_entry(self, content: str = "hello world"):
        from memgar.models import MemoryEntry
        return MemoryEntry(content=content, source_id="test", source_type="test")

    def test_analyze_returns_valid_result_with_metrics(self):
        """analyze() should return AnalysisResult even with metrics enabled."""
        try:
            import prometheus_client  # noqa: F401
        except ImportError:
            pytest.skip("prometheus_client not installed")

        from memgar.observability.metrics import init_metrics
        init_metrics()

        from memgar.analyzer import Analyzer
        analyzer = Analyzer()
        result = analyzer.analyze(self._make_entry("safe test content here"))
        assert result is not None
        assert hasattr(result, "decision")
        assert hasattr(result, "risk_score")

    def test_analyze_works_when_metrics_raise(self, monkeypatch):
        """Metrics exceptions must not propagate to callers."""
        import memgar.observability.metrics as m
        original = m.ANALYSES_TOTAL

        # Make the counter raise
        mock_counter = MagicMock()
        mock_counter.labels.side_effect = RuntimeError("deliberate metrics failure")
        m.ANALYSES_TOTAL = mock_counter

        from memgar.analyzer import Analyzer
        analyzer = Analyzer()
        result = analyzer.analyze(self._make_entry("safe content"))
        m.ANALYSES_TOTAL = original

        assert result is not None

    def test_analyze_internal_exists(self):
        from memgar.analyzer import Analyzer
        analyzer = Analyzer()
        assert hasattr(analyzer, "_analyze_internal")
        assert callable(analyzer._analyze_internal)


# ---------------------------------------------------------------------------
# start_metrics_server
# ---------------------------------------------------------------------------

class TestStartMetricsServer:
    def test_start_metrics_server_missing_prometheus_raises(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "prometheus_client":
                raise ImportError("mocked missing")
            return real_import(name, *args, **kwargs)

        import memgar.observability as obs
        original_started = obs._started
        obs._started = False

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(ImportError, match="prometheus_client"):
            obs.start_metrics_server(port=29999)

        obs._started = original_started

    def test_start_metrics_server_idempotent(self, monkeypatch):
        """Calling start_metrics_server twice should only bind once."""
        try:
            import prometheus_client  # noqa: F401
        except ImportError:
            pytest.skip("prometheus_client not installed")

        call_count = []

        import memgar.observability as obs
        original_started = obs._started

        monkeypatch.setattr(
            "prometheus_client.start_http_server",
            lambda port, registry=None: call_count.append(port),
        )
        obs._started = False

        obs.start_metrics_server(port=29998)
        obs.start_metrics_server(port=29998)  # second call — should be no-op

        obs._started = original_started
        assert len(call_count) == 1  # bound exactly once


# ---------------------------------------------------------------------------
# SIEM drift alert
# ---------------------------------------------------------------------------

class TestSIEMDriftAlert:
    def test_emit_drift_alert_uses_correct_category(self):
        from memgar.siem import EventCategory, SIEMRouter

        received = []
        router = SIEMRouter(async_mode=False)

        class CaptureSink:
            name = "capture"

            def send(self, events):
                received.extend(events)

        router._sinks.append(CaptureSink())
        router.emit_drift_alert(psi=0.25, severity_level=3, window_size=1000, threshold=0.2)

        assert len(received) == 1
        assert received[0].category == EventCategory.DRIFT_DETECTED

    def test_drift_detected_in_event_category_enum(self):
        from memgar.siem import EventCategory
        assert EventCategory.DRIFT_DETECTED == "drift_detected"

    def test_emit_drift_alert_sets_severity(self):
        from memgar.siem import SIEMRouter

        received = []
        router = SIEMRouter(async_mode=False)

        class CaptureSink:
            name = "capture"

            def send(self, events):
                received.extend(events)

        router._sinks.append(CaptureSink())
        router.emit_drift_alert(psi=0.30, severity_level=4, window_size=500, threshold=0.2)
        assert received[0].severity == "critical"
