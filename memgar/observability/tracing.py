"""OpenTelemetry distributed tracing for Memgar.

Provides a tracer that instruments each analysis layer as a child span under a
parent ``memgar.analyze`` span.  When ``opentelemetry-sdk`` is not installed
every call silently degrades to no-ops so the rest of the codebase never needs
try/except guards around tracer calls.

Usage
-----
    # Configure once at startup (optional — skip if you manage the provider yourself)
    from memgar.observability.tracing import configure_tracing
    configure_tracing(otlp_endpoint="http://localhost:4317")

    # That's it.  Analyzer spans are emitted automatically.

Requires: pip install 'memgar[tracing]'
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional OTel import
# ---------------------------------------------------------------------------
_OTEL_AVAILABLE = False

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import (
        NonRecordingSpan,
        SpanKind,
        StatusCode,
    )
    _OTEL_AVAILABLE = True
except ImportError:
    _otel_trace = None  # type: ignore[assignment]
    SpanKind = None  # type: ignore[assignment,misc]
    StatusCode = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# No-op fallbacks (used when OTel not installed)
# ---------------------------------------------------------------------------

class _NoOpSpan:
    """Minimal span interface that discards everything."""

    def set_attribute(self, key: str, value: Any) -> "_NoOpSpan":
        return self

    def record_exception(self, exc: Exception, **kwargs: Any) -> None:
        pass

    def set_status(self, status: Any, description: str = "") -> None:
        pass

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


@contextlib.contextmanager
def _noop_span_context(name: str, **kwargs: Any) -> Iterator[_NoOpSpan]:
    yield _NoOpSpan()


class _NoOpTracer:
    """Drop-in tracer when OTel SDK is absent."""

    def start_as_current_span(
        self,
        name: str,
        kind: Any = None,
        attributes: Any = None,
        **kwargs: Any,
    ) -> Any:
        return _noop_span_context(name)

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()


# ---------------------------------------------------------------------------
# Tracer accessor
# ---------------------------------------------------------------------------
_SERVICE_NAME = "memgar"
_tracer: Optional[Any] = None
# Module-level provider — set by configure_tracing() or tests.
# When None, falls back to the OTel global registry.
_provider: Optional[Any] = None


def get_tracer(name: str = "memgar") -> Any:
    """Return the active OTel tracer or a no-op tracer if OTel is not installed."""
    global _tracer
    if _tracer is not None:
        return _tracer
    if _OTEL_AVAILABLE and _otel_trace is not None:
        if _provider is not None:
            # Use the module-local provider (set by configure_tracing or test fixture)
            # so we never fight with the global OTel registry in tests.
            _tracer = _provider.get_tracer(
                name,
                schema_url="https://opentelemetry.io/schemas/1.22.0",
            )
        else:
            _tracer = _otel_trace.get_tracer(
                name,
                schema_url="https://opentelemetry.io/schemas/1.22.0",
            )
        return _tracer
    _tracer = _NoOpTracer()
    return _tracer


def _reset_tracer() -> None:
    """Reset cached tracer (and optionally the provider) — test helper only."""
    global _tracer
    _tracer = None


# ---------------------------------------------------------------------------
# One-call setup for common exporters
# ---------------------------------------------------------------------------

def configure_tracing(
    *,
    service_name: str = "memgar",
    otlp_endpoint: Optional[str] = None,
    jaeger_host: Optional[str] = None,
    jaeger_port: int = 6831,
    exporter: Optional[Any] = None,
    sample_rate: float = 1.0,
) -> None:
    """Configure the global OTel tracer provider.

    Call once at startup before the first ``analyze()`` call.  All subsequent
    spans will flow to the configured exporter.

    Args:
        service_name:   Service name tag in exported spans.
        otlp_endpoint:  gRPC OTLP collector URL (e.g. ``http://localhost:4317``).
        jaeger_host:    Jaeger UDP agent hostname.
        jaeger_port:    Jaeger UDP agent port (default 6831).
        exporter:       Bring-your-own SpanExporter instance.
        sample_rate:    Fraction of traces to sample (0.0–1.0, default 1.0).

    Raises:
        ImportError: If ``opentelemetry-sdk`` is not installed.
    """
    global _SERVICE_NAME, _tracer

    if not _OTEL_AVAILABLE or _otel_trace is None:
        raise ImportError(
            "OpenTelemetry is required for tracing. "
            "Install with: pip install 'memgar[tracing]'"
        )

    try:
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased, ALWAYS_ON
    except ImportError as exc:
        raise ImportError(
            "opentelemetry-sdk is required. "
            "Install with: pip install 'memgar[tracing]'"
        ) from exc

    global _provider, _SERVICE_NAME, _tracer

    _SERVICE_NAME = service_name
    resource = Resource.create({SERVICE_NAME: service_name})
    sampler = ALWAYS_ON if sample_rate >= 1.0 else TraceIdRatioBased(sample_rate)
    new_provider = TracerProvider(resource=resource, sampler=sampler)

    # Resolve exporter
    _exporter = exporter
    if _exporter is None and otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            _exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        except ImportError as exc:
            raise ImportError(
                "OTLP exporter requires opentelemetry-exporter-otlp-proto-grpc. "
                "Install with: pip install opentelemetry-exporter-otlp-proto-grpc"
            ) from exc

    if _exporter is None and jaeger_host:
        try:
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter
            _exporter = JaegerExporter(agent_host_name=jaeger_host, agent_port=jaeger_port)
        except ImportError as exc:
            raise ImportError(
                "Jaeger exporter requires opentelemetry-exporter-jaeger. "
                "Install with: pip install opentelemetry-exporter-jaeger"
            ) from exc

    if _exporter is not None:
        new_provider.add_span_processor(BatchSpanProcessor(_exporter))

    # Store on the module variable rather than the global OTel registry so
    # configure_tracing() is idempotent and test fixtures can swap providers
    # without hitting OTel's "override not allowed" guard.
    _provider = new_provider
    _tracer = None  # force re-fetch with new provider
    logger.info("OpenTelemetry tracing configured — service_name=%s", service_name)
