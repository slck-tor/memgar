"""FastAPI REST server for Memgar — production-ready HTTP interface.

Usage
-----
    # Programmatic
    import uvicorn
    from memgar.server import create_app
    uvicorn.run(create_app(), host="0.0.0.0", port=8000)

    # CLI
    memgar serve [--host 0.0.0.0] [--port 8000] [--rate-limit 60]

Requires: fastapi, uvicorn  (pip install 'memgar[server]')
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models (module-level so FastAPI can inspect type annotations)
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel, Field

    class AnalyzeRequest(BaseModel):
        content: str = Field(..., description="Memory content to analyse")
        source_type: str = Field("unknown", description="Source type: chat | email | document | …")
        source_id: Optional[str] = Field(None, description="Source ID for Layer 3 trust scoring")
        agent_id: Optional[str] = Field(None, description="Agent ID for Layer 4 behavioural baseline")

    class ThreatDetail(BaseModel):
        id: str
        name: str
        severity: str
        category: str
        matched_text: str
        confidence: float

    class AnalyzeResponse(BaseModel):
        decision: str          # allow | quarantine | block
        risk_score: int        # 0–100
        threat_count: int
        threats: List[ThreatDetail]
        explanation: str
        layers_used: List[str]
        analysis_time_ms: float

    class ScanRequest(BaseModel):
        entries: List[AnalyzeRequest] = Field(
            ..., max_length=100, description="Up to 100 entries to scan concurrently"
        )

    class ScanResponse(BaseModel):
        total: int
        blocked: int
        quarantined: int
        allowed: int
        results: List[AnalyzeResponse]
        total_time_ms: float

    class HealthResponse(BaseModel):
        status: str
        version: str
        uptime_secs: float

    class ReadyResponse(BaseModel):
        ready: bool
        patterns_loaded: int
        model_loaded: bool
        feed_available: bool

    _MODELS_OK = True

except ImportError:
    _MODELS_OK = False
    # Provide stub names so `from memgar.server import create_app` doesn't fail
    AnalyzeRequest = AnalyzeResponse = ThreatDetail = None  # type: ignore[misc,assignment]
    ScanRequest = ScanResponse = HealthResponse = ReadyResponse = None  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter (no extra deps)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Per-key sliding-window rate limiter backed by an in-memory list."""

    def __init__(self, requests_per_minute: int = 60) -> None:
        self._rpm = requests_per_minute
        self._window = 60.0
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = [t for t in self._buckets.get(key, []) if now - t < self._window]
            if len(bucket) >= self._rpm:
                self._buckets[key] = bucket
                return False
            bucket.append(now)
            self._buckets[key] = bucket
            return True


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    rate_limit_rpm: int = 60,
    cors_origins: Optional[List[str]] = None,
) -> Any:
    """Build and return the FastAPI application.

    Args:
        rate_limit_rpm: Max requests per minute per IP (default 60).
        cors_origins: Allowed CORS origins (default ["*"]).

    Returns:
        FastAPI application instance.

    Raises:
        ImportError: If ``fastapi`` is not installed.
    """
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise ImportError(
            "FastAPI is required for the REST server. "
            "Install it with: pip install 'memgar[server]'"
        ) from exc

    if not _MODELS_OK:
        raise ImportError("pydantic is required: pip install 'memgar[server]'")

    if cors_origins is None:
        cors_origins = ["*"]

    from memgar import __version__
    from memgar.models import MemoryEntry

    _start_time = time.time()
    _state: Dict[str, Any] = {"analyzer": None}
    _limiter = _RateLimiter(requests_per_minute=rate_limit_rpm)

    # ------------------------------------------------------------------
    # Lifespan
    # ------------------------------------------------------------------
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Memgar server starting — loading analyzer …")
        from memgar.analyzer import Analyzer
        _state["analyzer"] = Analyzer()
        logger.info("Analyzer ready: %d patterns loaded", len(_state["analyzer"].patterns))
        yield
        logger.info("Memgar server shutting down")

    # ------------------------------------------------------------------
    # App
    # ------------------------------------------------------------------
    app = FastAPI(
        title="Memgar API",
        description=(
            "AI agent memory security — multi-layer threat detection REST API.\n\n"
            "**Layers**: 1 pattern matching · 2 LLM semantic (optional) · "
            "3 trust scoring · 4 behavioural baseline"
        ),
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Rate-limit middleware
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if request.url.path not in ("/health", "/ready"):
            # Honour X-Forwarded-For for proxied deployments (first trusted hop).
            # Fall back to direct connection address and normalise IPv6.
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                raw_ip = forwarded_for.split(",")[0].strip()
            elif request.client:
                raw_ip = request.client.host
            else:
                raw_ip = "unknown"
            try:
                import ipaddress
                client_ip = str(ipaddress.ip_address(raw_ip.strip("[]")))
            except (ValueError, AttributeError):
                client_ip = raw_ip
            if not _limiter.is_allowed(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded: {rate_limit_rpm} req/min"},
                    headers={"Retry-After": "60"},
                )
        return await call_next(request)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------
    def _to_response(result) -> AnalyzeResponse:
        return AnalyzeResponse(
            decision=result.decision.value,
            risk_score=result.risk_score,
            threat_count=len(result.threats),
            threats=[
                ThreatDetail(
                    id=t.threat.id,
                    name=t.threat.name,
                    severity=t.threat.severity.value,
                    category=t.threat.category.value,
                    matched_text=t.matched_text,
                    confidence=t.confidence,
                )
                for t in result.threats
            ],
            explanation=result.explanation,
            layers_used=result.layers_used,
            analysis_time_ms=result.analysis_time_ms,
        )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------
    @app.get("/health", response_model=HealthResponse, tags=["ops"],
             summary="Liveness probe — always 200 while process is alive")
    async def health():
        return HealthResponse(
            status="ok",
            version=__version__,
            uptime_secs=round(time.time() - _start_time, 1),
        )

    @app.get("/ready", response_model=ReadyResponse, tags=["ops"],
             summary="Readiness probe — 200 when analyzer is loaded")
    async def ready():
        analyzer = _state.get("analyzer")
        patterns_loaded = len(analyzer.patterns) if analyzer else 0

        try:
            from ml.continuous_learning import StorageManager  # noqa: F401
            model_loaded = True
        except Exception:
            model_loaded = False

        try:
            from memgar import FEED_AVAILABLE as _fa
            feed_ok = bool(_fa)
        except Exception:
            feed_ok = False

        if patterns_loaded == 0:
            raise HTTPException(status_code=503, detail="Analyzer not ready")

        return ReadyResponse(
            ready=True,
            patterns_loaded=patterns_loaded,
            model_loaded=model_loaded,
            feed_available=feed_ok,
        )

    @app.post("/analyze", response_model=AnalyzeResponse, tags=["analyze"],
              summary="Analyse a single memory entry (all 4 layers)")
    async def analyze_endpoint(body: AnalyzeRequest):
        """
        Run all active layers (1–4) on a single memory entry.
        Returns decision (allow/quarantine/block), risk score 0–100,
        and details of every matched threat.
        """
        analyzer = _state.get("analyzer")
        if analyzer is None:
            raise HTTPException(status_code=503, detail="Analyzer not ready")

        meta = {"agent_id": body.agent_id} if body.agent_id else {}
        entry = MemoryEntry(
            content=body.content,
            source_type=body.source_type,
            source_id=body.source_id,
            metadata=meta,
        )
        result = await analyzer.analyze_async(entry)
        return _to_response(result)

    @app.post("/scan", response_model=ScanResponse, tags=["analyze"],
              summary="Scan up to 100 entries concurrently")
    async def scan_endpoint(body: ScanRequest):
        """
        Analyse multiple memory entries concurrently (max 100 per request).
        Returns per-entry results plus aggregated blocked/quarantined/allowed counts.
        """
        analyzer = _state.get("analyzer")
        if analyzer is None:
            raise HTTPException(status_code=503, detail="Analyzer not ready")

        import asyncio

        t0 = time.perf_counter()

        async def _one(req: AnalyzeRequest) -> AnalyzeResponse:
            meta = {"agent_id": req.agent_id} if req.agent_id else {}
            entry = MemoryEntry(
                content=req.content,
                source_type=req.source_type,
                source_id=req.source_id,
                metadata=meta,
            )
            return _to_response(await analyzer.analyze_async(entry))

        results = list(await asyncio.gather(*[_one(e) for e in body.entries]))
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        return ScanResponse(
            total=len(results),
            blocked=sum(1 for r in results if r.decision == "block"),
            quarantined=sum(1 for r in results if r.decision == "quarantine"),
            allowed=sum(1 for r in results if r.decision == "allow"),
            results=results,
            total_time_ms=elapsed_ms,
        )

    return app
