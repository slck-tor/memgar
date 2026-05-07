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

Multi-tenancy
-------------
Keys are managed via TenantStore (SQLite). The legacy env-var fallback
(MEMGAR_API_KEYS) is still supported for zero-config dev/local use.

Admin endpoints (POST /admin/tenants, POST /admin/keys, etc.) are protected
by the MEMGAR_ADMIN_KEY environment variable. If unset, admin routes return 501.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def _get_legacy_keys() -> Set[str]:
    """Fallback: comma-separated keys from MEMGAR_API_KEYS env var (dev mode)."""
    raw = os.environ.get("MEMGAR_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


def _get_trusted_proxies() -> Set[str]:
    raw = os.environ.get("MEMGAR_TRUSTED_PROXIES", "")
    return {ip.strip() for ip in raw.split(",") if ip.strip()}


def _get_admin_key() -> Optional[str]:
    return os.environ.get("MEMGAR_ADMIN_KEY") or None


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel, Field

    class AnalyzeRequest(BaseModel):
        content: str = Field(..., max_length=100_000, description="Memory content to analyse")
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
        decision: str
        risk_score: int
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

    # ── Admin models ──────────────────────────────────────────────────────────

    class CreateTenantRequest(BaseModel):
        name: str = Field(..., min_length=1, max_length=200)
        plan: str = Field("starter", description="free | starter | pro | enterprise")

    class TenantResponse(BaseModel):
        id: str
        name: str
        plan: str
        rate_limit_rpm: int
        created_at: float
        active: bool

    class CreateKeyRequest(BaseModel):
        tenant_id: str
        name: str = Field("default", max_length=100)

    class KeyResponse(BaseModel):
        key: str
        tenant_id: str
        name: str
        rate_limit_rpm: int
        created_at: float
        last_used_at: Optional[float]
        request_count: int
        active: bool

    class UsageResponse(BaseModel):
        tenant_id: str
        active_keys: int
        total_requests: int
        last_active: Optional[float]

    _MODELS_OK = True

except ImportError:
    _MODELS_OK = False
    AnalyzeRequest = AnalyzeResponse = ThreatDetail = None  # type: ignore[misc,assignment]
    ScanRequest = ScanResponse = HealthResponse = ReadyResponse = None  # type: ignore[misc,assignment]
    CreateTenantRequest = TenantResponse = CreateKeyRequest = KeyResponse = UsageResponse = None  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# Per-key sliding-window rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Per-key sliding-window rate limiter backed by in-memory buckets."""

    def __init__(self, default_rpm: int = 60) -> None:
        self._default_rpm = default_rpm
        self._window = 60.0
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, rpm: Optional[int] = None) -> bool:
        limit = rpm if rpm is not None else self._default_rpm
        now = time.time()
        with self._lock:
            bucket = [t for t in self._buckets.get(key, []) if now - t < self._window]
            if len(bucket) >= limit:
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
    tenant_db_path: Optional[str] = None,
) -> Any:
    """Build and return the FastAPI application.

    Args:
        rate_limit_rpm: Default RPM for legacy env-var keys (default 60).
        cors_origins: Allowed CORS origins (default ["*"]).
        tenant_db_path: Path to tenants SQLite DB (default ~/.cache/memgar/tenants.db).

    Returns:
        FastAPI application instance.
    """
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise ImportError(
            "FastAPI is required. Install with: pip install 'memgar[server]'"
        ) from exc

    if not _MODELS_OK:
        raise ImportError("pydantic is required: pip install 'memgar[server]'")

    if cors_origins is None:
        cors_origins = ["*"]

    from memgar import __version__
    from memgar.models import MemoryEntry
    from memgar.tenants import TenantStore

    _start_time = time.time()
    _state: Dict[str, Any] = {"analyzer": None}
    _limiter = _RateLimiter(default_rpm=rate_limit_rpm)

    # Tenant store — shared across all requests
    _tenant_store = TenantStore(db_path=tenant_db_path)

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
            "**Layers**: 1 pattern matching · 2 transformer ML · "
            "3 trust scoring · 4 behavioural baseline\n\n"
            "**Auth**: set `X-API-Key` header "
            "(manage keys via `memgar keys` CLI or admin endpoints)."
        ),
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*", "X-API-Key"],
    )

    # ------------------------------------------------------------------
    # Authentication middleware — per-key, with tenant store fallback to env
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if request.url.path in ("/health", "/ready"):
            return await call_next(request)

        api_key = (
            request.headers.get("X-API-Key")
            or request.query_params.get("api_key")
        )

        # Admin routes: require MEMGAR_ADMIN_KEY
        if request.url.path.startswith("/admin"):
            admin_key = _get_admin_key()
            if not admin_key:
                return JSONResponse(
                    status_code=501,
                    content={"detail": "Admin API not configured (set MEMGAR_ADMIN_KEY)."},
                )
            if api_key != admin_key:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing admin key."},
                    headers={"WWW-Authenticate": "ApiKey"},
                )
            return await call_next(request)

        # Try tenant store first, then legacy env-var keys
        tenant_key = _tenant_store.authenticate(api_key) if api_key else None
        legacy_keys = _get_legacy_keys()

        if not api_key:
            if legacy_keys:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key. Set X-API-Key header."},
                    headers={"WWW-Authenticate": "ApiKey"},
                )
            # No keys configured anywhere — open dev mode
            return await call_next(request)

        if tenant_key is None and api_key not in legacy_keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key. Set X-API-Key header."},
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Attach resolved key info for rate limiter
        request.state.tenant_key = tenant_key  # ApiKey | None
        request.state.api_key_str = api_key

        if tenant_key:
            _tenant_store.record_usage(api_key)

        return await call_next(request)

    # ------------------------------------------------------------------
    # Rate-limit middleware — per API key (falls back to per IP for legacy)
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if request.url.path in ("/health", "/ready"):
            return await call_next(request)

        tenant_key = getattr(request.state, "tenant_key", None)
        api_key_str = getattr(request.state, "api_key_str", None)

        if tenant_key is not None:
            # Per-key rate limit from tenant plan
            bucket_id = api_key_str
            rpm = tenant_key.rate_limit_rpm
        else:
            # Legacy: rate-limit by IP
            forwarded_for = request.headers.get("X-Forwarded-For")
            direct_ip = request.client.host if request.client else None
            trusted_proxies = _get_trusted_proxies()
            if forwarded_for and direct_ip and direct_ip in trusted_proxies:
                raw_ip = forwarded_for.split(",")[0].strip()
            elif request.client:
                raw_ip = request.client.host
            else:
                raw_ip = "unknown"
            try:
                import ipaddress
                bucket_id = str(ipaddress.ip_address(raw_ip.strip("[]")))
            except (ValueError, AttributeError):
                bucket_id = raw_ip
            rpm = rate_limit_rpm

        if not _limiter.is_allowed(bucket_id, rpm=rpm):
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: {rpm} req/min"},
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
    # Routes — public
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

    # ------------------------------------------------------------------
    # Routes — admin (require MEMGAR_ADMIN_KEY)
    # ------------------------------------------------------------------

    @app.post("/admin/tenants", response_model=TenantResponse, tags=["admin"],
              summary="Create a new tenant")
    async def admin_create_tenant(body: CreateTenantRequest):
        try:
            t = _tenant_store.create_tenant(name=body.name, plan=body.plan)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return TenantResponse(
            id=t.id, name=t.name, plan=t.plan,
            rate_limit_rpm=t.rate_limit_rpm,
            created_at=t.created_at, active=t.active,
        )

    @app.get("/admin/tenants", response_model=List[TenantResponse], tags=["admin"],
             summary="List all tenants")
    async def admin_list_tenants():
        tenants = _tenant_store.list_tenants()
        return [
            TenantResponse(
                id=t.id, name=t.name, plan=t.plan,
                rate_limit_rpm=t.rate_limit_rpm,
                created_at=t.created_at, active=t.active,
            )
            for t in tenants
        ]

    @app.get("/admin/tenants/{tenant_id}/usage", response_model=UsageResponse, tags=["admin"],
             summary="Usage stats for a tenant")
    async def admin_tenant_usage(tenant_id: str):
        tenant = _tenant_store.get_tenant(tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail="Tenant not found")
        stats = _tenant_store.usage_stats(tenant_id)
        return UsageResponse(**stats)

    @app.delete("/admin/tenants/{tenant_id}", tags=["admin"],
                summary="Deactivate a tenant and all its keys")
    async def admin_deactivate_tenant(tenant_id: str):
        ok = _tenant_store.deactivate_tenant(tenant_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {"detail": "Tenant deactivated"}

    @app.post("/admin/keys", response_model=KeyResponse, tags=["admin"],
              summary="Create an API key for a tenant")
    async def admin_create_key(body: CreateKeyRequest):
        try:
            k = _tenant_store.create_key(tenant_id=body.tenant_id, name=body.name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return KeyResponse(
            key=k.key, tenant_id=k.tenant_id, name=k.name,
            rate_limit_rpm=k.rate_limit_rpm, created_at=k.created_at,
            last_used_at=k.last_used_at, request_count=k.request_count,
            active=k.active,
        )

    @app.get("/admin/keys", response_model=List[KeyResponse], tags=["admin"],
             summary="List API keys (optionally filter by tenant_id)")
    async def admin_list_keys(tenant_id: Optional[str] = None):
        keys = _tenant_store.list_keys(tenant_id=tenant_id)
        return [
            KeyResponse(
                key=k.key, tenant_id=k.tenant_id, name=k.name,
                rate_limit_rpm=k.rate_limit_rpm, created_at=k.created_at,
                last_used_at=k.last_used_at, request_count=k.request_count,
                active=k.active,
            )
            for k in keys
        ]

    @app.delete("/admin/keys/{key}", tags=["admin"],
                summary="Revoke an API key")
    async def admin_revoke_key(key: str):
        ok = _tenant_store.revoke_key(key)
        if not ok:
            raise HTTPException(status_code=404, detail="Key not found")
        return {"detail": "Key revoked"}

    return app
