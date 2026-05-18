"""FastAPI control plane for memgar cloud.

Endpoints:
    GET  /v1/health                          liveness
    POST /v1/telemetry                       ingest signed batch of events
    GET  /v1/reputation/{source_id_hash}     scored from aggregated telemetry
    GET  /v1/feed/latest                     redirect to GitHub Release asset
    GET  /v1/sector/{sector}/baseline        per-sector pattern frequency
    GET  /v1/admin/summary                   admin-scoped fleet stats
    GET  /                                   minimal HTML dashboard

Run with:
    uvicorn memgar.cloud.server:app --port 8000

Or programmatically:
    from memgar.cloud.server import build_app
    app = build_app()

FastAPI is an optional dependency — install with `pip install memgar[cloud]`.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .aggregator import SignalAggregator, TelemetryRecord
from .auth import (
    ApiKeyScope, AuthError, InMemoryTenantStore, InsufficientScope,
    InvalidApiKey, SqliteTenantStore, TenantDisabled, TenantStore,
    verify_api_key,
)
from .config import MemgarCloudConfig

logger = logging.getLogger("memgar.cloud.server")


try:
    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = object  # type: ignore[assignment,misc]


def _ensure_fastapi() -> None:
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "memgar cloud server requires FastAPI. "
            "Install with: pip install 'memgar[cloud]'"
        )


# ─── Request / response models ────────────────────────────────────────


if FASTAPI_AVAILABLE:

    class TelemetryEventIn(BaseModel):
        signal_hash: str = Field(..., min_length=64, max_length=64)
        source_id_hash: str = Field(..., min_length=64, max_length=64)
        pattern_id: str = Field(..., max_length=64)
        risk_score: int = Field(..., ge=0, le=100)
        decision: str = Field(..., max_length=32)
        sector: Optional[str] = Field(default=None, max_length=64)
        ts: float = Field(..., ge=0)

    class TelemetryBatchIn(BaseModel):
        events: List[TelemetryEventIn] = Field(..., max_length=500)


# ─── Auth dependency ──────────────────────────────────────────────────


def _auth_dep(store: TenantStore, required: ApiKeyScope):
    """Build a FastAPI dependency for a given scope."""
    _ensure_fastapi()
    bearer = HTTPBearer(auto_error=False)

    async def _check(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        if credentials is None or not credentials.credentials:
            raise HTTPException(status_code=401, detail="missing Authorization bearer")
        try:
            key, tenant = verify_api_key(
                store, raw_key=credentials.credentials, required_scope=required,
            )
        except InvalidApiKey as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except InsufficientScope as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TenantDisabled as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return key, tenant

    return _check


# ─── App factory ──────────────────────────────────────────────────────


def build_app(
    *,
    config: Optional[MemgarCloudConfig] = None,
    store: Optional[TenantStore] = None,
    aggregator: Optional[SignalAggregator] = None,
):
    """Construct the FastAPI app with injectable storage.

    For self-hosters: pass a `SqliteTenantStore("/data/tenants.db")` and
    a `SignalAggregator(history_size=1_000_000)`. For tests / demos:
    omit both — defaults are in-memory.
    """
    _ensure_fastapi()
    cfg = config or MemgarCloudConfig()
    store = store or InMemoryTenantStore()
    aggregator = aggregator or SignalAggregator()

    app = FastAPI(
        title="Memgar Cloud",
        description="Telemetry, reputation, and feed mirror for connected memgar deployments.",
        version="0.1.0",
        docs_url="/v1/docs",
        redoc_url=None,
    )

    require_telemetry = _auth_dep(store, ApiKeyScope.TELEMETRY_WRITE)
    require_reputation = _auth_dep(store, ApiKeyScope.REPUTATION_READ)
    require_admin = _auth_dep(store, ApiKeyScope.ADMIN)

    # ─── Health ──────────────────────────────────────────────────────

    @app.get("/v1/health", tags=["meta"])
    async def health():
        return {
            "status": "ok",
            "service": "memgar-cloud",
            "version": app.version,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    # ─── Telemetry ───────────────────────────────────────────────────

    @app.post("/v1/telemetry", tags=["telemetry"])
    async def ingest_telemetry(
        batch: TelemetryBatchIn,
        auth=Depends(require_telemetry),
    ):
        key, tenant = auth
        accepted = 0
        for event in batch.events:
            aggregator.ingest(TelemetryRecord(
                tenant_id=tenant.id,
                received_at=time.time(),
                signal_hash=event.signal_hash,
                source_id_hash=event.source_id_hash,
                pattern_id=event.pattern_id,
                risk_score=event.risk_score,
                decision=event.decision,
                sector=event.sector,
            ))
            accepted += 1
        return {"accepted": accepted, "tenant_id": tenant.id}

    # ─── Reputation ──────────────────────────────────────────────────

    @app.get("/v1/reputation/{source_id_hash}", tags=["reputation"])
    async def reputation(source_id_hash: str, auth=Depends(require_reputation)):
        if len(source_id_hash) != 64:
            raise HTTPException(status_code=400, detail="source_id_hash must be sha256 hex (64 chars)")
        score = aggregator.reputation(source_id_hash)
        card = aggregator.source_card(source_id_hash)
        return {
            "source_id_hash": source_id_hash,
            "reputation": score,
            "evidence": card,
        }

    # ─── Sector baselines ────────────────────────────────────────────

    @app.get("/v1/sector/{sector}/baseline", tags=["reputation"])
    async def sector_baseline(sector: str, auth=Depends(require_reputation)):
        return {
            "sector": sector,
            "top_patterns": aggregator.top_patterns_for_sector(sector),
        }

    # ─── Feed mirror ─────────────────────────────────────────────────

    @app.get("/v1/feed/latest", tags=["feed"])
    async def feed_latest():
        return RedirectResponse(url=cfg.feed_storage_url, status_code=307)

    # ─── Admin ───────────────────────────────────────────────────────

    @app.get("/v1/admin/summary", tags=["admin"])
    async def admin_summary(auth=Depends(require_admin)):
        return {
            "aggregator": aggregator.summary(),
            "tenants": len(store.list_tenants()),
        }

    # ─── Minimal HTML dashboard ──────────────────────────────────────

    @app.get("/", response_class=HTMLResponse, tags=["meta"])
    async def index():
        summary = aggregator.summary()
        return _render_dashboard(summary)

    return app


# Module-level app for `uvicorn memgar.cloud.server:app`.
# Lazy: only constructed if FastAPI is available; otherwise the import
# of this module still succeeds so `memgar.cloud.client` and `auth` can
# be used without the server extras.
app = build_app() if FASTAPI_AVAILABLE else None


# ─── Dashboard rendering ──────────────────────────────────────────────


def _render_dashboard(summary: dict) -> str:
    top = summary.get("top_patterns", [])[:10]
    rows = "".join(
        f'<tr><td><code>{p["pattern_id"]}</code></td><td>{p["hits"]}</td></tr>'
        for p in top
    ) or '<tr><td colspan="2"><em>(no events yet)</em></td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Memgar Cloud — Control Plane</title>
<style>
:root {{
  --bg: #0d0c10; --card: #15131c; --border: #26242f;
  --fg: #f3f1f7; --muted: #b8b6c4; --accent: #a855f7;
}}
html, body {{ background: var(--bg); color: var(--fg); margin: 0;
  font: 15px/1.6 Inter, system-ui, sans-serif; }}
.wrap {{ max-width: 960px; margin: 4rem auto; padding: 0 1.5rem; }}
h1 {{ font-size: 2rem; letter-spacing: -0.02em; margin-bottom: 0.25rem; }}
.muted {{ color: var(--muted); }}
.card {{ background: var(--card); border: 1px solid var(--border);
  border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0; }}
.stat {{ display: inline-block; margin-right: 2.5rem; }}
.stat-value {{ font-size: 1.875rem; font-weight: 700;
  background: linear-gradient(135deg, #a855f7, #d8b4fe);
  -webkit-background-clip: text; background-clip: text; color: transparent; }}
.stat-label {{ display: block; font-size: 0.8125rem; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.06em; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ text-align: left; padding: 0.5rem 0;
  border-bottom: 1px solid var(--border); }}
code {{ background: rgba(168,85,247,0.1); border: 1px solid rgba(168,85,247,0.2);
  border-radius: 4px; padding: 0.125rem 0.4rem; color: #e9d5ff;
  font: 13px JetBrains Mono, monospace; }}
a {{ color: var(--accent); }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Memgar Cloud</h1>
  <p class="muted">Control plane for connected memgar deployments — telemetry, reputation, feed mirror.</p>

  <div class="card">
    <div class="stat"><div class="stat-value">{summary.get('event_count', 0)}</div><span class="stat-label">Events ingested</span></div>
    <div class="stat"><div class="stat-value">{summary.get('distinct_sources', 0)}</div><span class="stat-label">Distinct sources</span></div>
    <div class="stat"><div class="stat-value">{summary.get('distinct_patterns', 0)}</div><span class="stat-label">Distinct patterns</span></div>
    <div class="stat"><div class="stat-value">{summary.get('distinct_sectors', 0)}</div><span class="stat-label">Sectors</span></div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;font-size:1.125rem">Top patterns (fleet-wide)</h2>
    <table>
      <thead><tr><th>Pattern ID</th><th>Hits</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <p class="muted">API docs: <a href="/v1/docs">/v1/docs</a> · Health: <a href="/v1/health">/v1/health</a></p>
</div>
</body>
</html>
"""


__all__ = ["build_app", "app", "FASTAPI_AVAILABLE"]
