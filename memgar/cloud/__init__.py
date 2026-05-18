"""Memgar Cloud — control plane for connected threat intelligence.

Architectural overview:

    self-hosted memgar libraries           memgar control plane (this module)
    ─────────────────────────────          ────────────────────────────────────
                                  POST /v1/telemetry
    Analyzer  ─────────────────────────────►  Aggregator → DB
        │   anonymised signal hashes
        │
        │                         GET /v1/reputation/{source_id}
        ├─────────────────────────────────────►  Reputation scorer
        │
        │                         GET /v1/feed/latest
        └─────────────────────────────────────►  Feed mirror (CDN-backed)

Three guarantees this module enforces:

  1. **Opt-in telemetry** — clients never push without explicit
     `MEMGAR_CLOUD_TELEMETRY=1` env var or `cloud.telemetry.enabled=True`
     config; default is OFF.

  2. **Hashed signals only** — no raw content ever leaves the client.
     Every telemetry event sends SHA-256 fingerprints + counts; the
     control plane sees patterns, not user data.

  3. **Self-hostable** — the entire control plane (`memgar.cloud.server`)
     can be deployed in-tenant (Docker / Kubernetes / Cloudflare Workers).
     Customers who can't share data with memgar Inc. run their own
     copy and point their `MEMGAR_CLOUD_URL` at it.

This is a *scaffolded* SaaS surface — the persistent storage layer
(Postgres, Redis) is wired through dependency injection. Default
in-process stores are provided for development and tests; production
deployers swap them out via the `MemgarCloudConfig` constructor.

Status: pre-1.0, every endpoint may change. See
`docs/cloud/overview.md` for the architecture and deployment guide.
"""

from .config import MemgarCloudConfig
from .client import CloudClient, TelemetryEvent
from .auth import ApiKey, Tenant, AuthError

__all__ = [
    "MemgarCloudConfig",
    "CloudClient",
    "TelemetryEvent",
    "ApiKey",
    "Tenant",
    "AuthError",
]
