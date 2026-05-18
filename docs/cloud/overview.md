# Memgar Cloud — connected threat intelligence

Self-hosted memgar protects one agent fleet from poisoned memory.
**Memgar Cloud** lets many self-hosted fleets share anonymised signals
so a poisoned source caught at one customer becomes a low-reputation
score at all the others. Same library, more eyes.

This is the **architecture and design** page. For the deployment
runbook see [Deployment](deployment.md); for the privacy contract see
[Telemetry](telemetry.md).

## What you get

| Capability | Self-hosted alone | Self-hosted + Cloud |
|---|---|---|
| Pattern library | bundled, updated by manual `feed sync` | bundled + **automatic weekly signed feed** |
| Source trust | manual `register_source_trust()` | manual + **fleet-aggregated reputation** |
| Behavioral baseline | per-agent local Welford stats | local + **sector cohort baseline** |
| Attack visibility | your logs | yours + **anonymised industry stats** |
| Threat-intel fresh | days/weeks | hours |

The cloud is **strictly opt-in**. Disabled by default; flipping it on
takes one env var and the data sent is hashed before it leaves the
process.

## Components

```
┌──────────────────────────────┐    ┌──────────────────────────────────────┐
│  self-hosted memgar          │    │  memgar control plane                │
│                              │    │  (this module: memgar.cloud)         │
│  ┌────────────────────────┐  │    │                                      │
│  │ Analyzer.analyze(...)  │  │    │  ┌────────────────────────────────┐  │
│  └──────────┬─────────────┘  │    │  │ POST /v1/telemetry             │  │
│             │                │    │  │   → SignalAggregator.ingest()  │  │
│             ▼                │    │  └────────────────────────────────┘  │
│  ┌────────────────────────┐  │    │  ┌────────────────────────────────┐  │
│  │ CloudClient.report()   │──┼────┼─►│ GET /v1/reputation/{hash}      │  │
│  │ CloudClient.reputation │◄─┼────┼──│   → SignalAggregator.reputation│  │
│  └────────────────────────┘  │    │  └────────────────────────────────┘  │
│                              │    │  ┌────────────────────────────────┐  │
│  ┌────────────────────────┐  │    │  │ GET /v1/feed/latest            │  │
│  │ FeedLoader.sync()      │◄─┼────┼──│   → 307 to GitHub Release asset│  │
│  └────────────────────────┘  │    │  └────────────────────────────────┘  │
│                              │    │  ┌────────────────────────────────┐  │
│                              │    │  │ GET /v1/sector/{s}/baseline    │  │
│                              │    │  └────────────────────────────────┘  │
│                              │    │  ┌────────────────────────────────┐  │
│                              │    │  │ GET /v1/admin/summary          │  │
│                              │    │  └────────────────────────────────┘  │
└──────────────────────────────┘    └──────────────────────────────────────┘
```

### `CloudClient` (in-process, opt-in)

`memgar/cloud/client.py`. A thin async batcher + reputation cache. It is
**off by default**:

```python
from memgar.cloud import CloudClient
client = CloudClient.from_env()
print(client.is_enabled)   # False — telemetry_enabled is OFF unless explicit
```

Enable it explicitly:

```bash
export MEMGAR_CLOUD_TELEMETRY=1
export MEMGAR_CLOUD_API_KEY=mck_yourkeyhere
export MEMGAR_CLOUD_URL=https://api.memgar.com   # or your self-hosted instance
```

The client batches events for `telemetry_interval_seconds` (default 60)
and POSTs them as a hashed batch. The reputation lookup is cached for
`reputation_cache_ttl_seconds` (default 5 minutes).

### `SignalAggregator` (server-side)

`memgar/cloud/aggregator.py`. The reputation scoring engine. Receives
`TelemetryRecord` events and maintains per-source running stats with
the following weighting:

  - **Base benignness** — `1 − mean_risk / 100`
  - **Cross-tenant penalty** — `0.03 × (distinct_tenants − 1)`
  - **Block-rate penalty** — `0.4 × (blocked + quarantined) / total_hits`
  - **Time decay** — half-life of 7 days; old observations anchor toward 0.5

Output is a `[0, 1]` reputation score. Below 5 observations the source
gets a neutral `0.5` so the client knows to fall back to local Layer 3
trust.

### `TenantStore` + `verify_api_key`

`memgar/cloud/auth.py`. Multi-tenant API key authentication.

- API keys hashed with SHA-256 at rest — DB leak alone is not enough
- Raw key shown to user **once** at issuance time, never again
- Scoped: `telemetry:write` / `reputation:read` / `feed:read` / `admin`
- Two storage backends ship: `InMemoryTenantStore` (tests) and
  `SqliteTenantStore` (self-hosted). Postgres / DynamoDB is a Protocol
  implementation away.

### FastAPI server

`memgar/cloud/server.py`. Mounts everything above as HTTP endpoints.

```bash
pip install 'memgar[cloud]'
uvicorn memgar.cloud.server:app --port 8000
```

Or programmatically:

```python
from memgar.cloud.server import build_app
from memgar.cloud.auth import SqliteTenantStore
from memgar.cloud.aggregator import SignalAggregator

app = build_app(
    store=SqliteTenantStore("/data/tenants.db"),
    aggregator=SignalAggregator(history_size=1_000_000),
)
```

## Endpoints

| Method | Path | Scope | Purpose |
|---|---|---|---|
| GET    | `/v1/health` | (none) | Liveness |
| POST   | `/v1/telemetry` | `telemetry:write` | Ingest batch of `TelemetryEventIn` |
| GET    | `/v1/reputation/{hash}` | `reputation:read` | Per-source reputation score + evidence |
| GET    | `/v1/sector/{sector}/baseline` | `reputation:read` | Top patterns in a sector |
| GET    | `/v1/feed/latest` | (none) | 307 redirect to latest GitHub Release asset |
| GET    | `/v1/admin/summary` | `admin` | Fleet-wide stats |
| GET    | `/` | (none) | Minimal HTML dashboard |

OpenAPI docs at `/v1/docs`.

## Privacy contract

What gets sent over the wire:

- `signal_hash` — SHA-256 of the raw content the analyser saw
- `source_id_hash` — SHA-256 of the source_id (also a string the user controls)
- `pattern_id` — public threat-catalog ID (e.g. `XSESS-001`)
- `risk_score` — 0-100 integer
- `decision` — `allow` / `sanitize` / `quarantine` / `block`
- `sector` — optional, from config — e.g. `legal`, `health`, `ecom`

What does **not** get sent:

- Raw content, raw source_id, agent_id, IP, hostname, file path
- Anything that could re-identify the user or organisation
- Tool calls, message contents, RAG document bodies
- Authentication credentials, API keys, OAuth tokens

The threat model: many honest tenants compute the same hash for the
same poisoned chunk. The aggregator can see "this hash was reported by
12 distinct tenants" but never sees the chunk itself.

## Status

This module is **scaffolded, not production-ready**. Shipped:

- Auth + multi-tenant data model ✓
- In-memory + SQLite stores ✓
- Aggregator with reputation + sector baselines ✓
- Opt-in client SDK with hash-only telemetry ✓
- FastAPI server with 6 endpoints ✓
- Minimal HTML dashboard ✓
- 25 tests, 100% passing ✓

Not yet:

- Postgres adapter
- WebSocket telemetry streaming
- Billing integration (Stripe stubs only)
- SLA, monitoring, alerting
- SOC 2 controls

The architecture is right; production hardening is a separate sprint.

## See also

- [Telemetry](telemetry.md) — exact privacy contract + opt-in flow
- [Deployment](deployment.md) — self-host the control plane
- [Threat feed pipeline](../operations/threat-feed-pipeline.md) — how
  the signed weekly feed is built and published
