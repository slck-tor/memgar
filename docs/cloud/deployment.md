# Self-hosting Memgar Cloud

Three options, by lift:

## 1. Public memgar.com (zero ops)

```bash
pip install 'memgar[cloud]'
export MEMGAR_CLOUD_TELEMETRY=1
export MEMGAR_CLOUD_API_KEY=mck_yourkey
```

That's it. Get a key by emailing hello@memgar.com (waitlist while we're
pre-1.0).

## 2. Single-node self-host

```bash
pip install 'memgar[cloud]'
export MEMGAR_CLOUD_DATABASE_URL=sqlite:///./tenants.db
uvicorn memgar.cloud.server:app --host 0.0.0.0 --port 8000
```

Mint your first tenant + key from a Python shell:

```python
from memgar.cloud.auth import (
    SqliteTenantStore, Tenant, ApiKeyScope, issue_api_key,
)
import time

store = SqliteTenantStore("./tenants.db")
store.upsert_tenant(Tenant(id="acme", name="ACME", created_at=time.time()))
record, raw = issue_api_key(
    store, tenant_id="acme", name="default",
    scopes=[ApiKeyScope.TELEMETRY_WRITE, ApiKeyScope.REPUTATION_READ],
)
print("Save this exactly once:", raw)
```

## 3. Cloudflare Workers (edge)

The aggregator is in-memory in Python — for the Workers tier, the
intended pattern is:

  - Ingest → Workers KV / Durable Objects
  - Reputation lookup → cached at the edge, recomputed every 5 min
  - Feed mirror → R2 + Cache Reserve

A reference TypeScript port lives at `cloudflare/` (TBD). PRs welcome.

## Bootstrap checklist

- [ ] Pick a database (SQLite for ≤ 1 node, Postgres for ≥ 2)
- [ ] Generate Ed25519 signing key for feed (`memgar feed keys generate`)
- [ ] Set `MEMGAR_FEED_PRIVATE_KEY_PEM` in GitHub Actions secrets
- [ ] Decide whether to publish to public GHCR or in-cluster registry
- [ ] Configure reverse proxy (TLS, rate limit, body-size limit)
- [ ] Decide on aggregator persistence cadence (currently in-memory)

Production hardening checklist (separate work):

- [ ] Postgres adapter for `TenantStore`
- [ ] Redis adapter for `SignalAggregator` (cross-node)
- [ ] Rate limiting per API key
- [ ] Quotas + billing integration (Stripe metered usage)
- [ ] Observability — `memgar.cloud` Prometheus metrics
- [ ] SOC 2 controls
