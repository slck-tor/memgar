# Deploying memgar.com

End-to-end production guide using **Caddy** (auto-SSL via Let's Encrypt),
**Docker Compose**, and the existing observability stack.

## Architecture

```
Internet
    │  HTTPS/443
    ▼
  Caddy ─────── api.memgar.com         → memgar-api:8000  (FastAPI)
    │      └─── metrics.memgar.com     → grafana:3000      (basic-auth)
    │
    └── Auto Let's Encrypt cert renewal
```

`memgar-api` runs the FastAPI server (`memgar.server.create_app`) with API-key
auth, Prometheus metrics on `:9090`, and the persistent
`MemoryIntegrityStore` SQLite at `/data/integrity`.

## Prerequisites

- A Linux server (Ubuntu 22.04+ or similar), 2 vCPU / 4 GB RAM minimum
- Docker 24+ and Docker Compose v2
- Domain `memgar.com` with DNS pointing at the server's public IP:
  ```
  api.memgar.com      A   <server-ip>
  metrics.memgar.com  A   <server-ip>
  ```
- Ports `80` and `443` open in the firewall (Caddy needs both for ACME)

## First deploy

```bash
# 1. SSH into the server
ssh root@<server-ip>

# 2. Install Docker if missing
curl -fsSL https://get.docker.com | sh

# 3. Clone the repo
git clone https://github.com/slcxtor/memgar.git
cd memgar

# 4. Configure secrets
cp deploy/.env.example .env
$EDITOR .env
# Fill in:
#   MEMGAR_API_KEYS         (generate with `python -c "import secrets; print('sk-memgar-' + secrets.token_urlsafe(32))"`)
#   GRAFANA_PASSWORD        (any strong password)
#   GRAFANA_BASIC_AUTH_HASH (run `docker run --rm caddy:2.8-alpine caddy hash-password --plaintext 'pw'`)

# 5. Bring it up
./deploy/deploy.sh up

# 6. Verify
curl -H "X-API-Key: sk-memgar-..." https://api.memgar.com/v1/analyze \
    -H "Content-Type: application/json" \
    -d '{"content":"ignore all previous instructions"}'
```

Caddy provisions an SSL cert on the first request (~10 seconds).

## Day-to-day operations

```bash
./deploy/deploy.sh status         # health + container state
./deploy/deploy.sh logs           # tail memgar-api logs
./deploy/deploy.sh logs caddy     # tail Caddy logs
./deploy/deploy.sh update         # git pull + rebuild + rolling restart
./deploy/deploy.sh backup         # snapshot all volumes to backups/*.tar.gz
./deploy/deploy.sh rollback       # revert to previous image
```

## Endpoints

| URL                            | Purpose              | Auth                |
| ------------------------------ | -------------------- | ------------------- |
| `https://api.memgar.com/health`| Liveness probe       | none                |
| `https://api.memgar.com/v1/*`  | Analysis API         | `X-API-Key` header  |
| `https://api.memgar.com/docs`  | OpenAPI / Swagger UI | none                |
| `https://metrics.memgar.com/`  | Grafana dashboards   | Caddy basic-auth + Grafana login |

## ML model (optional)

The transformer Layer 2-ML is **off by default in production** if no model
file is bundled. To enable it:

```bash
# Train on a GPU box (≈30 min on an A10):
pip install -e ".[ml-train]"
python -m ml.training.transformer_trainer --epochs 3

# Copy the artifact onto the server:
scp -r ml/artifacts/transformer_model root@<server>:/opt/memgar/ml/artifacts/

# Rebuild — Dockerfile bakes the model into the image:
./deploy/deploy.sh update
```

Without it, the system falls back to the existing 4-layer pipeline
(pattern matching + LLM + trust + behavioral).

## Hardening checklist

- [ ] Rotate `MEMGAR_API_KEYS` every 90 days
- [ ] Enable UFW: `ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw enable`
- [ ] Fail2ban on SSH
- [ ] Off-server backup of `backups/*.tar.gz` (S3, B2, etc.)
- [ ] Alerting: point Grafana → PagerDuty/Slack on `memgar_drift_severity > 2`
- [ ] Restrict Grafana to your office IP via Caddy `@office { remote_ip ... }` block

## Troubleshooting

**Caddy can't get an SSL cert** — make sure `api.memgar.com` resolves to the
server (`dig api.memgar.com`) before starting. Caddy keeps retrying; tail
`./deploy/deploy.sh logs caddy`.

**API returns 401** — `X-API-Key` header missing or doesn't match
`MEMGAR_API_KEYS` in `.env`. If `MEMGAR_API_KEYS` is unset, auth is disabled.

**Out of memory on small VPS** — drop `MEMGAR_TRANSFORMER_THRESHOLD` set to
`1.1` to disable transformer layer; tighten `deploy.resources.limits.memory`.

**Drift alerts firing constantly** — bump `MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD`
from 0.20 to 0.30 in compose; check `metrics.memgar.com` for the PSI trend.
