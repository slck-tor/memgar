# Telemetry — what gets sent, when, and how to opt out

Memgar Cloud telemetry is **opt-in, hash-only, and self-hostable**. This page
is the privacy contract.

## Off by default

```python
from memgar.cloud import CloudClient
CloudClient.from_env().is_enabled   # → False unless you flipped it on
```

The client refuses to send anything unless **both** are true:

1. `MEMGAR_CLOUD_TELEMETRY=1` env var (or `telemetry_enabled=True` in config)
2. `MEMGAR_CLOUD_API_KEY` is set (or `allow_anonymous_telemetry=True` on the server)

## What gets sent

Every analyser call that opted into telemetry produces 0–N events
(one per matched pattern, or one with `pattern_id="__no_threat__"` if
no threat fired). Each event:

```jsonc
{
  "signal_hash":     "<sha256 of the raw content>",       // 64 hex chars
  "source_id_hash":  "<sha256 of source_id>",             // 64 hex chars
  "pattern_id":      "XSESS-001",                          // public catalog ID
  "risk_score":      80,                                   // 0–100
  "decision":        "block",                              // verdict
  "sector":          "legal",                              // optional, from config
  "ts":              1779127740.123                        // event timestamp
}
```

## What does NOT get sent

- Raw content (text, code, prompts) — only its SHA-256
- Raw `source_id` — only its SHA-256
- `agent_id`, IP, hostname, file paths, OS info
- Tool calls, message bodies, RAG document chunks
- Authentication credentials, API keys, OAuth tokens
- Any field that could re-identify the user or organisation

The hash function is **one-way**. The aggregator can compare hashes
across tenants but cannot reverse them to content.

## Cross-tenant correlation, by design

Two honest tenants seeing the same poisoned chunk compute the **same**
`signal_hash`. This is the point: aggregator learns "this hash was seen
by 12 distinct tenants" → low reputation for the corresponding source.

Tenants do not see each other's data. Only the aggregator sees the
cross-tenant count.

## Self-hosting

If you can't share data with the public memgar control plane (compliance,
sovereignty, contracts), run your own:

```bash
docker run -p 8000:8000 -v /data:/data ghcr.io/slcxtor/memgar-cloud:latest
```

Then point your clients at it:

```bash
export MEMGAR_CLOUD_URL=https://memgar.internal.example.com
```

See [Deployment](deployment.md).

## Opting out mid-stream

```bash
unset MEMGAR_CLOUD_TELEMETRY    # or set to 0
# next process restart, telemetry is off; existing buffered events are dropped
```

The client has no persistent buffer — pending events live in an
in-process queue that's cleared on shutdown.

## Audit

The client logs every telemetry batch at DEBUG level:

```python
import logging
logging.getLogger("memgar.cloud.client").setLevel(logging.DEBUG)
```

You can also pipe the queue into your own SIEM via the `on_block`
callback on `VectorStoreSecurityShell` for the integration wrappers.
