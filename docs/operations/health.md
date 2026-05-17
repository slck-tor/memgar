# Health monitoring

Every memgar subsystem exposes a structured health dict. The aggregated view
is `Analyzer.health_check()`.

## Why structured health?

Memgar's pipeline degrades silently if you let it. The first version logged a
single `WARNING` when SemanticGuard was missing centroids — operators never
saw it, scored every input as `0.0`, and assumed memgar was working.

Now every subsystem:

1. Logs **one** clear WARNING the first time it degrades (deduped per
   process).
2. Exposes a `health()` method returning a uniform dict.
3. Reports itself via `Analyzer.health_check()` so operators can wire it
   into Prometheus / alerts.
4. Falls out of the analysis pipeline (no zero-padded scoring noise).

## Sample output

```python
{
  "patterns": {
    "status": "ok",
    "n_patterns": 770,
  },
  "layer1_5_semantic_guard": {
    "status": "degraded",
    "reason": "centroids_file_missing",
    "is_fitted": False,
    "n_centroids": 0,
    "centroids_path": "/path/to/centroids.pkl",
    "sentence_transformers_available": True,
    "fix_hint": "python scripts/compute_semantic_centroids.py",
  },
  "layer2_ml_transformer": {
    "status": "disabled",
    "reason": "tokenizer_dir_missing: ml/artifacts/transformer_model/tokenizer",
    "is_ready": False,
    "backend": "none",
    "onnx_path": "ml/artifacts/transformer_model/model.onnx",
    "tokenizer_dir": "ml/artifacts/transformer_model/tokenizer",
    "fix_hint": "python scripts/train_transformer.py --data your_data.json",
  },
  "threat_feed": {
    "status": "ok",
    "repo": "slcxtor/memgar",
    "last_outcome": "loaded",
    "last_attempt_at": "2026-05-17T13:00:00Z",
    "last_bundle_version": "1.2.0",
    "last_pattern_count": 770,
    "used_fallback_url": False,
    "fix_hint": None,
  },
  "trust": {"status": "ok", "n_registered_sources": 3},
  "behavioral_baseline": {"status": "ok", "n_agents_tracked": 12},
}
```

## Status values

| Status | Meaning | Action |
|---|---|---|
| `ok` | Layer is fully active | — |
| `degraded` | Layer is partially functional or missing optional data | Use `fix_hint` |
| `disabled` | Layer is intentionally turned off (config) | None |
| `unknown` | First call hasn't happened yet | Wait |

## Prometheus integration

```python
import memgar
memgar.start_metrics_server(port=9090)
```

Adds five gauges/counters:

| Metric | Type | Labels |
|---|---|---|
| `memgar_analyses_total{decision}` | counter | allow, quarantine, block |
| `memgar_analysis_latency_seconds` | histogram | — |
| `memgar_risk_score` | histogram | 0–100 |
| `memgar_drift_severity` | gauge | 0 none → 4 critical |
| `memgar_model_version{version}` | gauge | per-version |

A separate `memgar_layer_status{layer,status}` gauge can be derived from
`health_check()` if you need per-layer alerts.

## fail_close

When `MEMGAR_FAIL_CLOSE=true` and any ML layer or the feed reports
`degraded` / `disabled`, every `ALLOW` decision is escalated to
`QUARANTINE`. The explanation says exactly which layers were degraded so the
operator can recover the missing artifact.

Use this in production when you'd rather defer to human review than let
content through with reduced coverage.
