# Observability

## Prometheus metrics

```python
import memgar
memgar.start_metrics_server(port=9090)  # idempotent
```

| Metric | Type | Description |
|---|---|---|
| `memgar_analyses_total{decision}` | Counter | total analyses per decision |
| `memgar_analysis_latency_seconds` | Histogram | per-call latency |
| `memgar_risk_score` | Histogram | 0–100 risk scores |
| `memgar_drift_severity` | Gauge | 0 none → 4 critical |
| `memgar_model_version{version}` | Gauge | exposes deployed model version |

Curl test:

```bash
curl http://localhost:9090/metrics | grep memgar_
```

## Drift monitor

A `DriftMonitor` runs in a background thread (default 60s heartbeat) and
computes Population Stability Index (PSI) on incoming risk-score
distribution vs the baseline window.

Configure via env:

```bash
export MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD=0.20   # PSI threshold
export MEMGAR_OBSERVABILITY_DRIFT_WINDOW=1000      # baseline window size
```

When PSI crosses the threshold, the monitor emits a SIEM event
`DRIFT_DETECTED` with the affected layer and the actual PSI value.

## SIEM events (OCSF)

Every block / quarantine / drift-detection emits an OCSF-formatted event:

```json
{
  "metadata": {
    "version": "1.0.0",
    "product": {"name": "memgar", "version": "1.0.0"},
    "event_code": "MEMGAR_BLOCK"
  },
  "time": 1715953200000,
  "category_uid": 1,
  "category_name": "System Activity",
  "class_uid": 1006,
  "class_name": "Process Activity",
  "severity_id": 4,
  "severity": "High",
  "type_uid": 100601,
  "type_name": "Process Activity: Memory Modification Blocked",
  "actor": {
    "process": {"name": "memgar", "pid": 12345}
  },
  "memory": {
    "source_id": "untrusted-wiki",
    "decision": "block",
    "risk_score": 91.5,
    "category": "exfiltration",
    "layers_used": ["pattern_matching", "trust_aware"],
    "matched_threats": ["EXFIL-016"],
    "mitre_attack": ["T1213"]
  }
}
```

## Distributed tracing

Memgar instruments key layer calls with OpenTelemetry spans named
`memgar.layer1.pattern`, `memgar.layer1_5.semantic_guard`,
`memgar.layer2.llm`, `memgar.layer2ml.transformer`. Attach your OTel exporter
to see per-layer latency / probability attributes in Jaeger / Datadog /
Tempo.

```python
from opentelemetry import trace
tracer = trace.get_tracer("my-service")

with tracer.start_as_current_span("user.message"):
    result = analyzer.analyze(MemoryEntry(content=msg))
    # All memgar internal spans nest under user.message automatically
```
