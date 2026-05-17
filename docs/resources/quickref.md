# Quickref card

One-page memgar reference.

## Install

```bash
pip install memgar                                   # core
pip install "memgar[feed,observability,gateway]"     # production
pip install -e ".[dev,adversarial]"                  # contributors
```

## Analyze

```python
from memgar import Analyzer, MemoryEntry, Decision

a = Analyzer(use_llm=False)
result = a.analyze(MemoryEntry(content="..."))

result.decision         # Decision.ALLOW / QUARANTINE / BLOCK
result.risk_score       # 0-100
result.layers_used      # ['pattern_matching', 'transformer_ml', ...]
result.explanation      # human-readable
result.threats          # list[ThreatMatch]
```

## fail-close

```python
a = Analyzer(fail_close=True)
# or: export MEMGAR_FAIL_CLOSE=true
```

Escalates `ALLOW → QUARANTINE` when any ML layer or feed is degraded.

## Trust

```python
a.register_source_trust("openai-api",      0.95)
a.register_source_trust("user-form",       0.40)
a.register_source_trust("untrusted-wiki",  0.10)
```

## Health

```python
a.health_check()
# {'patterns': {...}, 'layer1_5_semantic_guard': {...},
#  'layer2_ml_transformer': {...}, 'threat_feed': {...}}
```

## Calibration (offline)

```bash
# Strict gate
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --output ml/artifacts/fpfn_calibration.json --no-llm
python scripts/check_calibration_gate.py

# Expanded gate
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --corpus ml/data/mined_hard_subset.json \
    --corpus ml/data/augmented_memory_context.json \
    --output ml/artifacts/fpfn_calibration_expanded.json --no-llm
python scripts/check_expanded_gate.py
```

## Environment

| Var | Default | Effect |
|---|---|---|
| `MEMGAR_FEED_ENABLED` | true | Pull signed threat feed |
| `MEMGAR_FEED_MAX_AGE_DAYS` | 7 | Cache staleness |
| `MEMGAR_OBSERVABILITY_ENABLED` | false | Prometheus + drift |
| `MEMGAR_OBSERVABILITY_PORT` | 9090 | Scrape port |
| `MEMGAR_FAIL_CLOSE` | false | Escalate on degraded |
| `MEMGAR_TRANSFORMER_THRESHOLD` | 0.92 | ML signal cutoff |
| `MEMGAR_CACHE_DIR` | `~/.cache/memgar` | Pattern + feed cache |

## CLI

```bash
memgar feed sync        # force pull threat feed
memgar feed status      # last outcome + version
memgar feed verify      # signature check
memgar gateway run      # FastAPI gateway mode
```

## Decisions

| `Decision` | When | Action |
|---|---|---|
| `ALLOW` | risk < 40 | use as-is |
| `QUARANTINE` | 40 ≤ risk < 80 | audit / human review |
| `BLOCK` | risk ≥ 80 or CRITICAL match | reject |

## Pattern ID prefixes

| Prefix | Category |
|---|---|
| `INJ-` | prompt injection / override |
| `EXFIL-` | exfiltration / leak |
| `EXEC-` | execution / malware / cyber |
| `MANIP-` | manipulation / disinformation |
| `CRED-` | credential / token leak |
| `PRIV-` | privilege escalation |
| `FIN-` | financial fraud / wire transfer |
| `EVAS-` | encoding / obfuscation evasion |
| `BHV-` | sleeper / conditional behaviour |

See the [full catalog](../threats/catalog.md) for every ID.
