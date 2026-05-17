# Memgar — Development Guide

## Project Overview

Memgar is a production-grade AI agent memory security library. It detects and blocks memory poisoning attacks against LLM-based agents using a 4-layer analysis pipeline.

## Architecture

### 4-Layer Analysis Pipeline (`memgar/analyzer.py`)

```
Layer 1 — Pattern Matching         <1ms    always on
Layer 2 — LLM Semantic Analysis    ~200ms  optional (use_llm=True)
Layer 3 — Trust-Aware Scoring      <0.1ms  auto (when source registered)
Layer 4 — Behavioral Baseline      <1ms    auto (per-agent, after warm-up)
```

**Layer 1** (`_layer1_pattern_matching`): Regex + keyword matching against 736 threat patterns loaded from `memgar/patterns.py` (pickle-cached for 3ms load vs 3500ms cold).

**Layer 2** (`_layer2_semantic_analysis`): Claude LLM call for sophisticated attacks. Runs independently of Layer 1 (catches obfuscation Layer 1 misses).

**Layer 3** (`_analyze_internal`, after risk_score computed): Source trust adjustment. Call `analyzer.register_source_trust(source_id, 0.0–1.0)` before analyzing. Low trust (<0.3) boosts risk ≤+30pts; high trust (≥0.8) reduces borderline scores by 5pts.

**Layer 4** (`analyze()`, after _analyze_internal): Per-agent `BehavioralBaseline` observes `scan_risk_score` and `scan_block_rate`. If the agent's current signals deviate SUSPICIOUS (+15pts) or CRITICAL (+30pts) from their learned baseline, risk is elevated. Only amplifies existing threat signals — never flags `risk_score=0` content.

### Key Entry Points

```python
from memgar import Analyzer, MemoryEntry, Decision

a = Analyzer(use_llm=False)                          # Layer 1+3+4
a.register_source_trust("untrusted-wiki", 0.1)       # Layer 3 setup
result = a.analyze(MemoryEntry(content="..."))        # sync
result = await a.analyze_async(MemoryEntry(...))      # async (thread-pool)
```

### Threat Intelligence Feed (`memgar/feed/`)

- **`FeedLoader`** downloads `memgar-feed.json.gz` from GitHub Releases, verifies Ed25519 signature, caches at `~/.cache/memgar/feeds/`
- **`FeedVerifier`** (`verifier.py`): `FEED_PUBLIC_KEY_B64` holds the real public key (generated 2026-04-26)
- **`FeedCache`**: 20MB compressed / 100MB decompressed limits; stale after `max_age_days=7`
- Feed patterns merge into Analyzer at startup if `cfg.feed.enabled=True` (default)
- CLI: `memgar feed sync | status | verify`
- Publish new bundle: `python scripts/publish_feed.py --private-key-file feed_private.pem --feed-version X.Y.Z`

### Adversarial Red-Team Loop (`ml/adversarial/`)

```
AttackGenerator  →  VariantCurator  →  HardNegativeMiner  →  AutoRetrainer.retrain()
```

- **`AttackGenerator`**: 4 offline mutations (homoglyph Cyrillic, leetspeak, base64, passive rewrite) + optional Claude API
- **`VariantCurator`**: TF-IDF cosine dedup, `max_variants_per_cluster=3`
- CLI: `python scripts/red_team_run.py --n-seeds 10 --n-variants 5 [--dry-run] [--offline]`

### Observability (`memgar/observability/`)

5 Prometheus metrics:
- `memgar_analyses_total{decision}` Counter
- `memgar_analysis_latency_seconds` Histogram
- `memgar_risk_score` Histogram (0-100)
- `memgar_drift_severity` Gauge (0=none → 4=critical)
- `memgar_model_version{version}` Gauge

PSI-based `DriftMonitor` runs in background thread (60s heartbeat). Emits SIEM `DRIFT_DETECTED` events on high PSI.

```python
import memgar
memgar.start_metrics_server(port=9090)  # idempotent
```

### Continuous Learning (`ml/continuous_learning.py`)

- `AutoRetrainer.retrain()`: backup → quality gate (precision≥0.94, recall≥0.94, P95≤25ms) → promote or restore
- `inject_adversarial_variants(variants)`: appends to `adversarial_variants.jsonl`
- `StorageManager.save_prediction()`: called automatically by `Analyzer.analyze()` for every prediction
- `compare_to_baseline(new_metrics, baseline_metrics, max_regression=0.02)`: regression guard

## Development Workflow

```bash
# Install with all extras
pip install -e ".[dev,adversarial,feed,observability]"

# Run tests
pytest -q                              # 165 pass, 7 skip (crypto)
pytest tests/test_analyzer.py -v      # Layer 3+4 integration tests
pytest tests/test_feed.py -v          # Feed verify/cache/loader tests
pytest tests/test_adversarial.py -v   # Red-team tests
pytest tests/test_observability.py -v # Prometheus/drift tests

# Rebuild ML model (runs quality gate)
python rebuild_model.py

# Red-team dry run
python scripts/red_team_run.py --n-seeds 10 --n-variants 5 --dry-run --offline

# Corpus expansion pipeline (Phase 1 + 2 of corpus growth)
python scripts/import_public_corpora.py            # AdvBench/JBB/HarmBench/gandalf/deepset → external_corpus_*.json
python scripts/mine_hard_negatives.py              # Diagnostic subset: all FPs + top-N FN per category → mined_hard_subset.json
python scripts/augment_memory_context.py           # Wrap attack seeds in 8 memory-injection envelopes → augmented_memory_context.json
python scripts/merge_corpus.py --aux ml/data/mined_hard_subset.json \
    --aux ml/data/augmented_memory_context.json    # Dry-run: see merged stats (gold stays untouched)

# Calibration (two-tier)
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --output ml/artifacts/fpfn_calibration.json --no-llm
python scripts/check_calibration_gate.py           # Gold-only: 8 strict gates (CI blocker)

python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --corpus ml/data/mined_hard_subset.json \
    --corpus ml/data/augmented_memory_context.json \
    --output ml/artifacts/fpfn_calibration_expanded.json --no-llm
python scripts/check_expanded_gate.py              # Merged: 6 regression-only gates
```

## Corpus tiers

| Tier | File | Source | Reviewed | Used by |
|---|---|---|---|---|
| Gold | `ml/data/calibration_corpus.json` | hand-curated | yes | CI gate (strict) |
| Mined | `ml/data/mined_hard_subset.json` | auto from public-corpus FN/FP | algorithmic | Expanded gate |
| Augmented | `ml/data/augmented_memory_context.json` | template wrappers on seeds | deterministic | Expanded gate |
| Review queue | `ml/data/mined_review_queue.json` | boundary cases | pending | manual import only |
| Raw external | `ml/data/external_corpus_raw.json` | full public-corpus dump | none | reference only |

## Key Files

| Path | Purpose |
|------|---------|
| `memgar/analyzer.py` | Core 4-layer analysis engine |
| `memgar/patterns.py` | 736 threat patterns (source of truth) |
| `memgar/feed/verifier.py` | Ed25519 public key for feed verification |
| `memgar/config.py` | `MemgarConfig`, `FeedConfig`, `ObservabilityConfig` |
| `memgar/behavioral_baseline.py` | Layer 4 BehavioralBaseline, SIGNAL_REGISTRY |
| `memgar/retriever.py` | Layer 3 TrustAwareRetriever (standalone RAG) |
| `ml/continuous_learning.py` | AutoRetrainer, StorageManager, DriftDetector |
| `ml/quality_gate.py` | `run_quality_gate()`, `compare_to_baseline()` |
| `ml/adversarial/` | AttackGenerator, VariantCurator |
| `memgar/observability/` | Prometheus metrics, DriftMonitor |
| `memgar/siem.py` | OCSF-compatible SIEM events |
| `scripts/publish_feed.py` | Maintainer tool: sign + publish feed bundle |
| `scripts/red_team_run.py` | CLI: generate + inject adversarial variants |
| `scripts/import_public_corpora.py` | Pull + normalize public datasets (AdvBench, JBB, HarmBench, Gandalf, deepset) |
| `scripts/mine_hard_negatives.py` | Stratify hard subset → auto-merge-safe selection + review queue |
| `scripts/augment_memory_context.py` | Wrap attack seeds in 8 memory-injection envelopes |
| `scripts/merge_corpus.py` | Combine gold + auxiliary corpora (dry-run by default) |
| `scripts/calibrate_fpfn.py` | End-to-end Analyzer evaluation, accepts multiple `--corpus` flags |
| `scripts/check_calibration_gate.py` | Strict gold-only CI gate (8 gates) |
| `scripts/check_expanded_gate.py` | Regression-only merged-corpus gate (6 gates) |
| `feeds/memgar-feed.json.gz` | Signed feed bundle (committed, auto-updated by CI) |

## Configuration

All settings via `MemgarConfig` (YAML file or env vars):

```bash
MEMGAR_FEED_ENABLED=true           # default: true
MEMGAR_FEED_MAX_AGE_DAYS=7
MEMGAR_FEED_GITHUB_REPO=slcxtor/memgar
MEMGAR_OBSERVABILITY_ENABLED=true  # default: false
MEMGAR_OBSERVABILITY_PORT=9090
MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD=0.20
MEMGAR_OBSERVABILITY_DRIFT_WINDOW=1000
MEMGAR_CACHE_DIR=~/.cache/memgar
```

## Security Notes

- **Pickle RCE**: `_RestrictedUnpickler` allowlists only `builtins` + `memgar.models` classes
- **SSRF**: `FeedLoader._ALLOWED_HOSTS` restricts downloads to `github.com` / `*.githubusercontent.com`
- **Gzip bombs**: 20MB compressed / 100MB decompressed hard limits in both `FeedLoader` and `FeedCache`
- **Feed tampering**: Ed25519 signature verified before caching; `FeedSignatureError` raised on mismatch
- **Path traversal**: `MEMGAR_CACHE_DIR` validated to stay within home directory
- **pyo3 panics**: `except BaseException` guards around all `cryptography` imports (system package can panic)
