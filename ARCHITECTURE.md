# Memgar Architecture

## Overview

Memgar is a layered security library that intercepts content before it reaches an AI agent's persistent memory. Every piece of content passes through up to four independent detection layers; each layer can independently escalate the risk score.

```
Incoming Content
       │
       ▼
┌──────────────────────────────────────────────┐
│  Layer 1 — Pattern Matching          <1ms    │
│  Aho-Corasick (1,335 keywords)               │
│  Regex patterns (736 compiled)               │
│  Unicode normalization (NFKC)                │
└──────────────────────┬───────────────────────┘
                       │ risk_score += matched weight
                       ▼
┌──────────────────────────────────────────────┐
│  Layer 1.5 — SemanticGuard (optional) ~5ms  │
│  sentence-transformers all-MiniLM-L6-v2      │
│  K-means cluster centroids                   │
│  Sigmoid-calibrated similarity score         │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Layer 2 — LLM Semantic Analysis   ~200ms   │
│  Claude API (optional, use_llm=True)         │
│  Catches obfuscated / indirect attacks       │
│  Independent of Layer 1                      │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Layer 3 — Trust-Aware Scoring      <0.1ms  │
│  Per-source trust registry (0.0–1.0)         │
│  Low trust (<0.3)  → risk ≤+30 pts           │
│  High trust (≥0.8) → borderline −5 pts       │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Layer 4 — Behavioral Baseline       <1ms   │
│  Per-agent EWM baseline on risk/block rate   │
│  SUSPICIOUS (+15) / CRITICAL (+30) deviation │
│  Only amplifies — never flags score=0        │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
                  AnalysisResult
              decision / risk_score / threats
```

---

## Core Components

### Analyzer (`memgar/analyzer.py`)

The central orchestrator. Runs layers 1 → 3 synchronously in `_analyze_internal()`, then applies Layer 4 in `analyze()`. Exposes both sync `analyze()` and async `analyze_async()` (thread-pool backed).

Key methods:
- `analyze(entry: MemoryEntry) → AnalysisResult`
- `analyze_async(entry: MemoryEntry) → AnalysisResult`
- `register_source_trust(source_id, score)` — Layer 3 setup
- `quick_check(content) → bool` — Layer 1 only, no overhead

### Pattern Engine (`memgar/patterns.py` + `memgar/core/`)

- 736 threat patterns loaded from `patterns.py`
- Compiled on first use, then pickle-cached (`~3ms` warm vs `~3500ms` cold)
- Aho-Corasick automaton built over 1,335 keywords in `memgar/core/`
- `_RestrictedUnpickler` allowlist prevents pickle RCE on cache load

### SemanticGuard (`memgar/semantic_guard.py`)

Optional Layer 1.5:
- Embeds content with `all-MiniLM-L6-v2`
- Compares against K-means cluster centroids fitted on known attack embeddings
- Similarity score calibrated with sigmoid: `1 / (1 + exp(-10 * (sim - 0.55)))`
- 84% zero-shot recall on novel attack categories; 0% FPR

### Behavioral Baseline (`memgar/behavioral_baseline.py`)

`BehavioralBaseline` maintains an exponentially weighted moving average (EWM) of two signals per agent:
- `scan_risk_score` — rolling average risk score
- `scan_block_rate` — rolling fraction of blocked entries

`SIGNAL_REGISTRY` maps signal names to weight functions. `BaselineRegistry` is a process-level singleton keyed by `agent_id`.

### MemoryHunter (`memgar/hunter.py`)

Background daemon thread that periodically re-scans all captured entries:

```
MemoryHunter
  ├── memory_provider() → List[MemoryEntry]   (pluggable: SQLite / JSONL / list)
  ├── _stop_event (threading.Event)           (stop() wakes thread immediately)
  ├── _scan_cache (dict)                      (entry_key → Decision, TTL-based)
  └── _stats (HunterStats, lock-protected)
```

Factory constructors map common sources to the `memory_provider` callable abstraction without changing the core loop.

### Memory Stores (`memgar/memory_store.py`)

**`MemoryStore`** — `OrderedDict` ring buffer:
- Dedup by `source_id` (takes priority) or SHA-256[:24] of content
- LRU eviction at `max_entries`; TTL eviction on `get_entries()`

**`PersistentMemoryStore`** — inherits `MemoryStore`, adds:
- Appends every `add()` to a JSONL file (thread-safe `file_lock`)
- Loads history on `__init__` (filtered by `max_age_days`)
- `compact()` rewrites the file keeping only current in-memory entries

---

## Threat Intelligence Feed (`memgar/feed/`)

| Component | File | Role |
|-----------|------|------|
| `FeedLoader` | `loader.py` | Downloads `memgar-feed.json.gz` from GitHub Releases |
| `FeedVerifier` | `verifier.py` | Ed25519 signature verification |
| `FeedCache` | `cache.py` | Disk cache with 20MB/100MB compressed/decompressed limits |
| `FeedManifest` | `models.py` | Version, SHA-256, pattern count metadata |

Feed patterns are merged into the Analyzer's pattern set at startup when `cfg.feed.enabled=True`.

**Security invariants:**
- `_ALLOWED_HOSTS` restricts downloads to `github.com` / `*.githubusercontent.com` (SSRF protection)
- Signature verified before caching; `FeedSignatureError` raised on mismatch
- Gzip bomb guard: 20MB compressed / 100MB decompressed hard limits

---

## Observability (`memgar/observability/`)

Five Prometheus metrics exposed via `start_metrics_server(port=9090)`:

| Metric | Type | Labels |
|--------|------|--------|
| `memgar_analyses_total` | Counter | `decision` |
| `memgar_analysis_latency_seconds` | Histogram | — |
| `memgar_risk_score` | Histogram | — |
| `memgar_drift_severity` | Gauge | — |
| `memgar_model_version` | Gauge | `version` |

`DriftMonitor` runs in a background thread (60s heartbeat). Uses Population Stability Index (PSI) to detect distribution shift in risk scores. Emits OCSF-compatible SIEM events on `psi > drift_threshold`.

OpenTelemetry tracing available via `configure_tracing()` (`memgar/observability/tracing.py`).

---

## Framework Integrations (`memgar/frameworks/`)

### LangChain (`langchain_deep.py`)
- `MemgarSecurityRunnable` — drop-in LCEL chain component
- `MemgarChatMemory` — intercepts `add_user_message()` / `add_ai_message()`
- `SecureVectorStoreRetriever` — wraps any LangChain retriever, filters poisoned docs

### LlamaIndex (`llamaindex_deep.py`)
- `MemgarQueryEngineSecurity` — wraps any query engine
- `MemgarIngestionPipelineSecurity` — filters at ingestion time
- `MemgarNodeFilter` — post-retrieval node filtering

---

## ML System (`ml/`)

```
ml/
├── adversarial/
│   ├── attack_generator.py   # 4 offline mutations + optional Claude API
│   ├── variant_curator.py    # TF-IDF cosine dedup, max 3 per cluster
│   └── hard_negative_miner.py
├── continuous_learning.py    # AutoRetrainer, StorageManager, DriftDetector
├── quality_gate.py           # precision≥0.94, recall≥0.94, P95≤25ms
└── artifacts/
    └── gradient_boost_model.pkl
```

**AutoRetrainer pipeline:** backup → retrain → quality gate → promote or restore.

**Adversarial loop:** `AttackGenerator` produces 4 mutation types (homoglyph Cyrillic, leetspeak, base64, passive rewrite). `VariantCurator` deduplicates with TF-IDF cosine similarity. `HardNegativeMiner` selects near-misses for maximum training value.

---

## Data Flow: Write-Before-Store Pattern

The recommended integration pattern:

```
User Input
    │
    ▼
analyzer.analyze(entry)          # synchronous, <5ms
    │
    ├── Decision.ALLOW  → save to agent memory
    ├── Decision.WARN   → save with flag, alert
    └── Decision.BLOCK  → reject, emit SIEM event
```

For async frameworks:

```python
result = await analyzer.analyze_async(entry)
```

---

## Security Boundary Summary

| Threat | Mitigation |
|--------|-----------|
| Pickle RCE | `_RestrictedUnpickler` allowlists only `builtins` + `memgar.models` |
| SSRF | `FeedLoader._ALLOWED_HOSTS` = `{github.com, *.githubusercontent.com}` |
| Gzip bombs | 20MB compressed / 100MB decompressed limits |
| Feed tampering | Ed25519 signature verified before any caching |
| Path traversal | `MEMGAR_CACHE_DIR` validated to stay within home directory |
| pyo3 panics | `except BaseException` guards around all `cryptography` imports |
| Thread safety | `threading.Lock` on all shared state (MemoryStore, HunterStats, BaselineRegistry) |
