# ML System Documentation

## Overview

Memgar's ML system provides a gradient-boosted classifier as a continuous learning layer that runs alongside the pattern engine. It is not a replacement for Layer 1 — it catches attacks that slip through pattern matching via semantic intent rather than keyword presence.

```
Layer 1: Pattern matching  →  fast, high-recall, interpretable
ML layer: GBM classifier   →  intent-based, handles obfuscation
Combined:                  →  complements each other
```

---

## Model Details

| Property | Value |
|----------|-------|
| Algorithm | XGBoost Gradient Boosting |
| Features | 40 hand-crafted semantic features |
| Training examples | 9,998 |
| Accuracy | 97.92% |
| Precision | ≥0.94 (quality gate) |
| Recall | ≥0.94 (quality gate) |
| Inference latency | ~0.35ms |
| Throughput | ~2,850 req/sec |
| Model file | `ml/artifacts/gradient_boost_model.pkl` |

---

## Feature Engineering

40 features across 4 categories extracted by `ml/feature_extractor.py`:

### Lexical (10 features)
- Word count, character count
- Capitalization ratio (ALL-CAPS words)
- Special character density (`@`, `=`, `;`, etc.)
- Numeric token ratio
- Average word length
- Punctuation density
- URL presence
- Email address presence
- Repeated character sequences

### Syntactic (10 features)
- Command verb count (`send`, `forward`, `execute`, `ignore`, `delete`)
- Imperative sentence structure
- Subordinate clause count (obfuscation signal)
- Passive voice usage
- Modal verb density (`must`, `should`, `will`)
- Negation count
- Question mark presence
- Conditional structure (`if ... then`)
- Enumeration patterns (`1.`, `2.`, etc.)
- Sentence count

### Semantic (10 features)
- Instruction keyword overlap with known attack taxonomy
- System/role keyword density (`system`, `assistant`, `admin`, `root`)
- Role-play indicator presence (`act as`, `pretend`, `you are now`)
- Context switch signals (`from now on`, `going forward`, `forget`)
- Authority claim score (`I am your`, `your new`, `new directive`)
- Sensitive data references (`password`, `token`, `key`, `credentials`)
- Exfiltration target presence (email, URL, external domain)
- Financial instrument references (IBAN, routing, wallet)
- Persistence trigger patterns (`always`, `every time`, `whenever`)
- Bypass/evasion indicators (`ignore`, `disregard`, `override`)

### Behavioral (10 features)
- Urgency marker count (`immediately`, `now`, `urgent`)
- Threat or coercion language
- Reward/flattery manipulation (`good job`, `well done`, `excellent`)
- Social engineering patterns
- Scarcity / deadline framing
- Authority escalation (fake hierarchy claims)
- Confusion injection (contradictory instructions)
- Memory tampering language (`remember`, `update your memory`)
- Scope expansion (`and also`, `additionally`, `furthermore`)
- Multi-step instruction chaining

---

## Zero-Shot Generalization

The SemanticGuard module (`memgar/semantic_guard.py`) extends detection to novel attack categories using embedding similarity rather than trained features.

**Benchmark results** (`scripts/zero_shot_benchmark.py`):

| Attack Category | Recall |
|----------------|--------|
| Sleeper payload triggers | 100% |
| Memory schema manipulation | 100% |
| Cross-agent relay attacks | 100% |
| Recursive self-modification | 100% |
| Cognitive load injection | 100% |
| Time-delayed persistence | 83% |
| Emotional manipulation | 67% |
| Indirect exfiltration | 67% |
| Steganographic encoding | 50% |
| Voice/persona phishing | 17% |
| **Aggregate (10 categories)** | **84%** |
| False positive rate (20 benign texts) | **0%** |

Gate thresholds: recall ≥ 60%, FPR ≤ 10%.

---

## Adversarial Red-Team Loop (`ml/adversarial/`)

The red-team pipeline automatically generates attack variants that evade current detection and injects them as hard negatives for the next training run.

```
AttackGenerator
    │  4 offline mutations per seed:
    │  1. Homoglyph substitution (Cyrillic lookalikes)
    │  2. Leetspeak encoding (a→4, e→3, i→1, o→0, s→5)
    │  3. Base64 payload wrapping
    │  4. Passive-voice rewrite
    │  (+ optional Claude API for semantic rewrites)
    ▼
VariantCurator
    │  TF-IDF cosine dedup (threshold=0.85)
    │  max_variants_per_cluster=3
    ▼
HardNegativeMiner
    │  Score each variant with current model
    │  Keep only near-misses (score 40–70)
    ▼
adversarial_variants.jsonl  (append)
    │
    ▼
AutoRetrainer.retrain()
```

### CLI usage

```bash
# Dry run — see what would be generated
python scripts/red_team_run.py --n-seeds 10 --n-variants 5 --dry-run --offline

# Full run — generate, inject, rebuild model
python scripts/red_team_run.py --n-seeds 10 --n-variants 5
python rebuild_model.py
```

---

## Continuous Learning (`ml/continuous_learning.py`)

### AutoRetrainer

```python
from ml.continuous_learning import AutoRetrainer

retrainer = AutoRetrainer()
result = retrainer.retrain()
# result.promoted → True if model passed quality gate
# result.metrics  → {precision, recall, p95_latency_ms}
```

Pipeline:
1. Backup current model (`ml/artifacts/gradient_boost_model.pkl.bak`)
2. Retrain on updated dataset
3. Run quality gate (precision ≥ 0.94, recall ≥ 0.94, P95 ≤ 25ms)
4. Compare against baseline — reject if regression > 2%
5. Promote or restore backup

### StorageManager

`StorageManager.save_prediction()` is called automatically by `Analyzer.analyze()` for every prediction. Predictions are written to `ml/predictions.jsonl` and used as training signal.

### DriftDetector

PSI-based drift detection over the rolling prediction distribution. Alerts via SIEM when `psi > 0.20`.

---

## Quality Gate (`ml/quality_gate.py`)

```python
from ml.quality_gate import run_quality_gate, compare_to_baseline

metrics = run_quality_gate(model_path="ml/artifacts/gradient_boost_model.pkl")
# metrics = {"precision": 0.9792, "recall": 0.9750, "p95_latency_ms": 18.3}

ok = compare_to_baseline(
    new_metrics=metrics,
    baseline_metrics={"precision": 0.9750, "recall": 0.9720, "p95_latency_ms": 20.0},
    max_regression=0.02,
)
# ok = True if no metric regresses more than 2%
```

Gates:
- Precision ≥ 0.94
- Recall ≥ 0.94
- P95 latency ≤ 25ms
- Max regression vs baseline: 2%

---

## Rebuilding the Model

```bash
# Standard rebuild
python rebuild_model.py

# With verbose output
python rebuild_model.py --verbose

# After injecting adversarial variants
python scripts/red_team_run.py --n-seeds 20 --n-variants 10
python rebuild_model.py
```

The script:
1. Loads `ml/artifacts/training_data.jsonl` + `adversarial_variants.jsonl`
2. Extracts 40 features from each example
3. Trains XGBoost classifier with cross-validation
4. Runs quality gate — aborts if thresholds not met
5. Writes new `gradient_boost_model.pkl` with config JSON

---

## Limitations

- **Training data is primarily English.** Non-English injections may have lower recall.
- **Adversarial variants use offline mutations only** (unless `--use-claude` is passed). LLM-generated rewrites require an Anthropic API key.
- **ML layer is optional** — `Analyzer(use_llm=False)` runs Layer 1 + 3 + 4 only. The gradient boost model is separate from the LLM layer.
- **Model file must exist** — if `ml/artifacts/gradient_boost_model.pkl` is absent, ML-dependent tests skip automatically.
