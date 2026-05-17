# Calibration

Memgar's FP/FN behaviour is measured by `scripts/calibrate_fpfn.py`. It runs
the full `Analyzer.analyze()` pipeline against a labelled corpus and reports
threshold sweeps, per-language confusion matrices, per-category recall,
and recommended thresholds for strict / balanced / precision profiles.

## Two-tier gate

| Gate | Corpus | Thresholds | Status |
|---|---|---|---|
| `check_calibration_gate.py` | Gold (95) | 8 strict | Must always PASS |
| `check_expanded_gate.py` | Merged (464) | 6 regression-only | Tracks real-world performance |

## Running locally

### Gold gate (strict)

```bash
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --output ml/artifacts/fpfn_calibration.json \
    --no-llm

python scripts/check_calibration_gate.py
```

Sample output:

```
Metric                                                   Actual     Threshold  Status
-----------------------------------------------------------------------------------------
Overall attack recall (block_rate_attack)                 0.800         ≥0.55  ✓ PASS
Overall benign FPR (block_rate_benign)                    0.091         ≤0.15  ✓ PASS
English recall                                            1.000         ≥0.80  ✓ PASS
English FPR                                               0.040         ≤0.10  ✓ PASS
Turkish recall (expect to rise as patterns improve)       0.600         ≥0.30  ✓ PASS
Turkish FPR                                               0.133         ≤0.20  ✓ PASS
Manipulation category recall                              0.750         ≥0.30  ✓ PASS
Exfiltration category recall                              0.909         ≥0.35  ✓ PASS

All gates PASSED.
```

### Expanded gate (regression-only)

```bash
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --corpus ml/data/mined_hard_subset.json \
    --corpus ml/data/augmented_memory_context.json \
    --output ml/artifacts/fpfn_calibration_expanded.json \
    --no-llm

python scripts/check_expanded_gate.py
```

Sample output:

```
Expanded Metric                                                   Actual     Threshold  Status
--------------------------------------------------------------------------------------------------
Expanded corpus overall attack recall                              0.798        >=0.70  v PASS
Expanded English recall (gold + memory-context + mined)            0.809        >=0.72  v PASS
Memory-context-wrapped attack recall (memgar's unique angle)       0.809        >=0.80  v PASS
Expanded exfiltration recall                                       0.891        >=0.75  v PASS
Expanded manipulation recall                                       0.805        >=0.70  v PASS
Expanded prompt_injection recall                                   0.878        >=0.70  v PASS

All expanded gates PASSED.
```

## What the report contains

`fpfn_calibration.json` schema:

```python
{
  "n_samples": 95,
  "n_attack": 40,
  "n_benign": 55,
  "analyzer_default_metrics": {
    "tp": 32, "fp": 5, "tn": 50, "fn": 8,
    "precision": 0.865,
    "recall":    0.800,
    "block_rate_attack": 0.800,
    "block_rate_benign": 0.091,
  },
  "per_language": {
    "en": {"n": 45, "tp": ..., "fp": ..., "recall": 1.000, "fpr": 0.040, ...},
    "tr": {"n": 50, ...},
  },
  "per_category_recall": {
    "manipulation": {"n": 8, "blocked": 6, "recall": 0.750, "missed_examples": [...]},
    "exfiltration": {"n": 11, "blocked": 10, "recall": 0.909, "missed_examples": [...]},
    ...
  },
  "threshold_sweep": [
    {"threshold": 0, "precision": 0.421, "recall": 1.0, "f1": 0.593, "fpr": 1.0},
    ...
    {"threshold": 100, "precision": 1.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0},
  ],
  "recommended_thresholds": {
    "strict":    {"threshold": 0,  "precision": 0.421, "recall": 1.0, "f1": 0.593, "fpr": 1.0},
    "balanced":  {"threshold": 78, "precision": 0.872, "recall": 0.85, "f1": 0.861, "fpr": 0.091},
    "precision": null,
  },
}
```

## Adding samples

1. Open `ml/data/calibration_corpus.json` (gold only — auxiliary corpora are
   auto-generated).
2. Append a row with the schema:
   ```json
   {"text": "...", "label": 1, "language": "en", "category": "exfiltration"}
   ```
3. Run the gold gate locally — every threshold must PASS.
4. Open a PR.

## When the gate regresses

If your change drops a threshold:

1. Investigate **why** — usually a pattern over-flagged or under-fired on
   the new sample.
2. Fix the pattern OR remove the test sample if it's truly out-of-scope
   (e.g. content-moderation rather than memory-poisoning).
3. Re-run; do not lower the gate threshold unless explicitly documented and
   approved.
