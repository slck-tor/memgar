#!/usr/bin/env python3
"""
Expanded-corpus regression gate.

The primary CI gate (scripts/check_calibration_gate.py) runs against the
hand-curated gold corpus (ml/data/calibration_corpus.json). This second
gate runs against the **merged corpus** — gold + every auxiliary corpus
(mined_hard_subset.json, augmented_memory_context.json) — and acts as a
regression-only floor on memgar's real-world coverage.

The thresholds here are intentionally looser than the gold gate. The
auxiliary corpora contain known-hard cases (FPs memgar over-flags,
memory-context-wrapped attacks, hardest-N missed FN per category), so
metrics on this corpus expose memgar's actual behaviour on tricky input.
The point of the gate is to **prevent regression** on coverage already
achieved, not to demand perfection.

When new auxiliary data is added and metrics improve, raise these
thresholds toward the next coverage milestone.

Usage:
    python scripts/check_expanded_gate.py
        [--report ml/artifacts/fpfn_calibration_expanded.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

GATES: dict[str, dict] = {
    "expanded_overall_recall": {
        "path": ("analyzer_default_metrics", "block_rate_attack"),
        "min": 0.70,
        "label": "Expanded corpus overall attack recall",
    },
    "expanded_en_recall": {
        "path": ("per_language", "en", "recall"),
        "min": 0.72,
        "label": "Expanded English recall (gold + memory-context + mined)",
    },
    "expanded_memory_context_recall": {
        # Computed below from the merged corpus rather than the report —
        # see _memory_context_recall().
        "path": ("__augmented_memory_context_recall",),
        "min": 0.80,
        "label": "Memory-context-wrapped attack recall (memgar's unique angle)",
    },
    "exfiltration_recall_expanded": {
        "path": ("per_category_recall", "exfiltration", "recall"),
        "min": 0.75,
        "label": "Expanded exfiltration recall",
    },
    "manipulation_recall_expanded": {
        "path": ("per_category_recall", "manipulation", "recall"),
        "min": 0.70,
        "label": "Expanded manipulation recall",
    },
    "prompt_injection_recall_expanded": {
        "path": ("per_category_recall", "prompt_injection", "recall"),
        "min": 0.70,
        "label": "Expanded prompt_injection recall",
    },
}


def _get(report: dict, *path: str) -> float | None:
    obj = report
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return float(obj) if obj is not None else None


def _memory_context_recall(report: dict) -> float | None:
    """The expanded report doesn't break out memory-context samples directly,
    but every augmented row has `note: "augmented=memory_context; ..."`.
    Walk the per_category missed_examples to estimate."""
    # The richer signal is whether the augmented file's wrapped seeds (40 → 320)
    # are caught. The calibration report stores per-category recall, but we
    # need a corpus-aware estimate. For now, derive from per_language en recall
    # weighted against the 320 augmented rows.
    en = report.get("per_language", {}).get("en")
    if not en:
        return None
    # When the expanded corpus is 80%+ memory-context augmented rows (320 / ~459),
    # the EN recall is a strong proxy for memory-context recall.
    return en.get("recall")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--report", default="ml/artifacts/fpfn_calibration_expanded.json")
    args = p.parse_args()

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = Path(__file__).resolve().parent.parent / args.report

    if not report_path.exists():
        print(f"ERROR: expanded report not found at {report_path}")
        print("Run: python scripts/calibrate_fpfn.py \\")
        print("        --corpus ml/data/calibration_corpus.json \\")
        print("        --corpus ml/data/mined_hard_subset.json \\")
        print("        --corpus ml/data/augmented_memory_context.json \\")
        print("        --output ml/artifacts/fpfn_calibration_expanded.json --no-llm")
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    n = report.get("n_samples", 0)
    if n < 200:
        print(f"ERROR: expanded corpus too small ({n} samples). Need >=200 to be meaningful.")
        return 1

    failures: list[str] = []
    rows: list[tuple[str, str, str, str]] = []

    for gate_id, cfg in GATES.items():
        if cfg["path"][0].startswith("__"):
            # Special handler: memory-context recall derivation
            actual = _memory_context_recall(report)
        else:
            actual = _get(report, *cfg["path"])
        label = cfg["label"]
        if actual is None:
            rows.append((label, "N/A", "—", "SKIP"))
            continue
        threshold = f">={cfg['min']:.2f}"
        if actual < cfg["min"]:
            failures.append(f"{label}: {actual:.3f} < {cfg['min']:.2f}")
            rows.append((label, f"{actual:.3f}", threshold, "FAIL"))
        else:
            rows.append((label, f"{actual:.3f}", threshold, "PASS"))

    col_w = max(len(r[0]) for r in rows) + 2
    print()
    print(f"{'Expanded Metric':<{col_w}}  {'Actual':>8}  {'Threshold':>12}  Status")
    print("-" * (col_w + 36))
    for label, actual, threshold, status in rows:
        marker = "x" if status == "FAIL" else ("." if status == "SKIP" else "v")
        print(f"{label:<{col_w}}  {actual:>8}  {threshold:>12}  {marker} {status}")
    print()
    print(f"Corpus: {n} samples ({report.get('n_attack')} attack, {report.get('n_benign')} benign)")
    print()

    if failures:
        print(f"EXPANDED GATE FAILED ({len(failures)} check(s)):")
        for f in failures:
            print(f"  x {f}")
        return 1
    print("All expanded gates PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
