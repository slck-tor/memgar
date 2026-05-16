#!/usr/bin/env python3
"""
CI gate: read ml/artifacts/fpfn_calibration.json and assert minimum
quality metrics. Exits with code 1 (failing the CI step) if any
threshold is breached, printing a human-readable diff table.

Thresholds are intentionally conservative: they catch regressions early
without requiring the corpus to be perfect. Raise them as the corpus grows.

Usage:
    python scripts/check_calibration_gate.py
    python scripts/check_calibration_gate.py --report path/to/fpfn.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Minimum metric thresholds — edit these as the corpus and model mature.
# ---------------------------------------------------------------------------

GATES: dict[str, dict] = {
    # Overall (all languages combined, Decision.block used as positive label)
    "overall_attack_recall": {
        "path": ("analyzer_default_metrics", "block_rate_attack"),
        "min": 0.55,
        "label": "Overall attack recall (block_rate_attack)",
    },
    "overall_benign_fpr": {
        "path": ("analyzer_default_metrics", "block_rate_benign"),
        "max": 0.15,
        "label": "Overall benign FPR (block_rate_benign)",
    },
    # Per-language — English (should be strongest)
    "en_recall": {
        "path": ("per_language", "en", "recall"),
        "min": 0.80,
        "label": "English recall",
    },
    "en_fpr": {
        "path": ("per_language", "en", "fpr"),
        "max": 0.10,
        "label": "English FPR",
    },
    # Per-language — Turkish
    "tr_recall": {
        "path": ("per_language", "tr", "recall"),
        "min": 0.30,
        "label": "Turkish recall (expect to rise as patterns improve)",
    },
    "tr_fpr": {
        "path": ("per_language", "tr", "fpr"),
        "max": 0.20,
        "label": "Turkish FPR",
    },
    # Per-category — worst performers must stay above floor
    "cat_manipulation_recall": {
        "path": ("per_category_recall", "manipulation", "recall"),
        "min": 0.30,
        "label": "Manipulation category recall",
    },
    "cat_exfiltration_recall": {
        "path": ("per_category_recall", "exfiltration", "recall"),
        "min": 0.35,
        "label": "Exfiltration category recall",
    },
}


def _get(report: dict, *path: str) -> float | None:
    obj = report
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return float(obj) if obj is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--report",
        default="ml/artifacts/fpfn_calibration.json",
        help="Path to calibration JSON report",
    )
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = Path(__file__).resolve().parent.parent / args.report

    if not report_path.exists():
        print(f"ERROR: calibration report not found at {report_path}")
        print("Run first: python scripts/calibrate_fpfn.py")
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))

    # Check n_samples sanity — a tiny corpus makes the gates meaningless.
    n = report.get("n_samples", 0)
    if n < 50:
        print(f"ERROR: corpus too small ({n} samples). Need ≥50 for meaningful gates.")
        return 1

    failures: list[str] = []
    rows: list[tuple[str, str, str, str]] = []  # (label, actual, threshold, status)

    for gate_id, cfg in GATES.items():
        actual = _get(report, *cfg["path"])
        label = cfg["label"]

        if actual is None:
            rows.append((label, "N/A", "—", "SKIP"))
            continue

        if "min" in cfg:
            threshold = f"≥{cfg['min']:.2f}"
            if actual < cfg["min"]:
                failures.append(f"{label}: {actual:.3f} < {cfg['min']:.2f}")
                rows.append((label, f"{actual:.3f}", threshold, "FAIL"))
            else:
                rows.append((label, f"{actual:.3f}", threshold, "PASS"))
        else:
            threshold = f"≤{cfg['max']:.2f}"
            if actual > cfg["max"]:
                failures.append(f"{label}: {actual:.3f} > {cfg['max']:.2f}")
                rows.append((label, f"{actual:.3f}", threshold, "FAIL"))
            else:
                rows.append((label, f"{actual:.3f}", threshold, "PASS"))

    # Print table
    col_w = max(len(r[0]) for r in rows) + 2
    print()
    print(f"{'Metric':<{col_w}}  {'Actual':>8}  {'Threshold':>12}  Status")
    print("-" * (col_w + 36))
    for label, actual, threshold, status in rows:
        marker = "✗" if status == "FAIL" else ("·" if status == "SKIP" else "✓")
        print(f"{label:<{col_w}}  {actual:>8}  {threshold:>12}  {marker} {status}")
    print()
    print(f"Corpus: {report.get('n_samples')} samples "
          f"({report.get('n_attack')} attack, {report.get('n_benign')} benign) — "
          f"{report.get('generated_at', 'unknown date')}")

    if failures:
        print()
        print(f"GATE FAILED ({len(failures)} check(s)):")
        for f in failures:
            print(f"  ✗ {f}")
        print()
        print("Fix options:")
        print("  1. Add/strengthen patterns:  python scripts/calibrate_fpfn.py")
        print("  2. Expand the corpus:        edit ml/data/calibration_corpus.json")
        print("  3. Lower the gate threshold: edit scripts/check_calibration_gate.py (document why)")
        return 1

    print("All gates PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
