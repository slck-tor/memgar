"""
Release quality gate for Memgar ML detector.

Fail-fast checks:
- precision >= configured minimum
- recall >= configured minimum
- p95 latency <= configured maximum
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np

from memgar.ml_semantic_detector import MLSemanticDetector
from ml.training.train import XGBoostTrainingPipeline


def _stratified_holdout_indices(
    labels: Sequence[int],
    test_size: float,
    random_state: int,
) -> np.ndarray:
    from sklearn.model_selection import train_test_split  # type: ignore

    idx = np.arange(len(labels))
    y = np.array(labels, dtype=int)
    _, holdout_idx = train_test_split(
        idx,
        test_size=test_size,
        random_state=random_state,
        stratify=y if len(np.unique(y)) > 1 else None,
    )
    return np.array(holdout_idx, dtype=int)


def _measure_latency_ms(detector: MLSemanticDetector, texts: Sequence[str]) -> List[float]:
    timings: List[float] = []
    for text in texts:
        start = time.perf_counter()
        detector.detect(text)
        timings.append((time.perf_counter() - start) * 1000.0)
    return timings


def run_quality_gate(
    model_path: str,
    training_data_path: str,
    min_precision: float,
    min_recall: float,
    max_p95_latency_ms: float,
    max_avg_latency_ms: float,
    threshold: float,
    test_size: float,
    random_state: int,
    latency_sample_size: int,
) -> Tuple[int, Dict[str, Any]]:
    pipeline = XGBoostTrainingPipeline(random_state=random_state)
    texts, labels = pipeline.load_training_data(training_data_path)
    if len(texts) < 200:
        return 90, {
            "status": "error",
            "reason": "insufficient_training_data",
            "sample_count": len(texts),
        }

    holdout_idx = _stratified_holdout_indices(labels, test_size=test_size, random_state=random_state)
    holdout_texts = [texts[i] for i in holdout_idx]
    y_holdout = np.array([labels[i] for i in holdout_idx], dtype=int)
    X_holdout = pipeline.extract_features(holdout_texts, show_progress=False)

    pipeline.load_model(model_path)
    metrics = pipeline.evaluate(
        X_holdout,
        y_holdout,
        threshold=threshold,
        use_calibrated=True,
    )

    latency_n = max(1, min(int(latency_sample_size), len(holdout_texts)))
    detector = MLSemanticDetector(model_path=model_path)
    latency_values = _measure_latency_ms(detector, holdout_texts[:latency_n])
    p95_latency = float(np.percentile(latency_values, 95))
    avg_latency = float(np.mean(latency_values))

    summary: Dict[str, Any] = {
        "status": "ok",
        "samples": {
            "total": len(texts),
            "holdout": int(len(holdout_texts)),
            "latency_sample": latency_n,
        },
        "metrics": {
            "precision": float(metrics.precision),
            "recall": float(metrics.recall),
            "f1": float(metrics.f1_score),
            "accuracy": float(metrics.accuracy),
            "roc_auc": float(metrics.roc_auc),
            "brier": float(metrics.brier_score),
        },
        "latency_ms": {
            "avg": avg_latency,
            "p95": p95_latency,
            "max": float(max(latency_values) if latency_values else 0.0),
        },
        "thresholds": {
            "min_precision": min_precision,
            "min_recall": min_recall,
            "max_p95_latency_ms": max_p95_latency_ms,
            "max_avg_latency_ms": max_avg_latency_ms,
            "decision_threshold": threshold,
        },
    }

    if metrics.precision < min_precision:
        summary["status"] = "failed"
        summary["reason"] = "precision_below_threshold"
        return 2, summary
    if metrics.recall < min_recall:
        summary["status"] = "failed"
        summary["reason"] = "recall_below_threshold"
        return 3, summary
    if p95_latency > max_p95_latency_ms:
        summary["status"] = "failed"
        summary["reason"] = "p95_latency_above_threshold"
        return 4, summary
    if avg_latency > max_avg_latency_ms:
        summary["status"] = "failed"
        summary["reason"] = "avg_latency_above_threshold"
        return 5, summary

    return 0, summary


def compare_to_baseline(
    new_metrics: Dict[str, float],
    baseline_metrics: Dict[str, float],
    max_regression: float = 0.02,
) -> Tuple[bool, Dict[str, Any]]:
    """Compare new metrics against a baseline; reject if regression > max_regression.

    Args:
        new_metrics: dict with at least "precision" and "recall" floats.
        baseline_metrics: previous reference metrics, same shape.
        max_regression: absolute drop allowed before rejecting (default 2%).

    Returns:
        (passed, details) where details contains per-metric deltas.
    """
    details: Dict[str, Any] = {"deltas": {}, "max_regression": max_regression}
    passed = True
    for key in ("precision", "recall"):
        new_v = float(new_metrics.get(key, 0.0))
        base_v = float(baseline_metrics.get(key, 0.0))
        delta = new_v - base_v
        details["deltas"][key] = delta
        if delta < -max_regression:
            passed = False
            details.setdefault("regressions", []).append(key)
    details["passed"] = passed
    return passed, details


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Memgar ML release quality gate")
    parser.add_argument("--model-path", default="ml/artifacts/gradient_boost_model.pkl")
    parser.add_argument("--training-data-path", default="ml/data/training_data.json")
    parser.add_argument("--min-precision", type=float, default=0.94)
    parser.add_argument("--min-recall", type=float, default=0.94)
    parser.add_argument("--max-p95-latency-ms", type=float, default=25.0)
    parser.add_argument("--max-avg-latency-ms", type=float, default=10.0)
    parser.add_argument("--threshold", type=float, default=0.50)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--latency-sample-size", type=int, default=300)
    parser.add_argument(
        "--output-json",
        default="ml/artifacts/quality_gate_report.json",
        help="Write summary JSON for CI artifact/reporting.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    exit_code, summary = run_quality_gate(
        model_path=args.model_path,
        training_data_path=args.training_data_path,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        max_p95_latency_ms=args.max_p95_latency_ms,
        max_avg_latency_ms=args.max_avg_latency_ms,
        threshold=args.threshold,
        test_size=args.test_size,
        random_state=args.random_state,
        latency_sample_size=args.latency_sample_size,
    )

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return int(exit_code)


if __name__ == "__main__":
    sys.exit(main())
