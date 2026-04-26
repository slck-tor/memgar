#!/usr/bin/env python3
"""
Rebuild ML model from local training data with quality-gate enforcement.
"""

import os
import sys

import numpy as np

from ml.training.train import XGBoostTrainingPipeline


def rebuild_model(
    training_data_path: str = "ml/data/training_data.json",
    output_path: str = "ml/artifacts/gradient_boost_model.pkl",
    enforce_quality_gate: bool = True,
):
    if not os.path.exists(training_data_path):
        print(f"Training data not found: {training_data_path}")
        return None

    pipeline = XGBoostTrainingPipeline(
        random_state=42,
        estimator="auto",
        calibrate_method="isotonic",
    )

    texts, labels = pipeline.load_training_data(training_data_path)
    y = np.array(labels)
    X = pipeline.extract_features(texts, show_progress=False)
    X_train, X_tmp, y_train, y_tmp = pipeline.split_data(X, y, test_size=0.3)
    X_val, X_test, y_val, y_test = pipeline.split_data(X_tmp, y_tmp, test_size=0.5)

    pipeline.train_xgboost(X_train, y_train, X_val, y_val, calibrate=True)
    metrics = pipeline.evaluate(X_test, y_test, threshold=0.5, use_calibrated=True)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    pipeline.save_model(output_path)

    print("Model rebuilt")
    print(f"  Accuracy:  {metrics.accuracy:.4f}")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall:    {metrics.recall:.4f}")
    print(f"  F1 Score:  {metrics.f1_score:.4f}")
    print(f"  Output:    {output_path}")

    if enforce_quality_gate:
        from ml.quality_gate import run_quality_gate

        exit_code, summary = run_quality_gate(
            model_path=output_path,
            training_data_path=training_data_path,
            min_precision=0.94,
            min_recall=0.94,
            max_p95_latency_ms=25.0,
            max_avg_latency_ms=10.0,
            threshold=0.5,
            test_size=0.20,
            random_state=42,
            latency_sample_size=300,
        )
        if exit_code != 0:
            print(f"Quality gate FAILED (exit={exit_code}): {summary.get('reason')}")
            sys.exit(exit_code)
        print(f"Quality gate PASSED (precision={summary['metrics']['precision']:.4f}, recall={summary['metrics']['recall']:.4f})")

    return output_path


if __name__ == "__main__":
    rebuild_model()
