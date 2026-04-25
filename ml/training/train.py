"""
Production training pipeline for Memgar semantic ML detector.

Highlights:
- Gradient Boosting (or LightGBM when available) training
- Probability calibration (isotonic / sigmoid)
- Hard-negative augmentation support
- Backwards-compatible API with existing scripts/tests
"""

from __future__ import annotations

import json
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ml.training.ml_feature_extractor import FeatureVector, MLFeatureExtractor
from ml.training.hard_negative_miner import merge_training_examples


def _maybe_import_lightgbm():
    try:
        from lightgbm import LGBMClassifier  # type: ignore
        return LGBMClassifier
    except Exception:
        return None


def _require_sklearn():
    from sklearn.calibration import CalibratedClassifierCV  # type: ignore
    from sklearn.ensemble import GradientBoostingClassifier  # type: ignore
    from sklearn.metrics import (  # type: ignore
        log_loss,
        roc_auc_score,
    )
    from sklearn.model_selection import StratifiedKFold, train_test_split  # type: ignore
    return (
        GradientBoostingClassifier,
        CalibratedClassifierCV,
        train_test_split,
        StratifiedKFold,
        log_loss,
        roc_auc_score,
    )


@dataclass
class TrainingExample:
    """Single training row."""

    text: str
    label: int
    category: str = "unknown"
    subcategory: str = "unknown"
    confidence: float = 1.0
    source: str = "dataset"
    weight: float = 1.0


@dataclass
class ModelMetrics:
    """Evaluation metrics for binary classifier."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    brier_score: float = 0.0
    roc_auc: float = 0.0
    log_loss: float = 0.0


class XGBoostTrainingPipeline:
    """
    Backwards-compatible training pipeline.

    Name retained for compatibility; estimator can be:
    - auto (LightGBM when available, else GradientBoosting)
    - lightgbm
    - gradient_boosting
    """

    def __init__(
        self,
        random_state: int = 42,
        estimator: str = "auto",
        calibrate_method: str = "isotonic",
        min_calibration_samples: int = 250,
    ):
        self.random_state = random_state
        self.estimator_name = estimator
        self.calibrate_method = calibrate_method
        self.min_calibration_samples = min_calibration_samples

        self.feature_extractor = MLFeatureExtractor()
        self.model = None
        self.calibrated_model = None
        self.feature_importance: Dict[str, float] = {}
        self.training_history: List[Dict[str, Any]] = []

    # ---------------------------------------------------------------------
    # Data loading
    # ---------------------------------------------------------------------

    def load_training_examples(self, filename: str) -> List[TrainingExample]:
        """Load rich training examples from JSON file."""
        with open(filename, "r", encoding="utf-8") as f:
            raw = json.load(f)

        examples: List[TrainingExample] = []
        for row in raw:
            examples.append(
                TrainingExample(
                    text=str(row.get("text", "")),
                    label=int(row.get("label", 0)),
                    category=str(row.get("category", "unknown")),
                    subcategory=str(row.get("subcategory", "unknown")),
                    confidence=float(row.get("confidence", 1.0)),
                    source=str(row.get("source", "dataset")),
                    weight=float(row.get("weight", 1.0)),
                )
            )
        return examples

    def load_training_data(self, filename: str) -> Tuple[List[str], List[int]]:
        """
        Backwards-compatible loader returning (texts, labels).
        """
        examples = self.load_training_examples(filename)
        texts = [ex.text for ex in examples]
        labels = [ex.label for ex in examples]
        return texts, labels

    def extract_features(self, texts: List[str], show_progress: bool = True) -> np.ndarray:
        """Extract numeric feature matrix."""
        features_list: List[np.ndarray] = []
        start_time = time.time()
        total = max(1, len(texts))

        for i, text in enumerate(texts):
            if show_progress and (i + 1) % 2000 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / max(1e-9, elapsed)
                remaining = (total - i - 1) / max(1e-9, rate)
                print(f"  Progress: {i+1}/{total} ({(i+1)/total*100:.1f}%) ETA: {remaining:.1f}s")

            fv = self.feature_extractor.extract(text)
            features_list.append(fv.to_numpy())

        if not features_list:
            return np.zeros((0, len(FeatureVector().to_numpy())), dtype=np.float32)
        return np.vstack(features_list)

    def split_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Stratified train/test split."""
        (
            _GradientBoostingClassifier,
            _CalibratedClassifierCV,
            train_test_split,
            _StratifiedKFold,
            _log_loss,
            _roc_auc_score,
        ) = _require_sklearn()
        return train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=self.random_state,
            stratify=y if len(np.unique(y)) > 1 else None,
        )

    # ---------------------------------------------------------------------
    # Training / calibration
    # ---------------------------------------------------------------------

    def _build_estimator(self, params: Optional[Dict[str, Any]] = None):
        (
            GradientBoostingClassifier,
            _CalibratedClassifierCV,
            _train_test_split,
            _StratifiedKFold,
            _log_loss,
            _roc_auc_score,
        ) = _require_sklearn()

        params = dict(params or {})
        estimator_name = (self.estimator_name or "auto").lower()
        if estimator_name == "auto":
            estimator_name = "lightgbm" if _maybe_import_lightgbm() is not None else "gradient_boosting"

        if estimator_name == "lightgbm":
            LGBMClassifier = _maybe_import_lightgbm()
            if LGBMClassifier is not None:
                defaults = {
                    "n_estimators": 220,
                    "learning_rate": 0.06,
                    "max_depth": -1,
                    "num_leaves": 31,
                    "subsample": 0.9,
                    "colsample_bytree": 0.9,
                    "random_state": self.random_state,
                }
                defaults.update(params)
                return LGBMClassifier(**defaults)

        # Fallback and default: sklearn GradientBoostingClassifier
        defaults = {
            "n_estimators": 140,
            "max_depth": 3,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "random_state": self.random_state,
        }
        defaults.update(params)
        return GradientBoostingClassifier(**defaults)

    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        params: Optional[Dict[str, Any]] = None,
        sample_weight: Optional[np.ndarray] = None,
        calibrate: bool = True,
    ):
        """
        Backwards-compatible training entrypoint.
        """
        start = time.time()
        self.model = self._build_estimator(params=params)
        fit_kwargs: Dict[str, Any] = {}
        if sample_weight is not None:
            fit_kwargs["sample_weight"] = sample_weight
        self.model.fit(X_train, y_train, **fit_kwargs)

        self.calibrated_model = None
        if calibrate and X_val is not None and y_val is not None:
            self.calibrate_model(X_val, y_val)

        self.feature_importance = self._extract_feature_importance()
        self.training_history.append(
            {
                "timestamp": time.time(),
                "duration_sec": round(time.time() - start, 3),
                "estimator": type(self.model).__name__,
                "calibrated": self.calibrated_model is not None,
                "train_samples": int(len(X_train)),
                "val_samples": int(len(X_val)) if X_val is not None else 0,
            }
        )
        return self.model

    def calibrate_model(self, X_cal: np.ndarray, y_cal: np.ndarray, method: Optional[str] = None):
        """Calibrate probabilities with isotonic/sigmoid."""
        (
            _GradientBoostingClassifier,
            CalibratedClassifierCV,
            _train_test_split,
            _StratifiedKFold,
            _log_loss,
            _roc_auc_score,
        ) = _require_sklearn()

        if self.model is None:
            return None
        if len(y_cal) < self.min_calibration_samples:
            return None
        if len(np.unique(y_cal)) < 2:
            return None

        selected_method = (method or self.calibrate_method or "isotonic").lower()
        if selected_method not in {"isotonic", "sigmoid"}:
            selected_method = "isotonic"

        # sklearn <1.6 accepts prefit via cv="prefit". Newer versions require
        # a FrozenEstimator wrapper and cv=None for prefit calibration.
        calibrated = None
        try:
            calibrated = CalibratedClassifierCV(
                estimator=self.model,
                method=selected_method,
                cv="prefit",
            )
            calibrated.fit(X_cal, y_cal)
        except Exception:
            try:
                from sklearn.frozen import FrozenEstimator  # type: ignore

                frozen_estimator = FrozenEstimator(self.model)
                calibrated = CalibratedClassifierCV(
                    estimator=frozen_estimator,
                    method=selected_method,
                    cv=None,
                )
                calibrated.fit(X_cal, y_cal)
            except Exception:
                calibrated = None

        self.calibrated_model = calibrated
        return calibrated

    # ---------------------------------------------------------------------
    # Evaluation
    # ---------------------------------------------------------------------

    def _predict_proba(self, X: np.ndarray, use_calibrated: bool = True) -> np.ndarray:
        model = self.calibrated_model if (use_calibrated and self.calibrated_model is not None) else self.model
        if model is None:
            raise RuntimeError("Model has not been trained.")
        return model.predict_proba(X)[:, 1]

    def evaluate(self, X: np.ndarray, y: np.ndarray, threshold: float = 0.5, use_calibrated: bool = True) -> ModelMetrics:
        """Evaluate model with thresholded decisions + probability metrics."""
        (
            _GradientBoostingClassifier,
            _CalibratedClassifierCV,
            _train_test_split,
            _StratifiedKFold,
            log_loss,
            roc_auc_score,
        ) = _require_sklearn()

        y_prob = self._predict_proba(X, use_calibrated=use_calibrated)
        y_pred = (y_prob >= threshold).astype(int)

        tp = int(np.sum((y == 1) & (y_pred == 1)))
        tn = int(np.sum((y == 0) & (y_pred == 0)))
        fp = int(np.sum((y == 0) & (y_pred == 1)))
        fn = int(np.sum((y == 1) & (y_pred == 0)))

        total = max(1, len(y))
        accuracy = (tp + tn) / total
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        brier = float(np.mean((y_prob - y) ** 2))

        auc = 0.0
        ll = 0.0
        if len(np.unique(y)) > 1:
            auc = float(roc_auc_score(y, y_prob))
            ll = float(log_loss(y, np.vstack([1.0 - y_prob, y_prob]).T))

        return ModelMetrics(
            accuracy=float(accuracy),
            precision=float(precision),
            recall=float(recall),
            f1_score=float(f1),
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            brier_score=brier,
            roc_auc=auc,
            log_loss=ll,
        )

    def cross_validate(self, X: np.ndarray, y: np.ndarray, n_folds: int = 5) -> List[ModelMetrics]:
        """Stratified k-fold validation."""
        (
            _GradientBoostingClassifier,
            _CalibratedClassifierCV,
            _train_test_split,
            StratifiedKFold,
            _log_loss,
            _roc_auc_score,
        ) = _require_sklearn()

        fold_metrics: List[ModelMetrics] = []
        splitter = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=self.random_state)
        for train_idx, val_idx in splitter.split(X, y):
            model = self._build_estimator()
            model.fit(X[train_idx], y[train_idx])
            self.model = model
            self.calibrated_model = None
            fold_metrics.append(self.evaluate(X[val_idx], y[val_idx], threshold=0.5, use_calibrated=False))
        return fold_metrics

    # ---------------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------------

    def _extract_feature_importance(self) -> Dict[str, float]:
        if self.model is None:
            return {}
        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            return {}
        return {f"f{i}": float(v) for i, v in enumerate(importances)}

    def save_model(self, filename: str):
        """
        Save model for runtime compatibility.

        Runtime expects a pickled estimator with .predict_proba, so we store the
        calibrated estimator when available, otherwise base model.
        """
        if self.model is None:
            raise RuntimeError("No model to save. Train first.")

        target = self.calibrated_model if self.calibrated_model is not None else self.model
        with open(filename, "wb") as f:
            pickle.dump(target, f)

        config = {
            "schema_version": 2,
            "estimator": type(self.model).__name__,
            "calibrated_estimator": type(target).__name__,
            "is_calibrated": self.calibrated_model is not None,
            "calibration_method": self.calibrate_method if self.calibrated_model is not None else None,
            "random_state": self.random_state,
            "n_features": len(FeatureVector().to_numpy()),
            "feature_names": FeatureVector().get_feature_names(),
            "feature_importance": self.feature_importance,
            "training_history": self.training_history[-5:],
        }
        with open(f"{filename}.config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    def load_model(self, filename: str):
        """Load runtime model (calibrated or base estimator)."""
        with open(filename, "rb") as f:
            loaded = pickle.load(f)
        self.model = loaded
        self.calibrated_model = loaded
        return loaded

    # ---------------------------------------------------------------------
    # Data augmentation hooks
    # ---------------------------------------------------------------------

    def augment_with_hard_negatives(
        self,
        base_examples: Sequence[TrainingExample],
        hard_negative_examples: Sequence[TrainingExample],
        max_negative_ratio: float = 0.35,
    ) -> List[TrainingExample]:
        """Merge dataset while preventing negative-class explosion."""
        return merge_training_examples(
            list(base_examples),
            list(hard_negative_examples),
            max_added_negative_ratio=max_negative_ratio,
        )


def main():
    """
    Basic CLI runner:
      python -m ml.training.train
    """
    data_path = Path("ml/data/training_data.json")
    out_path = Path("ml/artifacts/gradient_boost_model.pkl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not data_path.exists():
        raise FileNotFoundError(f"Training dataset not found: {data_path}")

    pipeline = XGBoostTrainingPipeline(random_state=42, estimator="auto", calibrate_method="isotonic")
    examples = pipeline.load_training_examples(str(data_path))
    texts = [e.text for e in examples]
    labels = np.array([e.label for e in examples], dtype=np.int64)

    X = pipeline.extract_features(texts, show_progress=True)
    X_train, X_tmp, y_train, y_tmp = pipeline.split_data(X, labels, test_size=0.3)
    X_val, X_test, y_val, y_test = pipeline.split_data(X_tmp, y_tmp, test_size=0.5)

    pipeline.train_xgboost(X_train, y_train, X_val, y_val, calibrate=True)
    metrics = pipeline.evaluate(X_test, y_test, threshold=0.5, use_calibrated=True)
    pipeline.save_model(str(out_path))

    print("Training complete")
    print(f"  Accuracy:  {metrics.accuracy:.4f}")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall:    {metrics.recall:.4f}")
    print(f"  F1:        {metrics.f1_score:.4f}")
    print(f"  Brier:     {metrics.brier_score:.4f}")
    print(f"  AUC:       {metrics.roc_auc:.4f}")
    print(f"Saved model: {out_path}")


if __name__ == "__main__":
    main()
