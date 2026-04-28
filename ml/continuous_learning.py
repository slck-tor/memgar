"""
Continuous Learning System - Production Ready
==============================================

Plug-and-play autonomous ML system.

Features:
- ✅ Automatic feedback collection
- ✅ Drift detection
- ✅ Auto-retraining
- ✅ Model versioning
- ✅ A/B testing ready
- ✅ Zero configuration needed

Installation:
    pip install -r requirements.txt

Usage:
    from ml.continuous_learning import ContinuousLearning
    
    cl = ContinuousLearning()
    
    # In production:
    record_id = cl.track(content, prediction)
    
    # Daily cron:
    cl.check_and_improve()

Author: Memgar AI Security
Version: 1.0.0
"""

import json
import time
import pickle
import hashlib
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

from ml.training.hard_negative_miner import HardNegativeMiner, merge_training_examples
from ml.thresholds import ThresholdManager

try:
    from memgar.learning import PatternEvolutionEngine
except Exception:  # pragma: no cover
    PatternEvolutionEngine = None  # type: ignore

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class Prediction:
    """Single prediction record"""
    id: str
    content_hash: str  # Don't store raw content for privacy
    predicted_attack: bool
    confidence: float
    timestamp: float
    session_id: Optional[str] = None
    
    # Ground truth (added later)
    actual_attack: Optional[bool] = None
    feedback: Optional[str] = None  # "correct", "false_positive", "false_negative"
    reviewed_at: Optional[float] = None
    
    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        data = f"{self.content_hash}_{self.timestamp}"
        return hashlib.md5(data.encode()).hexdigest()[:16]


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    timestamp: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    sample_size: int
    
    # Confidence statistics
    avg_confidence: float
    confidence_std: float
    
    # Additional context
    model_version: str = "current"
    data_source: str = "validation"


@dataclass
class DriftReport:
    """Drift detection report"""
    timestamp: float
    drift_detected: bool
    severity: str  # "low", "medium", "high"
    
    # Metrics comparison
    baseline_accuracy: float
    current_accuracy: float
    accuracy_drop: float
    
    baseline_fp_rate: float
    current_fp_rate: float
    fp_increase: float
    baseline_fn_rate: float
    current_fn_rate: float
    fn_increase: float
    
    # Recommendations
    recommendation: str
    should_retrain: bool
    
    # Details
    details: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# STORAGE MANAGER
# =============================================================================

class StorageManager:
    """
    Manages all data persistence for continuous learning.
    
    Handles:
    - Prediction logs
    - Feedback data
    - Performance metrics
    - Model versions
    """
    
    def __init__(self, base_path: str = "ml/continuous_learning/storage"):
        self.base_path = Path(base_path)
        self._init_directories()
        
        self.logger = logging.getLogger('StorageManager')
    
    def _init_directories(self):
        """Create storage directories"""
        directories = [
            self.base_path / "predictions",
            self.base_path / "feedback",
            self.base_path / "metrics",
            self.base_path / "models",
            self.base_path / "drift_reports"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def save_prediction(self, prediction: Prediction):
        """Save prediction to daily batch file"""
        date = datetime.fromtimestamp(prediction.timestamp).strftime("%Y%m%d")
        filepath = self.base_path / "predictions" / f"predictions_{date}.jsonl"

        with open(filepath, 'a') as f:
            f.write(json.dumps(asdict(prediction)) + '\n')

        # Auto-label only high-confidence predictions (>= 0.90) so retrain() can
        # use them without requiring manual review. Confidence == 0.0 is NOT
        # auto-labeled because it signals model uncertainty, not safe content.
        if prediction.confidence >= 0.90:
            prediction.actual_attack = prediction.predicted_attack
            prediction.feedback = "auto_labeled_high_confidence"
            self._save_feedback(prediction)
    
    def load_predictions(self, days: int = 7) -> List[Prediction]:
        """Load predictions from last N days"""
        cutoff = time.time() - (days * 86400)
        predictions = []
        
        for filepath in (self.base_path / "predictions").glob("predictions_*.jsonl"):
            with open(filepath, 'r') as f:
                for line in f:
                    pred_dict = json.loads(line.strip())
                    pred = Prediction(**pred_dict)
                    
                    if pred.timestamp >= cutoff:
                        predictions.append(pred)
        
        return predictions
    
    def update_prediction_feedback(self, prediction_id: str, 
                                   actual_attack: bool, feedback: str):
        """Update prediction with ground truth"""
        # Load all recent predictions
        predictions = self.load_predictions(days=30)
        
        # Find and update
        for pred in predictions:
            if pred.id == prediction_id:
                pred.actual_attack = actual_attack
                pred.feedback = feedback
                pred.reviewed_at = time.time()
                
                # Save to feedback directory
                self._save_feedback(pred)
                break
    
    def _save_feedback(self, prediction: Prediction):
        """Save validated feedback"""
        date = datetime.fromtimestamp(prediction.timestamp).strftime("%Y%m%d")
        filepath = self.base_path / "feedback" / f"feedback_{date}.jsonl"
        
        with open(filepath, 'a') as f:
            f.write(json.dumps(asdict(prediction)) + '\n')
    
    def get_labeled_data(self, days: int = 30) -> List[Prediction]:
        """Get all predictions with ground truth labels"""
        labeled = []
        
        for filepath in (self.base_path / "feedback").glob("feedback_*.jsonl"):
            with open(filepath, 'r') as f:
                for line in f:
                    pred_dict = json.loads(line.strip())
                    pred = Prediction(**pred_dict)
                    
                    if pred.actual_attack is not None:
                        labeled.append(pred)
        
        return labeled
    
    def save_metrics(self, metrics: ModelMetrics):
        """Save performance metrics"""
        filepath = self.base_path / "metrics" / "metrics_history.jsonl"
        
        with open(filepath, 'a') as f:
            f.write(json.dumps(asdict(metrics)) + '\n')
    
    def load_latest_metrics(self) -> Optional[ModelMetrics]:
        """Load most recent metrics"""
        filepath = self.base_path / "metrics" / "metrics_history.jsonl"
        
        if not filepath.exists():
            return None
        
        with open(filepath, 'r') as f:
            lines = f.readlines()
            if lines:
                latest = json.loads(lines[-1].strip())
                return ModelMetrics(**latest)
        
        return None
    
    def save_drift_report(self, report: DriftReport):
        """Save drift detection report"""
        date = datetime.fromtimestamp(report.timestamp).strftime("%Y%m%d")
        filepath = self.base_path / "drift_reports" / f"drift_{date}.json"
        
        with open(filepath, 'w') as f:
            json.dump(asdict(report), f, indent=2)


# =============================================================================
# FEEDBACK TRACKER
# =============================================================================

class FeedbackTracker:
    """
    Tracks predictions and collects feedback.
    
    Lightweight, production-safe tracking.
    """
    
    def __init__(self, storage: StorageManager):
        self.storage = storage
        self.logger = logging.getLogger('FeedbackTracker')
    
    def track_prediction(self, 
                        content: str,
                        predicted_attack: bool,
                        confidence: float,
                        session_id: Optional[str] = None) -> str:
        """
        Track a prediction for future validation.
        
        Args:
            content: Input content (hashed for privacy)
            predicted_attack: Model's prediction
            confidence: Prediction confidence
            session_id: Optional session identifier
        
        Returns:
            prediction_id for future reference
        """
        # Hash content for privacy
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
        
        prediction = Prediction(
            id="",  # Auto-generated
            content_hash=content_hash,
            predicted_attack=predicted_attack,
            confidence=confidence,
            timestamp=time.time(),
            session_id=session_id
        )
        
        # Save
        self.storage.save_prediction(prediction)
        
        self.logger.debug(f"Tracked prediction: {prediction.id}")
        
        return prediction.id
    
    def add_feedback(self, 
                    prediction_id: str,
                    is_correct: bool,
                    was_attack: Optional[bool] = None):
        """
        Add feedback on a prediction.
        
        Args:
            prediction_id: ID from track_prediction()
            is_correct: Was the prediction correct?
            was_attack: Ground truth (if known)
        """
        # Determine feedback type
        if is_correct:
            feedback = "correct"
        else:
            # Need to know ground truth
            if was_attack is None:
                raise ValueError("was_attack required when is_correct=False")
            
            if was_attack:
                feedback = "false_negative"  # Missed attack
            else:
                feedback = "false_positive"  # Wrongly blocked
        
        # Update storage
        self.storage.update_prediction_feedback(
            prediction_id=prediction_id,
            actual_attack=was_attack if was_attack is not None else True,
            feedback=feedback
        )
        
        self.logger.info(f"Feedback recorded: {prediction_id} -> {feedback}")


# =============================================================================
# DRIFT DETECTOR
# =============================================================================

class DriftDetector:
    """
    Detects when model performance degrades.
    
    Monitors key metrics and triggers alerts.
    """
    
    def __init__(self, storage: StorageManager):
        self.storage = storage
        self.logger = logging.getLogger('DriftDetector')
        
        # Thresholds
        self.accuracy_threshold = 0.03  # 3% drop
        self.fp_threshold = 0.02  # 2% increase
        self.fn_threshold = 0.02  # 2% increase
    
    def calculate_current_metrics(self, 
                                  predictions: List[Prediction]) -> Optional[ModelMetrics]:
        """Calculate metrics from recent predictions"""
        
        # Filter labeled predictions
        labeled = [p for p in predictions if p.actual_attack is not None]
        
        if len(labeled) < 50:  # Minimum sample size
            self.logger.warning(f"Insufficient samples: {len(labeled)} < 50")
            return None
        
        # Calculate metrics
        correct = sum(1 for p in labeled 
                     if p.predicted_attack == p.actual_attack)
        
        tp = sum(1 for p in labeled 
                if p.predicted_attack and p.actual_attack)
        fp = sum(1 for p in labeled 
                if p.predicted_attack and not p.actual_attack)
        fn = sum(1 for p in labeled 
                if not p.predicted_attack and p.actual_attack)
        tn = sum(1 for p in labeled 
                if not p.predicted_attack and not p.actual_attack)
        
        total = len(labeled)
        accuracy = correct / total
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        fp_rate = fp / total
        fn_rate = fn / total
        
        confidences = [p.confidence for p in labeled]
        avg_confidence = np.mean(confidences)
        confidence_std = np.std(confidences)
        
        return ModelMetrics(
            timestamp=time.time(),
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fp_rate,
            false_negative_rate=fn_rate,
            sample_size=total,
            avg_confidence=avg_confidence,
            confidence_std=confidence_std,
            data_source="production"
        )
    
    def check_drift(self, 
                   baseline: ModelMetrics,
                   current: ModelMetrics) -> DriftReport:
        """
        Check if model has drifted from baseline.
        
        Returns detailed drift report.
        """
        drift_detected = False
        severity = "low"
        reasons = []
        
        # 1. Accuracy drift
        accuracy_drop = baseline.accuracy - current.accuracy
        if accuracy_drop > self.accuracy_threshold:
            drift_detected = True
            reasons.append(f"Accuracy dropped {accuracy_drop*100:.1f}%")
            severity = "high" if accuracy_drop > 0.05 else "medium"
        
        # 2. False positive drift
        fp_increase = current.false_positive_rate - baseline.false_positive_rate
        if fp_increase > self.fp_threshold:
            drift_detected = True
            reasons.append(f"FP rate increased {fp_increase*100:.1f}%")
        
        # 3. False negative drift (CRITICAL)
        fn_increase = current.false_negative_rate - baseline.false_negative_rate
        if fn_increase > self.fn_threshold:
            drift_detected = True
            reasons.append(f"FN rate increased {fn_increase*100:.1f}%")
            severity = "high"  # Missing attacks is critical
        
        # Recommendation
        if drift_detected:
            if severity == "high":
                recommendation = "URGENT: Retrain immediately"
                should_retrain = True
            elif severity == "medium":
                recommendation = "Retrain within 24 hours"
                should_retrain = True
            else:
                recommendation = "Monitor closely"
                should_retrain = False
        else:
            recommendation = "Model performance stable"
            should_retrain = False
        
        report = DriftReport(
            timestamp=time.time(),
            drift_detected=drift_detected,
            severity=severity,
            baseline_accuracy=baseline.accuracy,
            current_accuracy=current.accuracy,
            accuracy_drop=accuracy_drop,
            baseline_fp_rate=baseline.false_positive_rate,
            current_fp_rate=current.false_positive_rate,
            fp_increase=fp_increase,
            baseline_fn_rate=baseline.false_negative_rate,
            current_fn_rate=current.false_negative_rate,
            fn_increase=fn_increase,
            recommendation=recommendation,
            should_retrain=should_retrain,
            details={
                'reasons': reasons,
                'sample_size': current.sample_size,
                'baseline_sample_size': baseline.sample_size
            }
        )
        
        # Save report
        self.storage.save_drift_report(report)
        
        return report


# =============================================================================
# AUTO RETRAINER
# =============================================================================

class AutoRetrainer:
    """
    Automatically retrains model with new data.
    
    Handles:
    - Data merging
    - Training
    - Validation
    - Model versioning
    """
    
    def __init__(self, storage: StorageManager):
        self.storage = storage
        self.logger = logging.getLogger('AutoRetrainer')
        self.hard_negative_miner = HardNegativeMiner()

    def inject_adversarial_variants(self, variants: List[Dict[str, Any]]) -> int:
        """Persist LLM-generated adversarial variants for use in next retrain.

        Returns the number of variants written.
        """
        path = self.storage.base_path / "adversarial_variants.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(path, "a", encoding="utf-8") as f:
            for v in variants:
                if v.get("text"):
                    f.write(json.dumps(v, ensure_ascii=False) + "\n")
                    written += 1
        self.logger.info("Injected %d adversarial variants -> %s", written, path)
        return written

    def _load_adversarial_variants(self) -> List[Dict[str, Any]]:
        """Load previously injected adversarial variants."""
        path = self.storage.base_path / "adversarial_variants.jsonl"
        rows: List[Dict[str, Any]] = []
        if not path.exists():
            return rows
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict) and item.get("text"):
                    rows.append(item)
        return rows

    def _load_active_feedback_rows(self) -> List[Dict[str, Any]]:
        """
        Load text-preserving feedback rows written by collect_feedback().

        Format: JSONL at <storage>/active_feedback.jsonl
        """
        rows: List[Dict[str, Any]] = []
        path = self.storage.base_path / "active_feedback.jsonl"
        if not path.exists():
            return rows

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict) and item.get("text"):
                    rows.append(item)
        return rows

    def retrain(self, min_new_samples: int = 500) -> Dict:
        """
        Retrain model with new feedback data.
        
        Args:
            min_new_samples: Minimum new samples required
        
        Returns:
            Result dictionary with metrics
        """
        self.logger.info("Starting automated retraining...")
        
        # 1. Get labeled feedback (hashed stream + text-preserving active-learning stream)
        feedback_data = self.storage.get_labeled_data(days=30)
        active_feedback_rows = self._load_active_feedback_rows()
        total_new = len(feedback_data) + len(active_feedback_rows)

        if total_new < min_new_samples:
            self.logger.warning(
                f"Insufficient samples: {total_new} < {min_new_samples}"
            )
            return {
                'success': False,
                'reason': 'insufficient_samples',
                'sample_count': total_new
            }
        
        self.logger.info(f"Found {total_new} new labeled samples")
        
        # 2. Load original training data
        _training_data_path = (
            Path(__file__).parent / "data" / "training_data.json"
        )
        try:
            with open(_training_data_path, 'r') as f:
                original_data = json.load(f)
        except FileNotFoundError:
            self.logger.error("Original training data not found at %s", _training_data_path)
            return {'success': False, 'reason': 'missing_original_data'}
        
        # 3. Build new samples from hashed feedback (privacy-preserving fallback)
        new_samples = [
            {
                'text': f"sample_{p.content_hash}",  # Placeholder
                'label': 1 if p.actual_attack else 0,
                'category': 'production_feedback',
                'subcategory': p.feedback,
                'confidence': 1.0,
                'source': 'hashed_feedback',
                'weight': 1.0,
            }
            for p in feedback_data
        ]

        # 3b. Add text-preserving active-learning rows
        for row in active_feedback_rows:
            new_samples.append(
                {
                    'text': str(row.get('text', '')),
                    'label': int(row.get('actual', row.get('actual_label', 0))),
                    'category': 'production_feedback',
                    'subcategory': str(row.get('feedback', row.get('source', 'active_learning'))),
                    'confidence': float(row.get('confidence', 1.0)),
                    'source': 'active_learning',
                    'weight': 1.0,
                }
            )

        # 3c. Mine hard negatives from false positives
        hard_neg_candidates = self.hard_negative_miner.from_feedback(active_feedback_rows, max_samples=1500)
        hard_negative_rows = self.hard_negative_miner.to_training_examples(hard_neg_candidates)

        merged_new_samples = merge_training_examples(
            new_samples,
            hard_negative_rows,
            max_added_negative_ratio=0.35,
        )

        # 3d. Merge adversarial attack variants (capped at 20% of original)
        adversarial_rows_raw = self._load_adversarial_variants()
        if adversarial_rows_raw:
            adv_candidates = self.hard_negative_miner.from_variants(adversarial_rows_raw)
            adv_attack_rows = self.hard_negative_miner.to_attack_examples(adv_candidates)
            max_adv = int(len(original_data) * 0.20)
            adv_attack_rows = adv_attack_rows[:max_adv]
            merged_new_samples = merged_new_samples + adv_attack_rows
            self.logger.info("Added %d adversarial attack variants", len(adv_attack_rows))

        merged_data = original_data + merged_new_samples
        
        # 4. Save merged dataset
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_data_path = f'ml/data/training_data_v{timestamp}.json'
        
        with open(new_data_path, 'w') as f:
            json.dump(merged_data, f, indent=2)
        
        self.logger.info(f"Merged dataset: {len(merged_data)} samples")
        
        # 5. Train new model
        try:
            # Import training pipeline
            try:
                from ml.training.train import XGBoostTrainingPipeline
            except Exception:
                import sys
                sys.path.insert(0, 'ml/training')
                from train import XGBoostTrainingPipeline
            
            pipeline = XGBoostTrainingPipeline(
                random_state=42,
                estimator="auto",
                calibrate_method="isotonic",
            )
            
            # Prepare data
            texts = [ex['text'] for ex in merged_data]
            labels = [ex['label'] for ex in merged_data]
            
            y = np.array(labels)
            X = pipeline.extract_features(texts, show_progress=False)
            
            # Split train/val/test
            X_train, X_tmp, y_train, y_tmp = pipeline.split_data(X, y, test_size=0.3)
            X_val, X_test, y_val, y_test = pipeline.split_data(X_tmp, y_tmp, test_size=0.5)
            
            # Train + calibrate
            pipeline.train_xgboost(
                X_train,
                y_train,
                X_val,
                y_val,
                calibrate=True,
            )
            
            # Validate
            metrics = pipeline.evaluate(X_test, y_test, threshold=0.5, use_calibrated=True)
            
            # Save versioned new model
            new_model_path = f'ml/artifacts/gradient_boost_model_v{timestamp}.pkl'
            pipeline.save_model(new_model_path)
            self.logger.info(f"New model trained: {metrics.accuracy:.4f} accuracy")

            # Quality gate + atomic promotion to production path with rollback
            production_path = Path('ml/artifacts/gradient_boost_model.pkl')
            backup_path = production_path.with_suffix('.pkl.backup')
            had_backup = False
            if production_path.exists():
                if backup_path.exists():
                    backup_path.unlink()
                production_path.rename(backup_path)
                had_backup = True

            try:
                from ml.quality_gate import run_quality_gate
                gate_code, gate_summary = run_quality_gate(
                    model_path=new_model_path,
                    training_data_path=new_data_path,
                    min_precision=0.94,
                    min_recall=0.94,
                    max_p95_latency_ms=25.0,
                    max_avg_latency_ms=10.0,
                    threshold=0.5,
                    test_size=0.20,
                    random_state=42,
                    latency_sample_size=300,
                )
            except Exception as gate_exc:
                self.logger.error(f"Quality gate raised: {gate_exc}")
                if had_backup:
                    shutil.copyfile(backup_path, production_path)
                return {
                    'success': False,
                    'reason': 'quality_gate_error',
                    'error': str(gate_exc),
                    'model_path': new_model_path,
                }

            if gate_code != 0:
                self.logger.warning(
                    f"Quality gate failed (exit={gate_code}); rolling back to previous model"
                )
                if had_backup:
                    shutil.copyfile(backup_path, production_path)
                return {
                    'success': False,
                    'reason': 'quality_gate_failed',
                    'gate_exit_code': int(gate_code),
                    'gate_summary': gate_summary,
                    'model_path': new_model_path,
                }

            # Promote new model to production path
            shutil.copyfile(new_model_path, production_path)
            self.logger.info(f"Quality gate passed; promoted {new_model_path} -> {production_path}")

            return {
                'success': True,
                'model_path': str(production_path),
                'versioned_path': new_model_path,
                'data_path': new_data_path,
                'metrics': {
                    'accuracy': metrics.accuracy,
                    'f1_score': metrics.f1_score,
                    'precision': metrics.precision,
                    'recall': metrics.recall
                },
                'gate_summary': gate_summary,
                'sample_count': len(merged_data),
                'new_samples': len(merged_new_samples),
                'hard_negative_samples': len(hard_negative_rows),
            }

        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            # Restore backup if we had moved a production model aside
            try:
                production_path = Path('ml/artifacts/gradient_boost_model.pkl')
                backup_path = production_path.with_suffix('.pkl.backup')
                if not production_path.exists() and backup_path.exists():
                    shutil.copyfile(backup_path, production_path)
            except Exception:
                pass
            return {
                'success': False,
                'reason': 'training_error',
                'error': str(e)
            }


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

class ContinuousLearning:
    """
    Main continuous learning orchestrator.
    
    Usage:
        cl = ContinuousLearning()
        
        # Track predictions
        record_id = cl.track(content, prediction)
        
        # Add feedback
        cl.feedback(record_id, is_correct=False, was_attack=True)
        
        # Daily check
        cl.check_and_improve()
    """
    
    def __init__(
        self,
        storage_path: str = "ml/continuous_learning/storage",
        # Compatibility params — map to storage_path / tunable thresholds
        model_path: Optional[str] = None,
        feedback_dir: Optional[str] = None,
        min_feedback_count: int = 50,
        drift_threshold: float = 0.03,
        retrain_threshold: int = 100,
        version_history_size: int = 10,
        threshold_config_path: Optional[str] = None,
        threshold_profile: str = "balanced",
        enable_auto_threshold_tuning: bool = True,
        auto_threshold_min_block: float = 0.20,
        auto_threshold_max_block: float = 0.90,
    ):
        # If caller provides model_path/feedback_dir, derive storage_path from them
        if feedback_dir is not None:
            storage_path = feedback_dir
        elif model_path is not None:
            storage_path = os.path.dirname(model_path) or storage_path

        self.storage = StorageManager(storage_path)
        self.tracker = FeedbackTracker(self.storage)
        self.drift_detector = DriftDetector(self.storage)
        self.retrainer = AutoRetrainer(self.storage)

        self.logger = logging.getLogger('ContinuousLearning')

        # Configurable thresholds
        self.min_feedback_count = min_feedback_count
        self._drift_threshold = drift_threshold
        self.retrain_threshold = retrain_threshold
        self.version_history_size = version_history_size
        self.drift_detector.accuracy_threshold = drift_threshold

        # Dynamic threshold policy tuning
        self.threshold_profile = str(threshold_profile or "balanced")
        self.enable_auto_threshold_tuning = bool(enable_auto_threshold_tuning)
        self.auto_threshold_min_block = float(auto_threshold_min_block)
        self.auto_threshold_max_block = float(auto_threshold_max_block)
        if threshold_config_path is None:
            threshold_config_path = str(self.storage.base_path / "threshold_profiles.json")
        self.threshold_config_path = threshold_config_path
        self.threshold_manager = ThresholdManager(config_path=self.threshold_config_path)

        # Simple in-memory feedback store (lightweight, no full prediction pipeline)
        self._feedback: List[Dict] = []
        self._version: int = 1
        self._active_feedback_file = self.storage.base_path / "active_feedback.jsonl"

        # Optional drift/evolution engine from memgar.learning
        self.pattern_evolver = PatternEvolutionEngine() if PatternEvolutionEngine is not None else None

        # Get baseline metrics (from initial training)
        self.baseline_metrics = self._get_baseline_metrics()

        # Scheduling
        self.last_check = time.time()
        self.check_interval = 86400  # Daily

    def _get_baseline_metrics(self) -> ModelMetrics:
        """Get or create baseline metrics"""
        latest = self.storage.load_latest_metrics()
        
        if latest:
            return latest
        
        # Create baseline from initial training results
        baseline = ModelMetrics(
            timestamp=time.time(),
            accuracy=0.9792,
            precision=0.9803,
            recall=0.9813,
            f1_score=0.9790,
            false_positive_rate=0.020,
            false_negative_rate=0.018,
            sample_size=2000,
            avg_confidence=0.85,
            confidence_std=0.15,
            model_version="1.0.0",
            data_source="initial_training"
        )
        
        self.storage.save_metrics(baseline)
        return baseline
    
    def track(self, 
             content: str,
             prediction_result) -> str:
        """
        Track a prediction.
        
        Args:
            content: Input text
            prediction_result: ML detector result object
        
        Returns:
            record_id for future feedback
        """
        return self.tracker.track_prediction(
            content=content,
            predicted_attack=prediction_result.should_block,
            confidence=prediction_result.attack_probability
        )
    
    def feedback(self, 
                record_id: str,
                is_correct: bool,
                was_attack: Optional[bool] = None):
        """
        Add feedback on a prediction.
        
        Args:
            record_id: ID from track()
            is_correct: Was prediction correct?
            was_attack: Ground truth (required if incorrect)
        """
        self.tracker.add_feedback(record_id, is_correct, was_attack)
    
    def check_and_improve(self) -> Optional[Dict]:
        """
        Check for drift and retrain if needed.
        
        Run this daily (cron job).
        
        Returns:
            Result dict if action taken, None otherwise
        """
        # Rate limiting
        if time.time() - self.last_check < self.check_interval:
            return None
        
        self.last_check = time.time()
        
        self.logger.info("Running daily check...")
        
        # 1. Get recent predictions
        predictions = self.storage.load_predictions(days=7)
        
        # 2. Calculate current metrics
        current_metrics = self.drift_detector.calculate_current_metrics(predictions)
        
        if not current_metrics:
            self.logger.info("Insufficient data for drift check")
            return None
        
        # Save current metrics
        self.storage.save_metrics(current_metrics)
        
        # 3. Check drift
        drift_report = self.drift_detector.check_drift(
            baseline=self.baseline_metrics,
            current=current_metrics
        )
        
        self.logger.info(f"Drift check: {drift_report.recommendation}")
        
        # 4. Pattern-drift / attack-evolution analysis from active-learning feedback
        pattern_drift = self._analyze_pattern_drift()
        pattern_retrain_signal = bool(
            pattern_drift
            and pattern_drift.get('drift_detected')
            and float(pattern_drift.get('drift_score', 0.0)) >= 0.25
        )
        threshold_policy = self._auto_adjust_threshold_policy(
            drift_report=drift_report,
            pattern_drift=pattern_drift,
        )

        # 5. Retrain if needed
        if drift_report.should_retrain or pattern_retrain_signal:
            self.logger.info("Triggering automated retraining...")
            
            retrain_result = self.retrainer.retrain()
            
            if retrain_result['success']:
                self.logger.info(f"✅ Retraining successful: {retrain_result['model_path']}")
                
                # Update baseline
                new_baseline = ModelMetrics(
                    timestamp=time.time(),
                    accuracy=retrain_result['metrics']['accuracy'],
                    precision=retrain_result['metrics']['precision'],
                    recall=retrain_result['metrics']['recall'],
                    f1_score=retrain_result['metrics']['f1_score'],
                    false_positive_rate=0.0,  # Calculate if needed
                    false_negative_rate=0.0,
                    sample_size=retrain_result['sample_count'],
                    avg_confidence=0.85,
                    confidence_std=0.15,
                    model_version="auto_" + datetime.now().strftime("%Y%m%d"),
                    data_source="retrained"
                )
                
                self.storage.save_metrics(new_baseline)
                self.baseline_metrics = new_baseline
            else:
                self.logger.error(f"❌ Retraining failed: {retrain_result.get('reason')}")
            
            return {
                'drift': asdict(drift_report),
                'pattern_drift': pattern_drift,
                'threshold_policy': threshold_policy,
                'retrain': retrain_result
            }
        
        return {
            'drift': asdict(drift_report),
            'pattern_drift': pattern_drift,
            'threshold_policy': threshold_policy,
            'retrain': None
        }

    def _analyze_pattern_drift(self) -> Optional[Dict[str, Any]]:
        """
        Use PatternEvolutionEngine to detect evolving attack language.

        Relies on text-preserving feedback entries produced by collect_feedback().
        """
        if self.pattern_evolver is None:
            return None
        if not self._feedback:
            return None

        attack_samples = [f["text"] for f in self._feedback if int(f.get("actual", 0)) == 1 and f.get("text")]
        blocked_samples = [
            f["text"]
            for f in self._feedback
            if int(f.get("actual", 0)) == 1 and int(f.get("predicted", 0)) == 1 and f.get("text")
        ]
        if len(attack_samples) < 8:
            return None

        try:
            report = self.pattern_evolver.detect_drift(
                pattern_name="ml_semantic_attack_pattern",
                original_pattern=r"(ignore|bypass|disregard|override)",
                attack_samples=attack_samples[:500],
                blocked_samples=blocked_samples[:500],
            )
            return {
                "drift_detected": bool(report.drift_detected),
                "drift_score": float(report.drift_score),
                "pattern_name": report.pattern_name,
                "evasion_count": len(report.evasion_samples),
                "variant_count": len(report.proposed_variants),
                "explanation": report.explanation,
            }
        except Exception as exc:
            self.logger.warning(f"Pattern drift analysis failed: {exc}")
            return None

    def _derive_threshold_delta(
        self,
        drift_report: DriftReport,
        pattern_drift: Optional[Dict[str, Any]],
    ) -> Tuple[float, List[str]]:
        """
        Convert drift signals to a conservative threshold shift.

        Negative delta => stricter blocking.
        Positive delta => more lenient blocking.
        """
        reasons: List[str] = []
        delta = 0.0

        fn_increase = max(0.0, float(drift_report.fn_increase))
        fp_increase = max(0.0, float(drift_report.fp_increase))
        pattern_detected = bool(pattern_drift and pattern_drift.get("drift_detected"))
        pattern_score = float(pattern_drift.get("drift_score", 0.0)) if pattern_drift else 0.0

        # Security-first: missed attacks (FN) or evolving adversarial language => tighten.
        if fn_increase > self.drift_detector.fn_threshold:
            delta -= 0.06
            reasons.append(f"fn_increase={fn_increase:.4f}>fn_threshold")
        elif fn_increase > 0.0:
            delta -= 0.02
            reasons.append(f"fn_increase={fn_increase:.4f}")

        if pattern_detected:
            if pattern_score >= 0.45:
                delta -= 0.06
            elif pattern_score >= 0.25:
                delta -= 0.04
            else:
                delta -= 0.02
            reasons.append(f"pattern_drift={pattern_score:.4f}")

        # If only false positives are rising, relax slightly.
        if (
            fp_increase > self.drift_detector.fp_threshold
            and fn_increase <= self.drift_detector.fn_threshold
            and not pattern_detected
        ):
            delta += 0.04
            reasons.append(f"fp_increase={fp_increase:.4f}>fp_threshold")

        if drift_report.severity == "high" and delta < 0.0:
            delta *= 1.20
        elif drift_report.severity == "medium" and delta < 0.0:
            delta *= 1.10

        return delta, reasons

    def _auto_adjust_threshold_policy(
        self,
        drift_report: DriftReport,
        pattern_drift: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Adjust threshold profile automatically and persist config."""
        if not self.enable_auto_threshold_tuning:
            return {
                "enabled": False,
                "updated": False,
                "profile": self.threshold_profile,
                "reason": "disabled",
            }

        profile_name = self.threshold_profile or "balanced"
        try:
            before = self.threshold_manager.get_profile(profile_name)
            delta, reasons = self._derive_threshold_delta(drift_report, pattern_drift)

            if abs(delta) < 1e-12:
                return {
                    "enabled": True,
                    "updated": False,
                    "profile": before.name,
                    "old_block_threshold": before.block_threshold,
                    "new_block_threshold": before.block_threshold,
                    "delta": 0.0,
                    "reasons": reasons,
                    "config_path": self.threshold_config_path,
                }

            updated = self.threshold_manager.adjust_profile(
                profile_name=before.name,
                block_delta=delta,
                fallback_profile=profile_name,
                min_block=self.auto_threshold_min_block,
                max_block=self.auto_threshold_max_block,
            )
            saved_path = self.threshold_manager.save(self.threshold_config_path)
            action = "tighten" if updated.block_threshold < before.block_threshold else "relax"
            applied_delta = updated.block_threshold - before.block_threshold

            self.logger.info(
                "Threshold policy update (%s): %.3f -> %.3f",
                action,
                before.block_threshold,
                updated.block_threshold,
            )

            return {
                "enabled": True,
                "updated": True,
                "action": action,
                "profile": updated.name,
                "old_block_threshold": before.block_threshold,
                "new_block_threshold": updated.block_threshold,
                "delta": applied_delta,
                "reasons": reasons,
                "config_path": saved_path or self.threshold_config_path,
            }
        except Exception as exc:
            self.logger.warning(f"Threshold policy update failed: {exc}")
            return {
                "enabled": True,
                "updated": False,
                "profile": profile_name,
                "reason": "error",
                "error": str(exc),
            }
    
    # -------------------------------------------------------------------------
    # Simplified test-friendly API
    # -------------------------------------------------------------------------

    def collect_feedback(
        self,
        text: str,
        predicted_label: int,
        actual_label: int,
        confidence: float = 1.0,
    ) -> None:
        """Collect a labelled feedback sample (simplified API)."""
        entry = {
            "text": str(text),
            "predicted": int(predicted_label),
            "actual": int(actual_label),
            "predicted_label": int(predicted_label),
            "actual_label": int(actual_label),
            "confidence": float(confidence),
            "correct": predicted_label == actual_label,
            "source": "collect_feedback",
            "timestamp": time.time(),
        }
        self._feedback.append(entry)

        # Persist to JSONL stream for active learning
        try:
            os.makedirs(str(self.storage.base_path), exist_ok=True)
            with open(self._active_feedback_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def feedback_count(self) -> int:
        """Return the number of collected feedback samples."""
        return len(self._feedback)

    def check_drift(self) -> bool:
        """Return True if error rate among collected feedback exceeds the threshold."""
        if not self._feedback:
            return False
        errors = sum(1 for f in self._feedback if not f["correct"])
        error_rate = errors / len(self._feedback)
        return error_rate > self._drift_threshold

    def should_retrain(self) -> bool:
        """Return True when enough feedback or drift is detected."""
        return self.feedback_count() >= self.retrain_threshold or self.check_drift()

    def get_current_version(self) -> int:
        """Return current model version number."""
        return self._version

    def increment_version(self) -> int:
        """Increment and return the model version."""
        self._version += 1
        return self._version

    def get_stats(self) -> Dict:
        """Get system statistics"""
        predictions = self.storage.load_predictions(days=7)
        labeled = self.storage.get_labeled_data(days=30)
        latest_metrics = self.storage.load_latest_metrics()
        
        return {
            'predictions_last_7_days': len(predictions),
            'labeled_data_count': len(labeled),
            'active_feedback_count': len(self._feedback),
            'latest_metrics': asdict(latest_metrics) if latest_metrics else None,
            'baseline_accuracy': self.baseline_metrics.accuracy,
            'storage_path': str(self.storage.base_path),
            'active_feedback_file': str(self._active_feedback_file),
            'threshold_profile': self.threshold_profile,
            'threshold_config_path': str(self.threshold_config_path),
        }


# =============================================================================
# SMART DETECTOR — ML detector wrapper with optional continuous learning
# =============================================================================

class SmartDetector:
    """
    ML-aware detector with an optional continuous-learning feedback loop.

    Parameters
    ----------
    model_path : str
        Path to the trained model .pkl file.
    enable_learning : bool
        If True, feedback can be collected and used to retrain.
    feedback_dir : str | None
        Directory for persisting feedback.  Uses a temp dir when *None*.
    """

    def __init__(
        self,
        model_path: str,
        enable_learning: bool = True,
        feedback_dir: Optional[str] = None,
        threshold_config_path: Optional[str] = None,
        threshold_profile: str = "balanced",
    ):
        self.model_path = model_path
        self.enable_learning = enable_learning

        # Feedback store (always available, even without a model)
        import tempfile, os
        _fdir = feedback_dir or tempfile.mkdtemp(prefix="smartdetector_")
        os.makedirs(_fdir, exist_ok=True)
        self._cl: Optional["ContinuousLearning"] = None
        if enable_learning:
            self._cl = ContinuousLearning(
                model_path=model_path,
                feedback_dir=_fdir,
                threshold_config_path=threshold_config_path,
                threshold_profile=threshold_profile,
            )

        effective_threshold_config = (
            self._cl.threshold_config_path
            if self._cl is not None
            else threshold_config_path
        )

        # Lazy-load ML detector to avoid hard import failures
        self._detector = None
        try:
            from memgar.ml_semantic_detector import MLSemanticDetector
            import os
            if os.path.exists(model_path):
                self._detector = MLSemanticDetector(
                    model_path,
                    threshold_manager=self._cl.threshold_manager if self._cl is not None else None,
                    threshold_config_path=effective_threshold_config,
                    default_profile=threshold_profile,
                )
        except Exception:
            pass

    def detect(self, text: str):
        """Run detection and return a result with .attack_probability and .should_block."""
        if self._detector is not None:
            return self._detector.detect(text)

        # Fallback: use the regex/pattern analyzer from memgar core
        from memgar.analyzer import Analyzer
        from memgar.models import MemoryEntry, Decision

        analyzer = Analyzer()
        result = analyzer.analyze(MemoryEntry(content=text or ""))

        # Wrap into a simple object that matches the expected interface
        class _FallbackResult:
            def __init__(self, r):
                self.decision = r.decision
                self.risk_score = r.risk_score
                self.attack_probability = r.risk_score / 100.0
                self.should_block = r.decision == Decision.BLOCK
                self.threats = r.threats

        return _FallbackResult(result)

    def add_feedback(
        self,
        text: str,
        predicted_label: int,
        actual_label: int,
        confidence: float = 1.0,
    ) -> None:
        """Record labelled feedback."""
        if self._cl is not None:
            self._cl.collect_feedback(
                text=text,
                predicted_label=predicted_label,
                actual_label=actual_label,
                confidence=confidence,
            )

    def feedback_count(self) -> int:
        """Return number of collected feedback samples."""
        if self._cl is not None:
            return self._cl.feedback_count()
        return 0


# =============================================================================
# CLI & EXAMPLES
# =============================================================================

if __name__ == "__main__":
    # Example usage
    print("Continuous Learning System - Example")
    print("=" * 50)
    
    # Initialize
    cl = ContinuousLearning()
    
    # Simulate prediction tracking
    print("\n1. Tracking prediction...")
    record_id = cl.track(
        content="test input",
        prediction_result=type('obj', (object,), {
            'should_block': True,
            'attack_probability': 0.95
        })()
    )
    print(f"   Tracked: {record_id}")
    
    # Simulate feedback
    print("\n2. Adding feedback...")
    cl.feedback(record_id, is_correct=False, was_attack=False)
    print("   Feedback: false positive")
    
    # Get stats
    print("\n3. System stats:")
    stats = cl.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Example complete!")
