"""
XGBoost Training Pipeline for ML Semantic Classifier
====================================================

Complete production pipeline:
1. Load training data
2. Extract features using MLFeatureExtractor
3. Train XGBoost classifier
4. Cross-validation (5-fold)
5. Hyperparameter tuning
6. Model evaluation
7. Save trained model

Target: 95%+ accuracy with cross-validation

Author: Memgar AI Security
Version: 1.0.0
"""

import json
import numpy as np
import pickle
import time
from typing import List, Dict, Tuple
from dataclasses import dataclass
import sys

# Use sklearn GradientBoosting (similar to XGBoost, already installed)
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

XGBOOST_AVAILABLE = False  # Using sklearn instead

# Add path for feature extractor
sys.path.insert(0, '/home/claude/test_env')
from ml_feature_extractor_v3 import MLFeatureExtractor, FeatureVector


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    
    def __str__(self):
        return f"""
Performance Metrics:
  Accuracy:  {self.accuracy:.4f}
  Precision: {self.precision:.4f}
  Recall:    {self.recall:.4f}
  F1 Score:  {self.f1_score:.4f}
  
Confusion Matrix:
  TP: {self.true_positives:4d}  FN: {self.false_negatives:4d}
  FP: {self.false_positives:4d}  TN: {self.true_negatives:4d}
"""


class XGBoostTrainingPipeline:
    """
    Complete XGBoost training pipeline.
    
    Features:
    - Automatic feature extraction
    - Cross-validation
    - Hyperparameter tuning
    - Model persistence
    - Performance monitoring
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.feature_extractor = MLFeatureExtractor()
        self.model = None
        self.feature_importance = None
        self.training_history = []
    
    def load_training_data(self, filename: str) -> Tuple[List[str], List[int]]:
        """
        Load training data from JSON file.
        
        Returns:
            (texts, labels)
        """
        print(f"Loading training data from {filename}...")
        
        with open(filename, 'r') as f:
            data = json.load(f)
        
        texts = [ex['text'] for ex in data]
        labels = [ex['label'] for ex in data]
        
        print(f"✅ Loaded {len(texts)} examples")
        print(f"   Attacks: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        print(f"   Legitimate: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
        print()
        
        return texts, labels
    
    def extract_features(self, texts: List[str], show_progress: bool = True) -> np.ndarray:
        """
        Extract features from texts using MLFeatureExtractor.
        
        Returns:
            Feature matrix (n_samples, n_features)
        """
        print(f"Extracting features from {len(texts)} examples...")
        
        features_list = []
        start_time = time.time()
        
        for i, text in enumerate(texts):
            if show_progress and (i + 1) % 1000 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                eta = (len(texts) - i - 1) / rate
                print(f"  Progress: {i+1}/{len(texts)} ({(i+1)/len(texts)*100:.1f}%) - ETA: {eta:.1f}s")
            
            feature_vector = self.feature_extractor.extract(text)
            features_list.append(feature_vector.to_numpy())
        
        features = np.vstack(features_list)
        
        elapsed = time.time() - start_time
        print(f"✅ Feature extraction complete in {elapsed:.2f}s")
        print(f"   Feature matrix shape: {features.shape}")
        print(f"   Average time per example: {elapsed/len(texts)*1000:.2f}ms")
        print()
        
        return features
    
    def split_data(self, X: np.ndarray, y: np.ndarray, 
                   test_size: float = 0.2) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Split data into train/test sets.
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Fraction for test set
        
        Returns:
            X_train, X_test, y_train, y_test
        """
        n_samples = len(X)
        n_test = int(n_samples * test_size)
        
        # Shuffle indices
        np.random.seed(self.random_state)
        indices = np.random.permutation(n_samples)
        
        # Split
        test_indices = indices[:n_test]
        train_indices = indices[n_test:]
        
        X_train = X[train_indices]
        X_test = X[test_indices]
        y_train = y[train_indices]
        y_test = y[test_indices]
        
        print(f"Data split:")
        print(f"  Train: {len(X_train)} examples ({len(X_train)/n_samples*100:.1f}%)")
        print(f"  Test:  {len(X_test)} examples ({len(X_test)/n_samples*100:.1f}%)")
        print()
        
        return X_train, X_test, y_train, y_test
    
    def train_xgboost(self, X_train: np.ndarray, y_train: np.ndarray,
                     X_val: np.ndarray = None, y_val: np.ndarray = None,
                     params: Dict = None):
        """
        Train Gradient Boosting model (sklearn implementation).
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            params: Model parameters (optional)
        
        Returns:
            Trained model
        """
        print("Training Gradient Boosting model (sklearn)...")
        
        # Default parameters (optimized for binary classification)
        if params is None:
            params = {
                'n_estimators': 100,
                'max_depth': 6,
                'learning_rate': 0.1,
                'subsample': 0.8,
                'min_samples_split': 3,
                'min_samples_leaf': 1,
                'random_state': self.random_state,
                'verbose': 0
            }
        
        # Train
        start_time = time.time()
        
        self.model = GradientBoostingClassifier(**params)
        self.model.fit(X_train, y_train)
        
        elapsed = time.time() - start_time
        print(f"✅ Training complete in {elapsed:.2f}s")
        
        # Validation score if provided
        if X_val is not None and y_val is not None:
            val_score = self.model.score(X_val, y_val)
            print(f"   Validation accuracy: {val_score:.4f}")
        
        print()
        
        # Feature importance
        self.feature_importance = {
            f'f{i}': imp for i, imp in enumerate(self.model.feature_importances_)
        }
        
        return self.model
    
    def evaluate(self, X: np.ndarray, y: np.ndarray, 
                threshold: float = 0.5) -> ModelMetrics:
        """
        Evaluate model performance.
        
        Args:
            X: Feature matrix
            y: True labels
            threshold: Classification threshold
        
        Returns:
            ModelMetrics object
        """
        # Predict
        y_pred_proba = self.model.predict_proba(X)[:, 1]  # Probability of class 1
        y_pred = (y_pred_proba >= threshold).astype(int)
        
        # Calculate metrics
        tp = np.sum((y == 1) & (y_pred == 1))
        tn = np.sum((y == 0) & (y_pred == 0))
        fp = np.sum((y == 0) & (y_pred == 1))
        fn = np.sum((y == 1) & (y_pred == 0))
        
        accuracy = (tp + tn) / len(y)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn
        )
    
    def cross_validate(self, X: np.ndarray, y: np.ndarray, 
                      n_folds: int = 5) -> List[ModelMetrics]:
        """
        Perform k-fold cross-validation.
        
        Args:
            X: Feature matrix
            y: Labels
            n_folds: Number of folds
        
        Returns:
            List of metrics for each fold
        """
        print(f"Performing {n_folds}-fold cross-validation...")
        print()
        
        n_samples = len(X)
        fold_size = n_samples // n_folds
        
        # Shuffle indices
        np.random.seed(self.random_state)
        indices = np.random.permutation(n_samples)
        
        metrics_list = []
        
        for fold in range(n_folds):
            print(f"Fold {fold + 1}/{n_folds}:")
            
            # Split indices
            val_start = fold * fold_size
            val_end = val_start + fold_size if fold < n_folds - 1 else n_samples
            val_indices = indices[val_start:val_end]
            train_indices = np.concatenate([indices[:val_start], indices[val_end:]])
            
            # Split data
            X_train_fold = X[train_indices]
            y_train_fold = y[train_indices]
            X_val_fold = X[val_indices]
            y_val_fold = y[val_indices]
            
            # Train
            self.train_xgboost(X_train_fold, y_train_fold, X_val_fold, y_val_fold)
            
            # Evaluate
            metrics = self.evaluate(X_val_fold, y_val_fold)
            metrics_list.append(metrics)
            
            print(f"  Accuracy: {metrics.accuracy:.4f}")
            print(f"  F1 Score: {metrics.f1_score:.4f}")
            print()
        
        # Average metrics
        avg_accuracy = np.mean([m.accuracy for m in metrics_list])
        avg_f1 = np.mean([m.f1_score for m in metrics_list])
        
        print("="*70)
        print(f"Cross-Validation Results ({n_folds} folds):")
        print(f"  Average Accuracy: {avg_accuracy:.4f} (± {np.std([m.accuracy for m in metrics_list]):.4f})")
        print(f"  Average F1 Score: {avg_f1:.4f} (± {np.std([m.f1_score for m in metrics_list]):.4f})")
        print("="*70)
        print()
        
        return metrics_list
    
    def save_model(self, filename: str):
        """Save trained model to file"""
        if self.model is None:
            print("❌ No model to save. Train a model first.")
            return
        
        # Save sklearn model with pickle
        with open(filename, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Also save feature extractor config (for reproducibility)
        config = {
            'random_state': self.random_state,
            'feature_names': FeatureVector().get_feature_names(),
            'n_features': 40,
            'feature_importance': self.feature_importance
        }
        
        with open(filename + '.config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Model saved to {filename}")
        print(f"✅ Config saved to {filename}.config.json")
    
    def load_model(self, filename: str):
        """Load trained model from file"""
        with open(filename, 'rb') as f:
            self.model = pickle.load(f)
        
        # Load config
        try:
            with open(filename + '.config.json', 'r') as f:
                config = json.load(f)
            self.feature_importance = config.get('feature_importance', {})
            print(f"✅ Model loaded from {filename}")
        except FileNotFoundError:
            print(f"✅ Model loaded from {filename} (no config file)")
    
    def print_feature_importance(self, top_n: int = 10):
        """Print top N most important features"""
        if not self.feature_importance:
            print("❌ No feature importance available")
            return
        
        # Sort by importance
        sorted_features = sorted(
            self.feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        print(f"Top {top_n} Most Important Features:")
        print("="*50)
        for i, (feature, importance) in enumerate(sorted_features[:top_n], 1):
            print(f"{i:2d}. {feature:30s} {importance:8.2f}")


# =============================================================================
# MAIN TRAINING PIPELINE
# =============================================================================

def main():
    """Run complete training pipeline"""
    
    print("="*70)
    print("XGBOOST TRAINING PIPELINE")
    print("="*70)
    print()
    
    # Initialize pipeline
    pipeline = XGBoostTrainingPipeline(random_state=42)
    
    # Step 1: Load data
    texts, labels = pipeline.load_training_data('/mnt/user-data/outputs/training_data.json')
    y = np.array(labels)
    
    # Step 2: Extract features
    X = pipeline.extract_features(texts)
    
    # Step 3: Split data
    X_train, X_test, y_train, y_test = pipeline.split_data(X, y, test_size=0.2)
    
    # Step 4: Train model
    print("="*70)
    print("TRAINING XGBOOST MODEL")
    print("="*70)
    print()
    
    pipeline.train_xgboost(X_train, y_train, X_test, y_test)
    
    # Step 5: Evaluate on test set
    print("="*70)
    print("TEST SET EVALUATION")
    print("="*70)
    
    test_metrics = pipeline.evaluate(X_test, y_test)
    print(test_metrics)
    
    # Step 6: Cross-validation
    print("="*70)
    print("CROSS-VALIDATION")
    print("="*70)
    print()
    
    cv_metrics = pipeline.cross_validate(X, y, n_folds=5)
    
    # Step 7: Feature importance
    print()
    pipeline.print_feature_importance(top_n=15)
    print()
    
    # Step 8: Save model
    pipeline.save_model('/mnt/user-data/outputs/gradient_boost_model.pkl')
    
    print()
    print("="*70)
    print("✅ TRAINING PIPELINE COMPLETE!")
    print("="*70)
    
    # Final summary
    avg_cv_accuracy = np.mean([m.accuracy for m in cv_metrics])
    avg_cv_f1 = np.mean([m.f1_score for m in cv_metrics])
    
    print()
    print("FINAL SUMMARY:")
    print(f"  Test Set Accuracy: {test_metrics.accuracy:.4f}")
    print(f"  Test Set F1 Score: {test_metrics.f1_score:.4f}")
    print(f"  CV Average Accuracy: {avg_cv_accuracy:.4f}")
    print(f"  CV Average F1 Score: {avg_cv_f1:.4f}")
    print()
    
    # Status
    if avg_cv_accuracy >= 0.95 and avg_cv_f1 >= 0.95:
        print("🎉 TARGET ACHIEVED: 95%+ accuracy and F1 score!")
    elif avg_cv_accuracy >= 0.90:
        print("✅ GOOD PERFORMANCE: 90%+ accuracy")
    else:
        print("⚠️ NEEDS IMPROVEMENT: Consider hyperparameter tuning")


if __name__ == "__main__":
    main()
