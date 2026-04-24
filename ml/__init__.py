"""
ML System for Memgar
====================

Machine learning components for advanced threat detection.

Components:
- inference/: Production ML detectors
- training/: Model training pipeline
- data/: Training datasets
- artifacts/: Trained models

Usage:
    # Import ML detector
    from ml.inference.ml_detector import MLSemanticDetector
    
    # Or lazy import to avoid dependencies
    detector = None
    try:
        from ml.inference.ml_detector import MLSemanticDetector
        detector = MLSemanticDetector('model.pkl')
    except ImportError:
        print("ML dependencies not installed")
"""

__version__ = '1.0.0'
__author__ = 'Memgar Security Team'

# Lazy imports - only load when explicitly imported
# This prevents forcing ML dependencies on users who don't need them
def get_ml_detector():
    """Lazy load ML detector to avoid dependency issues"""
    try:
        from ml.inference.ml_detector import MLSemanticDetector
        return MLSemanticDetector
    except ImportError as e:
        raise ImportError(
            "ML dependencies not installed. "
            "Install with: pip install scikit-learn xgboost numpy"
        ) from e


def get_training_pipeline():
    """Lazy load training pipeline"""
    try:
        from ml.training.train import XGBoostTrainingPipeline
        return XGBoostTrainingPipeline
    except ImportError as e:
        raise ImportError(
            "ML training dependencies not installed. "
            "Install with: pip install scikit-learn xgboost numpy pandas"
        ) from e


__all__ = [
    'get_ml_detector',
    'get_training_pipeline',
]
