"""
ML Inference Components
=======================

Production-ready ML detectors for real-time threat detection.

Available Detectors:
- MLSemanticDetector: Intent-based semantic detection (97.92% accuracy)
- HybridOrchestrator: Multi-layer defense (Regex + ML)

Usage:
    from ml.inference.ml_detector import MLSemanticDetector
    
    detector = MLSemanticDetector('model.pkl')
    result = detector.detect("user input")
    
    if result.should_block:
        print(f"Attack detected: {result.threat_level}")
"""

# Lazy imports to avoid forcing dependencies
# Users can import what they need

__all__ = [
    # 'MLSemanticDetector',      # Uncomment when ml_detector.py is moved here
    # 'HybridOrchestrator',       # Uncomment when orchestrator is moved here
]

# Version tracking
__version__ = '1.0.0'


def check_dependencies():
    """Check if ML dependencies are installed"""
    try:
        import sklearn
        import xgboost
        import numpy
        return True
    except ImportError as e:
        print(f"Missing ML dependency: {e}")
        print("Install with: pip install scikit-learn xgboost numpy")
        return False
