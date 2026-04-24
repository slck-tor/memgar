"""
Tests for Continuous Learning System
=====================================

Tests the autonomous learning and model improvement system.

Tests cover:
- Feedback collection
- Model retraining triggers
- Drift detection
- Version management
- Auto-improvement cycle
"""

import pytest
import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestContinuousLearningImport:
    """Test continuous learning module import"""
    
    def test_module_import(self):
        """Test that continuous learning module can be imported"""
        try:
            from ml.continuous_learning import ContinuousLearning
            assert ContinuousLearning is not None
        except ImportError as e:
            pytest.skip(f"Continuous learning module not available: {e}")
    
    def test_smart_detector_import(self):
        """Test that smart detector can be imported"""
        try:
            from ml.continuous_learning import SmartDetector
            assert SmartDetector is not None
        except ImportError as e:
            pytest.skip(f"Smart detector not available: {e}")


class TestContinuousLearningInitialization:
    """Test CL system initialization"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        temp = tempfile.mkdtemp()
        yield temp
        shutil.rmtree(temp, ignore_errors=True)
    
    def test_cl_creation(self, temp_dir):
        """Test creating continuous learning instance"""
        try:
            from ml.continuous_learning import ContinuousLearning
            
            cl = ContinuousLearning(
                model_path=os.path.join(temp_dir, 'model.pkl'),
                feedback_dir=os.path.join(temp_dir, 'feedback'),
                min_feedback_count=10
            )
            
            assert cl is not None
        except ImportError:
            pytest.skip("Continuous learning not available")
    
    def test_cl_creates_directories(self, temp_dir):
        """Test that CL creates necessary directories"""
        try:
            from ml.continuous_learning import ContinuousLearning
            
            feedback_dir = os.path.join(temp_dir, 'feedback')
            
            cl = ContinuousLearning(
                model_path=os.path.join(temp_dir, 'model.pkl'),
                feedback_dir=feedback_dir,
                min_feedback_count=10
            )
            
            # Should create feedback directory
            assert os.path.exists(feedback_dir), "Feedback directory not created"
        except ImportError:
            pytest.skip("Continuous learning not available")


class TestFeedbackCollection:
    """Test feedback collection mechanism"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        temp = tempfile.mkdtemp()
        yield temp
        shutil.rmtree(temp, ignore_errors=True)
    
    @pytest.fixture
    def cl_system(self, temp_dir):
        """Create CL system instance"""
        try:
            from ml.continuous_learning import ContinuousLearning
            
            return ContinuousLearning(
                model_path=os.path.join(temp_dir, 'model.pkl'),
                feedback_dir=os.path.join(temp_dir, 'feedback'),
                min_feedback_count=5
            )
        except ImportError:
            pytest.skip("Continuous learning not available")
    
    def test_collect_positive_feedback(self, cl_system):
        """Test collecting positive feedback"""
        cl_system.collect_feedback(
            text="test input",
            predicted_label=1,
            actual_label=1,
            confidence=0.95
        )
        
        # Feedback should be stored
        assert cl_system.feedback_count() > 0
    
    def test_collect_negative_feedback(self, cl_system):
        """Test collecting negative (correction) feedback"""
        cl_system.collect_feedback(
            text="test input",
            predicted_label=1,
            actual_label=0,  # Correction
            confidence=0.85
        )
        
        # Should store correction
        assert cl_system.feedback_count() > 0
    
    def test_feedback_persistence(self, cl_system, temp_dir):
        """Test that feedback is saved to disk"""
        cl_system.collect_feedback(
            text="persistent test",
            predicted_label=1,
            actual_label=1,
            confidence=0.90
        )
        
        # Check that feedback files exist
        feedback_dir = os.path.join(temp_dir, 'feedback')
        files = os.listdir(feedback_dir)
        
        assert len(files) > 0, "No feedback files created"


class TestDriftDetection:
    """Test model drift detection"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        temp = tempfile.mkdtemp()
        yield temp
        shutil.rmtree(temp, ignore_errors=True)
    
    @pytest.fixture
    def cl_system(self, temp_dir):
        """Create CL system instance"""
        try:
            from ml.continuous_learning import ContinuousLearning
            
            return ContinuousLearning(
                model_path=os.path.join(temp_dir, 'model.pkl'),
                feedback_dir=os.path.join(temp_dir, 'feedback'),
                drift_threshold=0.15
            )
        except ImportError:
            pytest.skip("Continuous learning not available")
    
    def test_no_drift_when_accurate(self, cl_system):
        """Test no drift detection when model is accurate"""
        # Add accurate feedback
        for i in range(10):
            cl_system.collect_feedback(
                text=f"test {i}",
                predicted_label=1,
                actual_label=1,
                confidence=0.95
            )
        
        drift = cl_system.check_drift()
        assert not drift, "False drift detection on accurate predictions"
    
    def test_drift_when_inaccurate(self, cl_system):
        """Test drift detection when model becomes inaccurate"""
        # Add many incorrect predictions
        for i in range(20):
            cl_system.collect_feedback(
                text=f"test {i}",
                predicted_label=1,
                actual_label=0,  # All wrong
                confidence=0.85
            )
        
        drift = cl_system.check_drift()
        assert drift, "Failed to detect model drift"


class TestAutoRetraining:
    """Test automatic retraining triggers"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        temp = tempfile.mkdtemp()
        yield temp
        shutil.rmtree(temp, ignore_errors=True)
    
    @pytest.fixture
    def cl_system(self, temp_d
