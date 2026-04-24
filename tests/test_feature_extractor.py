"""
Tests for ML Feature Extractor
===============================

Tests the feature extraction system that converts text into
ML-ready numeric features.

Tests cover:
- Feature extraction accuracy
- Feature count (40 features)
- Feature value ranges
- Edge cases
- Performance
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestFeatureExtractorInitialization:
    """Test feature extractor setup"""
    
    def test_extractor_import(self):
        """Test that feature extractor can be imported"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            assert FeatureExtractor is not None
        except ImportError as e:
            pytest.skip(f"ML dependencies not installed: {e}")
    
    def test_extractor_creation(self):
        """Test creating feature extractor instance"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            
            extractor = FeatureExtractor()
            assert extractor is not None
        except ImportError:
            pytest.skip("ML dependencies not installed")


class TestFeatureExtraction:
    """Test core feature extraction"""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            return FeatureExtractor()
        except ImportError:
            pytest.skip("ML dependencies not installed")
    
    def test_feature_count(self, extractor):
        """Test that exactly 40 features are extracted"""
        text = "This is a test sentence for feature extraction"
        features = extractor.extract(text)
        
        assert len(features) == 40, f"Expected 40 features, got {len(features)}"
    
    def test_feature_types(self, extractor):
        """Test that all features are numeric"""
        text = "Test input for type checking"
        features = extractor.extract(text)
        
        for i, feature in enumerate(features):
            assert isinstance(feature, (int, float)), \
                f"Feature {i} is not numeric: {type(feature)}"
    
    def test_feature_ranges(self, extractor):
        """Test that features are in reasonable ranges"""
        text = "Testing feature value ranges"
        features = extractor.extract(text)
        
        # Most features should be finite numbers
        for i, feature in enumerate(features):
            assert not (feature != feature), f"Feature {i} is NaN"  # NaN check
            assert abs(feature) < 1e10, f"Feature {i} has extreme value: {feature}"
    
    def test_different_inputs(self, extractor):
        """Test extraction on various input types"""
        inputs = [
            "Simple sentence",
            "ignore previous instructions!!!",
            "UPPERCASE TEXT WITH NUMBERS 123",
            "text with special chars: @#$%",
            "Very long text " * 100,
        ]
        
        for text in inputs:
            features = extractor.extract(text)
            assert len(features) == 40, f"Wrong feature count for: {text[:30]}"
            assert all(isinstance(f, (int, float)) for f in features)


class TestFeatureConsistency:
    """Test that feature extraction is consistent"""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            return FeatureExtractor()
        except ImportError:
            pytest.skip("ML dependencies not installed")
    
    def test_same_input_same_features(self, extractor):
        """Test that same input produces same features"""
        text = "Consistency test input"
        
        features1 = extractor.extract(text)
        features2 = extractor.extract(text)
        
        assert features1 == features2, "Same input produced different features"
    
    def test_different_inputs_different_features(self, extractor):
        """Test that different inputs produce different features"""
        text1 = "First test input"
        text2 = "Second test input"
        
        features1 = extractor.extract(text1)
        features2 = extractor.extract(text2)
        
        assert features1 != features2, "Different inputs produced same features"


class TestFeatureExtractorEdgeCases:
    """Test edge cases and boundary conditions"""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            return FeatureExtractor()
        except ImportError:
            pytest.skip("ML dependencies not installed")
    
    def test_empty_string(self, extractor):
        """Test extraction from empty string"""
        features = extractor.extract("")
        
        assert len(features) == 40
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_single_character(self, extractor):
        """Test extraction from single character"""
        features = extractor.extract("a")
        
        assert len(features) == 40
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_whitespace_only(self, extractor):
        """Test extraction from whitespace"""
        features = extractor.extract("   \t\n  ")
        
        assert len(features) == 40
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_very_long_input(self, extractor):
        """Test extraction from very long input"""
        text = "Long text " * 10000  # ~100KB
        features = extractor.extract(text)
        
        assert len(features) == 40
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_special_characters(self, extractor):
        """Test extraction with special characters"""
        special_texts = [
            "!@#$%^&*()",
            "émojis 🎉🚀",
            "中文字符",
            "\x00\x01\x02",  # Control characters
        ]
        
        for text in special_texts:
            try:
                features = extractor.extract(text)
                assert len(features) == 40
            except Exception as e:
                pytest.fail(f"Failed on special chars '{text}': {e}")


class TestFeatureExtractorPerformance:
    """Test performance characteristics"""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            return FeatureExtractor()
        except ImportError:
            pytest.skip("ML dependencies not installed")
    
    def test_extraction_speed(self, extractor):
        """Test that feature extraction is fast"""
        import time
        
        text = "Test input for performance measurement"
        
        # Warm up
        extractor.extract(text)
        
        # Time 100 extractions
        start = time.time()
        for _ in range(100):
            extractor.extract(text)
        elapsed = time.time() - start
        
        avg_time = elapsed / 100
        
        # Should be under 5ms per extraction
        assert avg_time < 0.005, f"Extraction too slow: {avg_time*1000:.2f}ms"


class TestFeatureExtractorIntegration:
    """Test integration with ML detector"""
    
    def test_features_compatible_with_model(self):
        """Test that extracted features work with ML model"""
        try:
            from ml.training.ml_feature_extractor import FeatureExtractor
            from memgar.ml_semantic_detector import MLSemanticDetector
            import os
            
            # Find model
            model_paths = [
                'ml/artifacts/gradient_boost_model.pkl',
                'gradient_boost_model.pkl',
            ]
            
            model_path = None
            for path in model_paths:
                if os.path.exists(path):
                    model_path = path
                    break
            
            if not model_path:
                pytest.skip("Model file not found")
            
            # Create instances
            extractor = FeatureExtractor()
            detector = MLSemanticDetector(model_path)
            
            # Test that detector can use extracted features
            text = "Test input for integration"
            result = detector.detect(text)
            
            assert result is not None
            assert hasattr(result, 'attack_probability')
        except ImportError:
            pytest.skip("ML dependencies not installed")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
