# Testing Guide

## Quick Start
pytest tests/ -v

## Test Categories
### Unit Tests
- test_ml_detector.py
- test_feature_extractor.py
- test_scanner.py

### Integration Tests
- test_ml_integration.py
- test_hybrid_system.py

## Running Specific Tests
pytest tests/test_ml_detector.py -v
pytest tests/test_ml_detector.py::TestMLDetectorAttackDetection -v

## Coverage Reports
pytest tests/ --cov=memgar --cov=ml --cov-report=html

## CI/CD Integration
Example GitHub Actions workflow

## Troubleshooting
Common test failures and fixes
