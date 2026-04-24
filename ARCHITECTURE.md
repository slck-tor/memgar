# Architecture

## System Overview (Existing)
...

## ML Architecture (NEW)
### Components
- Feature Extractor (40 features)
- XGBoost Classifier
- Continuous Learning

### Data Flow
User Input → Feature Extraction → Model → Decision

### Integration Points
- Regex Layer (Layer 1)
- ML Layer (Layer 2)
- Hybrid Orchestrator

## Performance Characteristics
- Inference: <1ms
- Throughput: 1000+ req/sec
- Accuracy: 97.92%
