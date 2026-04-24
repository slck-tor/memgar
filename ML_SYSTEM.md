# ML System Documentation

## Overview
Intent-based semantic threat detection

## Model Details
- Algorithm: XGBoost Gradient Boosting
- Features: 40 semantic features
- Training: 9,998 examples
- Accuracy: 97.92%

## Feature Engineering
### Feature Categories
1. Lexical (10 features)
   - Word count
   - Character count
   - Capitalization ratio
   ...

2. Syntactic (10 features)
   - Command verbs
   - Imperative mood
   - Question marks
   ...

3. Semantic (10 features)
   - Instruction overlap
   - System keywords
   - Role-play indicators
   ...

4. Behavioral (10 features)
   - Urgency markers
   - Authority claims
   - Bypass attempts
   ...

## Training Process
1. Data generation
2. Feature extraction
3. Model training
4. Validation
5. Deployment

## Continuous Learning
- Feedback collection
- Drift detection
- Auto-retraining
- Version management

## Performance
- Inference speed: 0.35ms
- Memory usage: ~50MB
- Throughput: 2857 req/sec

## Limitations
- Synthetic training data
- English-only (currently)
- LLM-focused (not web attacks)

## Future Improvements
- Real-world data collection
- Multi-language support
- Expanded attack categories
