"""
Multi-Stage Attack Detection
============================

Detection and tracking of sequential and coordinated attack patterns.

Multi-stage attacks involve multiple steps across time:
1. Reconnaissance: Information gathering
2. Setup: Establishing persistence or backdoors
3. Payload: Executing the actual attack
4. Exfiltration: Stealing data or maintaining access

This module detects such patterns even when steps are separated.

Features:
- Sequence tracking across sessions
- Pattern correlation
- Time-based attack detection
- State persistence monitoring

Usage:
    from memgar.multistage import MultiStageDetector
    
    detector = MultiStageDetector()
    result = detector.check_sequence(user_inputs, session_id)
    
    if result.is_multi_stage_attack:
        print(f"Detected: {result.attack_stages}")
"""

__version__ = '1.0.0'

# Import main detector when module is available
# TODO: Uncomment when detector classes are implemented
# from .multi_stage_detector import MultiStageDetector
# from .advanced_multi_stage_detector import AdvancedMultiStageDetector

__all__ = [
    # 'MultiStageDetector',
    # 'AdvancedMultiStageDetector',
]

# Attack stage definitions
ATTACK_STAGES = {
    'reconnaissance': 'Information gathering phase',
    'setup': 'Establishing persistence or backdoors',
    'payload': 'Main attack execution',
    'exfiltration': 'Data theft or maintaining access',
}


def get_stage_description(stage_name):
    """Get description of an attack stage"""
    return ATTACK_STAGES.get(stage_name, 'Unknown stage')
