"""
Adversarial / red-team utilities.

- AttackGenerator: produces obfuscated/paraphrased variants of seed attacks via
  Anthropic Claude (online) or deterministic template mutations (offline).
- VariantCurator: deduplicates and clusters variants before retraining.
"""

from __future__ import annotations

from ml.adversarial.attack_generator import AttackGenerator
from ml.adversarial.variant_curator import VariantCurator

__all__ = ["AttackGenerator", "VariantCurator"]
