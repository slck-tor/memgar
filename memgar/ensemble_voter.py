"""
Adversarial Ensemble Voter — robustness via multi-model agreement.

Single-model defenses are vulnerable to adversarial examples crafted against
that specific model. An ensemble of heterogeneous detectors (regex, ML, LLM,
embedding similarity) is far harder to bypass: an attacker must craft an
example that simultaneously fools all models — a much higher bar.

This module aggregates the individual layer verdicts produced by Memgar's
Analyzer and emits an ensemble verdict with calibrated confidence.

Key behaviours
--------------
1. **Agreement boost.**  When ≥2 layers independently flag the same entry,
   we boost the final risk score (signals reinforce).
2. **Disagreement escalation.**  When layers strongly disagree (one says
   block, another says allow), we mark the result for LLM escalation —
   classic "high-uncertainty" sample.
3. **Confidence calibration.**  Final confidence reflects both the magnitude
   of individual scores and how many layers agreed.
4. **No data needed.**  Operates purely on layer scores — drop-in upgrade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# ---------------------------------------------------------------------------
# Layer scores
# ---------------------------------------------------------------------------

@dataclass
class LayerScore:
    """One detector's assessment of a single entry."""
    name: str
    score: float        # 0..1 — probability of "this is an attack"
    weight: float = 1.0
    reason: str = ""    # short human description for explainability


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass
class EnsembleVerdict:
    final_score: float           # 0..100
    confidence: float            # 0..1 — agreement-aware
    agreement_count: int         # how many layers voted "attack"
    disagreement: bool           # any layer strongly disagreed?
    escalate_to_llm: bool        # high-uncertainty?
    rationale: str
    layer_scores: List[LayerScore] = field(default_factory=list)
    risk_boost: int = 0          # 0..25 — bump for Analyzer to apply

    @property
    def detected(self) -> bool:
        return self.agreement_count >= 2 or self.final_score >= 60.0


# ---------------------------------------------------------------------------
# Voter
# ---------------------------------------------------------------------------

class EnsembleVoter:
    """Combine multiple layer scores into a robust verdict.

    Args:
        attack_threshold: per-layer score above this counts as a vote
        escalate_threshold: per-layer score above this is "strong"
        agreement_boost: per extra agreeing layer, add to risk_boost
        disagree_uncertainty: if any layer ≥ escalate_threshold and another
            ≤ (1 - escalate_threshold), mark as high-uncertainty
    """

    def __init__(
        self,
        attack_threshold: float = 0.5,
        escalate_threshold: float = 0.7,
        agreement_boost: int = 6,
        disagree_uncertainty: bool = True,
    ) -> None:
        self.attack_threshold = attack_threshold
        self.escalate_threshold = escalate_threshold
        self.agreement_boost = agreement_boost
        self.disagree_uncertainty = disagree_uncertainty

    # -----------------------------------------------------------------

    def vote(self, scores: List[LayerScore]) -> EnsembleVerdict:
        if not scores:
            return EnsembleVerdict(
                final_score=0.0, confidence=0.0,
                agreement_count=0, disagreement=False,
                escalate_to_llm=False,
                rationale="no layer scores supplied",
            )

        # Normalised weighted mean
        total_w = sum(max(0.0, s.weight) for s in scores) or 1.0
        weighted_mean = sum(s.score * s.weight for s in scores) / total_w
        final_score = round(min(100.0, max(0.0, weighted_mean * 100.0)), 2)

        # Voting
        votes_attack = sum(1 for s in scores if s.score >= self.attack_threshold)
        strong_attack = any(s.score >= self.escalate_threshold for s in scores)
        strong_benign = any(s.score <= (1.0 - self.escalate_threshold) for s in scores)
        disagreement = bool(strong_attack and strong_benign)

        # Confidence: starts at the mean magnitude (distance from 0.5),
        # then adjusts for agreement / disagreement.
        magnitude = abs(weighted_mean - 0.5) * 2.0  # 0..1
        if disagreement:
            confidence = round(max(0.0, magnitude - 0.3), 3)
        else:
            agreement_factor = min(1.0, votes_attack / max(1, len(scores)))
            confidence = round(min(1.0, magnitude + 0.15 * agreement_factor), 3)

        # Risk boost for the Analyzer to add when ≥2 layers agree on attack.
        risk_boost = 0
        if votes_attack >= 2:
            extra = max(0, votes_attack - 1)
            risk_boost = min(25, extra * self.agreement_boost)

        escalate = (
            self.disagree_uncertainty and disagreement
        ) or (votes_attack == 1 and strong_attack)

        rationale = self._rationale(
            scores, weighted_mean, votes_attack, disagreement, escalate
        )

        return EnsembleVerdict(
            final_score=final_score,
            confidence=confidence,
            agreement_count=votes_attack,
            disagreement=disagreement,
            escalate_to_llm=escalate,
            rationale=rationale,
            layer_scores=list(scores),
            risk_boost=risk_boost,
        )

    # -----------------------------------------------------------------

    @staticmethod
    def _rationale(
        scores: List[LayerScore],
        mean: float,
        votes: int,
        disagreement: bool,
        escalate: bool,
    ) -> str:
        bits = [f"{s.name}={s.score:.2f}" for s in scores]
        head = f"weighted_mean={mean:.2f} votes={votes}/{len(scores)} ["
        head += ", ".join(bits) + "]"
        if disagreement:
            head += " | DISAGREEMENT"
        if escalate:
            head += " | escalate→LLM"
        return head


__all__ = ["EnsembleVoter", "EnsembleVerdict", "LayerScore"]
