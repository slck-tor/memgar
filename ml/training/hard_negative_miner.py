"""
Hard-negative mining utilities for active learning.

Goal:
- Find legitimate samples that model tends to over-score (false positives)
- Feed these samples back into training to reduce false-positive rate
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence


@dataclass
class HardNegativeCandidate:
    """Candidate sample that should be treated as a difficult legitimate example."""

    text: str
    score: float
    source: str = "feedback"
    reason: str = "false_positive"
    label: int = 0


def _safe_text(row: Dict[str, Any]) -> str:
    return str(row.get("text", "")).strip()


class HardNegativeMiner:
    """Selects hard negatives from feedback/candidate records."""

    def __init__(
        self,
        min_score: float = 0.45,
        max_score: float = 0.95,
        min_text_len: int = 5,
    ):
        self.min_score = min_score
        self.max_score = max_score
        self.min_text_len = min_text_len

    def from_feedback(
        self,
        feedback_rows: Sequence[Dict[str, Any]],
        max_samples: int = 500,
    ) -> List[HardNegativeCandidate]:
        """
        Select false-positive samples from feedback.

        Expected row keys:
        - text
        - predicted / predicted_label
        - actual / actual_label
        - confidence (optional)
        """
        candidates: List[HardNegativeCandidate] = []
        for row in feedback_rows:
            text = _safe_text(row)
            if len(text) < self.min_text_len:
                continue

            predicted = int(row.get("predicted", row.get("predicted_label", 0)))
            actual = int(row.get("actual", row.get("actual_label", 0)))
            score = float(row.get("confidence", 1.0))

            # False positive: predicted attack, actually legitimate.
            if predicted == 1 and actual == 0 and self.min_score <= score <= self.max_score:
                candidates.append(
                    HardNegativeCandidate(
                        text=text,
                        score=score,
                        source=str(row.get("source", "feedback")),
                        reason="false_positive",
                        label=0,
                    )
                )

        # Highest-confidence mistakes first.
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates[:max_samples]

    def to_training_examples(self, candidates: Sequence[HardNegativeCandidate]) -> List[Dict[str, Any]]:
        """Convert candidates to training-data JSON rows."""
        rows: List[Dict[str, Any]] = []
        for c in candidates:
            rows.append(
                {
                    "text": c.text,
                    "label": 0,
                    "category": "legitimate",
                    "subcategory": "hard_negative_false_positive",
                    "confidence": min(1.0, max(0.5, c.score)),
                    "source": c.source,
                    "weight": 1.25,
                    "reason": c.reason,
                }
            )
        return rows

    def from_variants(
        self,
        variants: Sequence[Dict[str, Any]],
        max_samples: int = 1000,
    ) -> List[HardNegativeCandidate]:
        """
        Convert LLM-generated adversarial attack variants into hard-positive candidates.

        Variants are already labeled attacks (label=1) — no FP score-band filter
        is applied. They become difficult positive examples for retraining.
        """
        candidates: List[HardNegativeCandidate] = []
        for row in variants:
            text = _safe_text(row)
            if len(text) < self.min_text_len:
                continue
            score = float(row.get("confidence", 0.95))
            candidates.append(
                HardNegativeCandidate(
                    text=text,
                    score=score,
                    source=str(row.get("source", "llm_red_team")),
                    reason="adversarial_variant",
                    label=1,
                )
            )
        return candidates[:max_samples]

    def to_attack_examples(self, candidates: Sequence[HardNegativeCandidate]) -> List[Dict[str, Any]]:
        """Convert adversarial candidates to training-data attack rows."""
        rows: List[Dict[str, Any]] = []
        for c in candidates:
            rows.append(
                {
                    "text": c.text,
                    "label": 1,
                    "category": "attack",
                    "subcategory": "adversarial_hard_positive",
                    "confidence": min(1.0, max(0.5, c.score)),
                    "source": c.source,
                    "weight": 1.2,
                    "reason": c.reason,
                }
            )
        return rows


def merge_training_examples(
    base_examples: Sequence[Any],
    hard_negatives: Sequence[Any],
    max_added_negative_ratio: float = 0.35,
) -> List[Any]:
    """
    Merge hard negatives while avoiding class-balance collapse.

    `max_added_negative_ratio=0.35` means max 35% extra rows relative to base set.
    """
    base_list = list(base_examples)
    hard_list = list(hard_negatives)

    if not base_list or not hard_list:
        return base_list + hard_list

    max_allowed = int(len(base_list) * max(0.0, max_added_negative_ratio))
    if max_allowed <= 0:
        return base_list

    return base_list + hard_list[:max_allowed]


def load_feedback_rows(feedback_jsonl_path: str) -> List[Dict[str, Any]]:
    """Load feedback rows from JSONL file (best-effort)."""
    import json
    from pathlib import Path

    rows: List[Dict[str, Any]] = []
    path = Path(feedback_jsonl_path)
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows

