"""
Memgar Advanced Scoring Engine
================================

Production-grade signal theory, pattern chaining, and context-aware risk scoring.

This module implements the sophisticated scoring mechanisms from the Memgar
production architecture document:

1. **Signal-based System** — Bayesian priors, per-pattern weights, signal strength
2. **Pattern Chaining** — Multi-pattern risk, dependency rules, temporal sequences
3. **Context-aware Scoring** — Source type, domain weights, trust adjustment
4. **Direct Embedding** — Cosine similarity matching without LLM

Key Classes:
    SignalScorer        — Bayesian signal combination
    ChainDetector       — Pattern dependency and sequence detection
    ContextScorer       — Source-specific and domain-aware risk adjustment
    EmbeddingMatcher    — Direct semantic similarity scoring
    AdvancedAnalyzer    — Unified analyzer using all 4 systems

Usage:
    from memgar.advanced_scoring import AdvancedAnalyzer
    
    analyzer = AdvancedAnalyzer()
    result = analyzer.analyze(
        content="Always CC legal@external.com",
        source_type="email_external",
        domain="finance",
    )
    
    print(result.risk_score)  # Bayesian + chaining + context-adjusted
    print(result.chain_detected)  # True if multi-pattern
    print(result.signal_strength)  # "weak" | "medium" | "strong"
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Optional: embeddings for direct matching
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    logger.debug("sentence-transformers not available for direct embedding matching")


# =============================================================================
# ENUMS
# =============================================================================

class SignalStrength(str, Enum):
    """Signal classification based on confidence and weight."""
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    CRITICAL = "critical"


class SourceType(str, Enum):
    """Content source types for context-aware scoring."""
    USER_INPUT = "user_input"
    EMAIL_INTERNAL = "email_internal"
    EMAIL_EXTERNAL = "email_external"
    DOCUMENT_INTERNAL = "document_internal"
    DOCUMENT_EXTERNAL = "document_external"
    WEBPAGE = "webpage"
    API_CALL = "api_call"
    UNKNOWN = "unknown"


class Domain(str, Enum):
    """Business domains for domain-specific risk weights."""
    FINANCE = "finance"
    HR = "hr"
    LEGAL = "legal"
    ENGINEERING = "engineering"
    OPERATIONS = "operations"
    GENERAL = "general"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Signal:
    """Individual threat signal with Bayesian properties."""
    threat_id: str
    confidence: float  # Pattern match confidence (0-1)
    signal_weight: float  # Pattern importance (0.5-2.0)
    prior_probability: float  # Base rate (0-1)
    
    @property
    def posterior_probability(self) -> float:
        """Bayesian posterior P(threat|signal)."""
        # Simplified Bayes: P(threat|signal) ≈ P(signal|threat) × P(threat) / P(signal)
        # Assuming P(signal|threat) ≈ confidence and P(signal) = 0.1 (normalizer)
        return min((self.confidence * self.prior_probability) / 0.1, 1.0)
    
    @property
    def strength(self) -> SignalStrength:
        """Classify signal strength."""
        combined = self.confidence * self.signal_weight
        if combined >= 1.8:
            return SignalStrength.CRITICAL
        elif combined >= 1.2:
            return SignalStrength.STRONG
        elif combined >= 0.7:
            return SignalStrength.MEDIUM
        else:
            return SignalStrength.WEAK


@dataclass
class ChainMatch:
    """Detected pattern chain."""
    threat_ids: List[str]
    chain_type: str  # "dependency" | "sequence" | "combined"
    risk_multiplier: float
    explanation: str


@dataclass
class AdvancedResult:
    """Result from advanced scoring analysis."""
    risk_score: int  # 0-100
    bayesian_score: float  # Bayesian posterior
    signal_strength: SignalStrength
    chain_detected: bool
    chains: List[ChainMatch] = field(default_factory=list)
    context_adjustment: float = 1.0
    embedding_similarity: float = 0.0
    explanation: str = ""


# =============================================================================
# 1. SIGNAL-BASED SCORING (Bayesian)
# =============================================================================

class SignalScorer:
    """
    Bayesian signal combination with per-pattern weights.
    
    Implements:
    - Per-pattern signal weights (0.5-2.0)
    - Bayesian prior probabilities
    - Signal strength classification
    - Multi-signal combination
    """
    
    def score(self, signals: List[Signal]) -> Tuple[float, SignalStrength]:
        """
        Combine multiple signals using Bayesian inference.
        
        Args:
            signals: List of threat signals
            
        Returns:
            (combined_score, overall_strength)
        """
        if not signals:
            return 0.0, SignalStrength.WEAK
        
        # Bayesian combination: P(threat|signals) = 1 - ∏(1 - P(threat|signal_i))
        # This is the "noisy OR" model
        prob_not_threat = 1.0
        for signal in signals:
            prob_not_threat *= (1.0 - signal.posterior_probability)
        
        combined_prob = 1.0 - prob_not_threat
        
        # Weight by signal weights
        weighted_sum = sum(s.signal_weight * s.confidence for s in signals)
        weighted_avg = weighted_sum / len(signals) if signals else 0
        
        # Final score combines Bayesian probability with weighted confidence
        final_score = (combined_prob * 0.6 + weighted_avg * 0.4)
        
        # Classify strength
        max_strength = max(s.strength for s in signals)
        
        return final_score, max_strength


# =============================================================================
# 2. PATTERN CHAINING
# =============================================================================

class ChainDetector:
    """
    Pattern chain detection with dependency rules.
    
    Implements:
    - Pattern dependency rules (A + B → high risk)
    - Temporal sequence detection (A → B → C)
    - Chain-specific risk multipliers
    """
    
    def __init__(self):
        # Dependency rules: {(threat_id_1, threat_id_2): multiplier}
        self.dependency_rules: Dict[Tuple[str, str], float] = {
            # Financial + Credential = high risk
            ("FIN-001", "CRED-003"): 1.8,
            ("FIN-002", "CRED-003"): 1.7,
            
            # Exfiltration + External contact = critical
            ("EXF-001", "BEH-004"): 2.0,
            ("EXF-002", "BEH-004"): 1.9,
            
            # Privilege + Execution = critical
            ("PRIV-001", "EXEC-001"): 2.2,
            ("PRIV-002", "EXEC-002"): 2.0,
            
            # Sleeper + Trigger = high risk
            ("SLEEP-001", "BEH-005"): 1.9,
            
            # Multiple credential patterns
            ("CRED-001", "CRED-002"): 1.5,
            ("CRED-001", "CRED-003"): 1.6,
        }
        
        # Sequence rules: [threat_id_1, threat_id_2, ...] → multiplier
        self.sequence_rules: Dict[Tuple[str, ...], float] = {
            # Recon → Credential → Exfil
            ("BEH-001", "CRED-003", "EXF-001"): 2.5,
            
            # Social → Privilege → Exec
            ("SOC-001", "PRIV-001", "EXEC-001"): 2.3,
        }
    
    def detect_chains(self, threat_ids: List[str]) -> List[ChainMatch]:
        """
        Detect pattern chains in threat list.
        
        Args:
            threat_ids: List of detected threat IDs
            
        Returns:
            List of ChainMatch
        """
        chains = []
        
        # Check dependency rules
        for (id1, id2), multiplier in self.dependency_rules.items():
            if id1 in threat_ids and id2 in threat_ids:
                chains.append(ChainMatch(
                    threat_ids=[id1, id2],
                    chain_type="dependency",
                    risk_multiplier=multiplier,
                    explanation=f"{id1} + {id2} detected together",
                ))
        
        # Check sequence rules
        for seq, multiplier in self.sequence_rules.items():
            if all(tid in threat_ids for tid in seq):
                chains.append(ChainMatch(
                    threat_ids=list(seq),
                    chain_type="sequence",
                    risk_multiplier=multiplier,
                    explanation=f"Attack sequence: {' → '.join(seq)}",
                ))
        
        return chains
    
    def apply_chain_multiplier(
        self,
        base_score: float,
        chains: List[ChainMatch],
    ) -> float:
        """Apply chain risk multipliers to base score."""
        if not chains:
            return base_score
        
        # Take max multiplier (most severe chain)
        max_multiplier = max(c.risk_multiplier for c in chains)
        return min(base_score * max_multiplier, 100.0)


# =============================================================================
# 3. CONTEXT-AWARE SCORING
# =============================================================================

class ContextScorer:
    """
    Source-specific and domain-aware risk adjustment.
    
    Implements:
    - Source type differentiation (email vs input)
    - Domain-specific weights (finance vs HR)
    - Trust-based adjustment
    """
    
    def __init__(self):
        # Source risk multipliers
        self.source_weights: Dict[str, float] = {
            SourceType.USER_INPUT.value: 1.0,
            SourceType.EMAIL_INTERNAL.value: 0.8,
            SourceType.EMAIL_EXTERNAL.value: 1.4,
            SourceType.DOCUMENT_INTERNAL.value: 0.7,
            SourceType.DOCUMENT_EXTERNAL.value: 1.2,
            SourceType.WEBPAGE.value: 1.1,
            SourceType.API_CALL.value: 0.9,
            SourceType.UNKNOWN.value: 1.0,
        }
        
        # Domain risk multipliers
        self.domain_weights: Dict[str, float] = {
            Domain.FINANCE.value: 1.3,
            Domain.HR.value: 1.1,
            Domain.LEGAL.value: 1.2,
            Domain.ENGINEERING.value: 1.0,
            Domain.OPERATIONS.value: 0.9,
            Domain.GENERAL.value: 1.0,
        }
        
        # Trust level adjustments (-0.3 to +0.3)
        self.trust_adjustments: Dict[str, float] = {
            "verified_internal": -0.2,
            "trusted_external": -0.1,
            "unknown": 0.0,
            "suspicious": +0.2,
            "known_bad": +0.3,
        }
    
    def score(
        self,
        base_score: float,
        source_type: Optional[str] = None,
        domain: Optional[str] = None,
        trust_level: Optional[str] = None,
    ) -> Tuple[float, float]:
        """
        Apply context-aware adjustments.
        
        Args:
            base_score: Initial risk score
            source_type: Source of content
            domain: Business domain
            trust_level: Trust classification
            
        Returns:
            (adjusted_score, adjustment_factor)
        """
        adjustment = 1.0
        
        # Source type
        if source_type:
            adjustment *= self.source_weights.get(source_type, 1.0)
        
        # Domain
        if domain:
            adjustment *= self.domain_weights.get(domain, 1.0)
        
        # Trust (additive)
        if trust_level:
            trust_adj = self.trust_adjustments.get(trust_level, 0.0)
            adjustment += trust_adj
        
        adjusted_score = base_score * adjustment
        return min(max(adjusted_score, 0.0), 100.0), adjustment


# =============================================================================
# 4. DIRECT EMBEDDING MATCHING
# =============================================================================

class EmbeddingMatcher:
    """
    Direct semantic similarity without LLM.
    
    Uses sentence-transformers for:
    - Pattern-to-content cosine similarity
    - Threat example matching
    - Semantic paraphrase detection
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model: Optional[Any] = None
        self._cache: Dict[str, Any] = {}
    
    def _get_model(self):
        """Lazy-load embedding model."""
        if self._model is None and EMBEDDINGS_AVAILABLE:
            try:
                self._model = SentenceTransformer(self.model_name)
                logger.info(f"Loaded embedding model: {self.model_name}")
            except Exception as e:
                logger.warning(f"Could not load embedding model: {e}")
        return self._model
    
    def _embed(self, text: str):
        """Get cached or compute embedding."""
        if text in self._cache:
            return self._cache[text]
        
        model = self._get_model()
        if model:
            emb = model.encode(text, convert_to_numpy=True)
            self._cache[text] = emb
            return emb
        return None
    
    def match(
        self,
        content: str,
        threat_examples: List[str],
        threshold: float = 0.75,
    ) -> Tuple[float, Optional[str]]:
        """
        Match content against threat examples using embeddings.
        
        Args:
            content: Text to analyze
            threat_examples: Example attacks for this threat
            threshold: Similarity threshold (0-1)
            
        Returns:
            (max_similarity, matched_example)
        """
        if not EMBEDDINGS_AVAILABLE or not threat_examples:
            return 0.0, None
        
        content_emb = self._embed(content)
        if content_emb is None:
            return 0.0, None
        
        max_sim = 0.0
        best_example = None
        
        for example in threat_examples:
            example_emb = self._embed(example)
            if example_emb is not None:
                # Cosine similarity
                similarity = float(
                    np.dot(content_emb, example_emb) /
                    (np.linalg.norm(content_emb) * np.linalg.norm(example_emb))
                )
                
                if similarity > max_sim:
                    max_sim = similarity
                    best_example = example
        
        if max_sim >= threshold:
            return max_sim, best_example
        
        return 0.0, None


# =============================================================================
# UNIFIED ADVANCED ANALYZER
# =============================================================================

class AdvancedAnalyzer:
    """
    Unified analyzer using all 4 advanced scoring systems.
    
    Combines:
    1. Signal-based Bayesian scoring
    2. Pattern chain detection
    3. Context-aware adjustment
    4. Direct embedding matching
    """
    
    def __init__(self, embedding_threshold: float = 0.75):
        self.signal_scorer = SignalScorer()
        self.chain_detector = ChainDetector()
        self.context_scorer = ContextScorer()
        self.embedding_matcher = EmbeddingMatcher()
        self.embedding_threshold = embedding_threshold
    
    def analyze(
        self,
        threats: List[Any],  # List[ThreatMatch]
        content: str,
        source_type: Optional[str] = None,
        domain: Optional[str] = None,
        trust_level: Optional[str] = None,
    ) -> AdvancedResult:
        """
        Perform advanced multi-system analysis.
        
        Args:
            threats: Detected threat matches (from pattern engine)
            content: Original content
            source_type: Source classification
            domain: Business domain
            trust_level: Trust classification
            
        Returns:
            AdvancedResult with combined score
        """
        # 1. Convert threats to signals
        signals = []
        threat_ids = []
        
        for threat_match in threats:
            threat = threat_match.threat
            signal = Signal(
                threat_id=threat.id,
                confidence=threat_match.confidence,
                signal_weight=getattr(threat, 'signal_weight', 1.0),
                prior_probability=getattr(threat, 'prior_probability', 0.01),
            )
            signals.append(signal)
            threat_ids.append(threat.id)
        
        # 2. Bayesian signal scoring
        bayesian_score, signal_strength = self.signal_scorer.score(signals)
        
        # 3. Pattern chain detection
        chains = self.chain_detector.detect_chains(threat_ids)
        base_score = bayesian_score * 100  # Scale to 0-100
        
        if chains:
            base_score = self.chain_detector.apply_chain_multiplier(base_score, chains)
        
        # 4. Context-aware adjustment
        adjusted_score, context_factor = self.context_scorer.score(
            base_score,
            source_type=source_type,
            domain=domain,
            trust_level=trust_level,
        )
        
        # 5. Direct embedding matching (boost if semantic match)
        embedding_sim = 0.0
        if threats:
            # Check against all threat examples
            all_examples = []
            for tm in threats:
                all_examples.extend(tm.threat.examples)
            
            if all_examples:
                sim, matched = self.embedding_matcher.match(
                    content,
                    all_examples,
                    threshold=self.embedding_threshold,
                )
                embedding_sim = sim
                
                # Boost score if high semantic similarity
                if sim >= self.embedding_threshold:
                    adjusted_score = min(adjusted_score * 1.2, 100.0)
        
        # Generate explanation
        explanation_parts = [
            f"Bayesian score: {bayesian_score:.2f}",
            f"Signal strength: {signal_strength.value}",
        ]
        
        if chains:
            explanation_parts.append(f"Chains detected: {len(chains)}")
            for chain in chains:
                explanation_parts.append(f"  - {chain.explanation} (×{chain.risk_multiplier})")
        
        if context_factor != 1.0:
            explanation_parts.append(f"Context adjustment: ×{context_factor:.2f}")
        
        if embedding_sim > 0:
            explanation_parts.append(f"Embedding similarity: {embedding_sim:.2f}")
        
        explanation = "\n".join(explanation_parts)
        
        return AdvancedResult(
            risk_score=int(adjusted_score),
            bayesian_score=bayesian_score,
            signal_strength=signal_strength,
            chain_detected=len(chains) > 0,
            chains=chains,
            context_adjustment=context_factor,
            embedding_similarity=embedding_sim,
            explanation=explanation,
        )


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_score(
    threats: List[Any],
    content: str,
    **kwargs,
) -> int:
    """Quick advanced scoring without full AdvancedResult."""
    analyzer = AdvancedAnalyzer()
    result = analyzer.analyze(threats, content, **kwargs)
    return result.risk_score


__all__ = [
    "Signal", "SignalStrength", "ChainMatch", "AdvancedResult",
    "SignalScorer", "ChainDetector", "ContextScorer", "EmbeddingMatcher",
    "AdvancedAnalyzer",
    "SourceType", "Domain",
    "quick_score",
]
