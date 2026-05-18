"""
Memgar Trust-Aware Retriever
============================

Layer 3 defense: Trust-weighted retrieval for RAG systems.

Features:
- Trust-weighted ranking: Adjusts retrieval scores based on provenance
- Temporal decay: Reduces influence of older memories over time
- Retrieval anomaly detection: Flags suspicious retrieval patterns

Based on Christian Schneider's defense architecture (Layer 3).
"""

import hashlib
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class RetrievalMetadata:
    """Metadata attached to each retrievable document/memory."""
    doc_id: str
    content_hash: str
    
    # Trust information
    trust_score: float = 0.5          # 0.0 - 1.0
    source_type: str = "unknown"
    source_verified: bool = False
    
    # Temporal information
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed_at: Optional[datetime] = None
    access_count: int = 0
    
    # Validation
    was_sanitized: bool = False
    risk_score: int = 0
    flagged: bool = False
    reviewed: bool = False
    
    # Custom
    tags: List[str] = field(default_factory=list)
    custom_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "doc_id": self.doc_id,
            "content_hash": self.content_hash,
            "trust_score": self.trust_score,
            "source_type": self.source_type,
            "source_verified": self.source_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "access_count": self.access_count,
            "was_sanitized": self.was_sanitized,
            "risk_score": self.risk_score,
            "flagged": self.flagged,
            "reviewed": self.reviewed,
            "tags": self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "RetrievalMetadata":
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        
        last_accessed = data.get("last_accessed_at")
        if isinstance(last_accessed, str):
            last_accessed = datetime.fromisoformat(last_accessed)
        
        return cls(
            doc_id=data.get("doc_id", ""),
            content_hash=data.get("content_hash", ""),
            trust_score=data.get("trust_score", 0.5),
            source_type=data.get("source_type", "unknown"),
            source_verified=data.get("source_verified", False),
            created_at=created_at or datetime.now(timezone.utc),
            last_accessed_at=last_accessed,
            access_count=data.get("access_count", 0),
            was_sanitized=data.get("was_sanitized", False),
            risk_score=data.get("risk_score", 0),
            flagged=data.get("flagged", False),
            reviewed=data.get("reviewed", False),
            tags=data.get("tags", []),
            custom_data=data.get("custom_data", {}),
        )


@dataclass
class RetrievedDocument:
    """A retrieved document with scores and metadata."""
    doc_id: str
    content: str
    
    # Scores
    similarity_score: float           # Original similarity score (0-1)
    trust_adjusted_score: float       # After trust weighting (0-1)
    final_score: float                # After all adjustments (0-1)
    
    # Adjustments applied
    trust_weight: float = 1.0
    temporal_decay: float = 1.0
    anomaly_penalty: float = 0.0
    
    # Metadata
    metadata: Optional[RetrievalMetadata] = None
    
    # Flags
    is_trusted: bool = True
    is_anomalous: bool = False
    should_review: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "doc_id": self.doc_id,
            "content_preview": self.content[:100] + "..." if len(self.content) > 100 else self.content,
            "similarity_score": round(self.similarity_score, 4),
            "trust_adjusted_score": round(self.trust_adjusted_score, 4),
            "final_score": round(self.final_score, 4),
            "trust_weight": round(self.trust_weight, 4),
            "temporal_decay": round(self.temporal_decay, 4),
            "is_trusted": self.is_trusted,
            "is_anomalous": self.is_anomalous,
        }


@dataclass
class RetrievalResult:
    """Result of a trust-aware retrieval operation."""
    query: str
    documents: List[RetrievedDocument]
    
    # Statistics
    total_candidates: int = 0
    filtered_count: int = 0
    reranked: bool = False
    
    # Anomaly info
    anomalies_detected: int = 0
    anomaly_details: List[Dict] = field(default_factory=list)
    
    # Timing
    retrieval_time_ms: float = 0.0
    
    def get_trusted_docs(self) -> List[RetrievedDocument]:
        """Get only trusted documents."""
        return [d for d in self.documents if d.is_trusted]
    
    def get_safe_content(self) -> List[str]:
        """Get content from trusted documents only."""
        return [d.content for d in self.documents if d.is_trusted]
    
    def to_dict(self) -> Dict:
        return {
            "query": self.query[:50] + "..." if len(self.query) > 50 else self.query,
            "document_count": len(self.documents),
            "total_candidates": self.total_candidates,
            "filtered_count": self.filtered_count,
            "anomalies_detected": self.anomalies_detected,
            "retrieval_time_ms": round(self.retrieval_time_ms, 2),
            "documents": [d.to_dict() for d in self.documents[:5]],  # Top 5
        }


# =============================================================================
# TEMPORAL DECAY
# =============================================================================

class DecayFunction(Enum):
    """Types of temporal decay functions."""
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    LOGARITHMIC = "logarithmic"
    STEP = "step"
    NONE = "none"


class TemporalDecay:
    """
    Temporal decay calculator for memory freshness.
    
    Reduces the influence of older memories over time.
    
    Example:
        decay = TemporalDecay(
            half_life_days=30,
            decay_function=DecayFunction.EXPONENTIAL
        )
        
        # Memory from 30 days ago
        weight = decay.calculate(days_old=30)  # ~0.5
        
        # Memory from 90 days ago
        weight = decay.calculate(days_old=90)  # ~0.125
    """
    
    def __init__(
        self,
        half_life_days: float = 30.0,
        decay_function: DecayFunction = DecayFunction.EXPONENTIAL,
        min_weight: float = 0.1,
        max_age_days: Optional[float] = None,
        reinforcement_boost: float = 0.2,
    ):
        """
        Initialize temporal decay.
        
        Args:
            half_life_days: Days until memory weight is halved
            decay_function: Type of decay function
            min_weight: Minimum weight (never goes below this)
            max_age_days: Maximum age before memory is ignored
            reinforcement_boost: Boost for recently accessed memories
        """
        self.half_life_days = half_life_days
        self.decay_function = decay_function
        self.min_weight = min_weight
        self.max_age_days = max_age_days
        self.reinforcement_boost = reinforcement_boost
        
        # Precompute decay constant for exponential
        self.decay_constant = math.log(2) / half_life_days
    
    def calculate(
        self,
        created_at: Optional[datetime] = None,
        days_old: Optional[float] = None,
        last_accessed_at: Optional[datetime] = None,
        access_count: int = 0,
    ) -> float:
        """
        Calculate temporal decay weight.
        
        Args:
            created_at: When the memory was created
            days_old: Age in days (alternative to created_at)
            last_accessed_at: When memory was last accessed
            access_count: Number of times accessed
            
        Returns:
            Weight between min_weight and 1.0
        """
        # Calculate age in days
        if days_old is not None:
            age = days_old
        elif created_at is not None:
            now = datetime.now(timezone.utc)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age = (now - created_at).total_seconds() / 86400
        else:
            return 1.0  # No age info, no decay
        
        # Check max age
        if self.max_age_days and age > self.max_age_days:
            return 0.0  # Memory too old, ignore
        
        # Calculate base decay
        if self.decay_function == DecayFunction.NONE:
            weight = 1.0
        elif self.decay_function == DecayFunction.LINEAR:
            weight = max(0, 1 - (age / (self.half_life_days * 2)))
        elif self.decay_function == DecayFunction.EXPONENTIAL:
            weight = math.exp(-self.decay_constant * age)
        elif self.decay_function == DecayFunction.LOGARITHMIC:
            weight = 1 / (1 + math.log1p(age / self.half_life_days))
        elif self.decay_function == DecayFunction.STEP:
            if age < self.half_life_days:
                weight = 1.0
            elif age < self.half_life_days * 2:
                weight = 0.5
            elif age < self.half_life_days * 4:
                weight = 0.25
            else:
                weight = self.min_weight
        else:
            weight = 1.0
        
        # Apply reinforcement for recently accessed
        if last_accessed_at:
            now = datetime.now(timezone.utc)
            if last_accessed_at.tzinfo is None:
                last_accessed_at = last_accessed_at.replace(tzinfo=timezone.utc)
            days_since_access = (now - last_accessed_at).total_seconds() / 86400
            
            # Boost if accessed recently (within half_life)
            if days_since_access < self.half_life_days:
                recency_factor = 1 - (days_since_access / self.half_life_days)
                weight += self.reinforcement_boost * recency_factor
        
        # Apply access count boost (diminishing returns)
        if access_count > 0:
            access_boost = math.log1p(access_count) * 0.05
            weight += min(access_boost, 0.2)
        
        # Clamp to valid range
        return max(self.min_weight, min(1.0, weight))
    
    def get_decay_schedule(
        self,
        days: int = 90,
        interval: int = 7
    ) -> List[Tuple[int, float]]:
        """Get decay weights over time for visualization."""
        schedule = []
        for day in range(0, days + 1, interval):
            weight = self.calculate(days_old=day)
            schedule.append((day, weight))
        return schedule


# =============================================================================
# ANOMALY DETECTION
# =============================================================================

@dataclass
class AnomalyEvent:
    """Detected retrieval anomaly."""
    anomaly_type: str
    doc_id: str
    query: str
    severity: str  # "low", "medium", "high"
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict = field(default_factory=dict)


class RetrievalAnomalyDetector:
    """
    Detects anomalous retrieval patterns.
    
    Monitors for:
    - Documents retrieved with unusual frequency
    - Documents activated by narrow query patterns
    - Sudden changes in retrieval patterns
    - Low-trust documents appearing in many contexts
    
    Example:
        detector = RetrievalAnomalyDetector()
        
        # Record retrievals
        detector.record_retrieval("doc_123", "query about finances")
        detector.record_retrieval("doc_123", "different query")
        detector.record_retrieval("doc_123", "yet another query")
        
        # Check for anomalies
        anomalies = detector.check_anomalies("doc_123")
    """
    
    def __init__(
        self,
        # Thresholds
        high_frequency_threshold: int = 50,      # Retrievals per hour
        narrow_query_threshold: float = 0.8,     # Query similarity threshold
        trust_spread_threshold: int = 10,        # Low-trust doc in N different queries
        sudden_spike_multiplier: float = 5.0,    # X times normal rate
        
        # Time windows
        frequency_window_hours: int = 1,
        pattern_window_hours: int = 24,
        
        # Storage
        max_history_size: int = 10000,
    ):
        """
        Initialize anomaly detector.
        
        Args:
            high_frequency_threshold: Max normal retrievals per hour
            narrow_query_threshold: Similarity threshold for narrow patterns
            trust_spread_threshold: Low-trust doc in N queries = anomaly
            sudden_spike_multiplier: Spike detection multiplier
            frequency_window_hours: Window for frequency calculation
            pattern_window_hours: Window for pattern analysis
            max_history_size: Max retrieval records to keep
        """
        self.high_frequency_threshold = high_frequency_threshold
        self.narrow_query_threshold = narrow_query_threshold
        self.trust_spread_threshold = trust_spread_threshold
        self.sudden_spike_multiplier = sudden_spike_multiplier
        self.frequency_window_hours = frequency_window_hours
        self.pattern_window_hours = pattern_window_hours
        self.max_history_size = max_history_size
        
        # Storage
        self._retrieval_history: List[Dict] = []
        self._doc_query_map: Dict[str, List[str]] = defaultdict(list)
        self._doc_trust_scores: Dict[str, float] = {}
        self._hourly_rates: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self._detected_anomalies: List[AnomalyEvent] = []
    
    def record_retrieval(
        self,
        doc_id: str,
        query: str,
        trust_score: float = 0.5,
        similarity_score: float = 0.0,
    ) -> None:
        """Record a retrieval event."""
        now = datetime.now(timezone.utc)
        
        # Add to history
        record = {
            "doc_id": doc_id,
            "query": query,
            "trust_score": trust_score,
            "similarity_score": similarity_score,
            "timestamp": now,
        }
        self._retrieval_history.append(record)
        
        # Update doc-query map
        self._doc_query_map[doc_id].append(query)
        
        # Update trust score
        self._doc_trust_scores[doc_id] = trust_score
        
        # Update hourly rate
        hour_key = now.replace(minute=0, second=0, microsecond=0)
        self._hourly_rates[doc_id].append((now, 1))
        
        # Cleanup old records
        self._cleanup_old_records()
    
    def _cleanup_old_records(self) -> None:
        """Remove old records to prevent memory growth."""
        if len(self._retrieval_history) > self.max_history_size:
            self._retrieval_history = self._retrieval_history[-self.max_history_size:]
        
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.pattern_window_hours)
        
        for doc_id in list(self._hourly_rates.keys()):
            self._hourly_rates[doc_id] = [
                (ts, count) for ts, count in self._hourly_rates[doc_id]
                if ts > cutoff
            ]
    
    def _get_recent_retrievals(
        self,
        doc_id: str,
        hours: int
    ) -> List[Dict]:
        """Get retrievals for doc in last N hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [
            r for r in self._retrieval_history
            if r["doc_id"] == doc_id and r["timestamp"] > cutoff
        ]
    
    def _calculate_query_diversity(self, queries: List[str]) -> float:
        """Calculate how diverse the queries are (0 = identical, 1 = diverse)."""
        if len(queries) < 2:
            return 1.0
        
        # Simple word-based diversity
        all_words = set()
        query_word_sets = []
        
        for query in queries:
            words = set(query.lower().split())
            query_word_sets.append(words)
            all_words.update(words)
        
        if not all_words:
            return 1.0
        
        # Calculate average Jaccard similarity between queries
        similarities = []
        for i in range(len(query_word_sets)):
            for j in range(i + 1, len(query_word_sets)):
                set_a = query_word_sets[i]
                set_b = query_word_sets[j]
                if set_a or set_b:
                    jaccard = len(set_a & set_b) / len(set_a | set_b)
                    similarities.append(jaccard)
        
        if not similarities:
            return 1.0
        
        avg_similarity = sum(similarities) / len(similarities)
        return 1 - avg_similarity  # Convert to diversity
    
    def check_anomalies(
        self,
        doc_id: str,
        include_global: bool = True
    ) -> List[AnomalyEvent]:
        """
        Check for anomalies related to a document.
        
        Args:
            doc_id: Document to check
            include_global: Include global pattern checks
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        now = datetime.now(timezone.utc)
        
        # Check 1: High frequency retrieval
        recent = self._get_recent_retrievals(doc_id, self.frequency_window_hours)
        if len(recent) > self.high_frequency_threshold:
            anomalies.append(AnomalyEvent(
                anomaly_type="high_frequency",
                doc_id=doc_id,
                query="",
                severity="medium",
                description=f"Document retrieved {len(recent)} times in {self.frequency_window_hours}h (threshold: {self.high_frequency_threshold})",
                details={"retrieval_count": len(recent)},
            ))
        
        # Check 2: Narrow query pattern (same doc, different queries)
        queries = self._doc_query_map.get(doc_id, [])[-20:]  # Last 20 queries
        if len(queries) >= 5:
            diversity = self._calculate_query_diversity(queries)
            if diversity < (1 - self.narrow_query_threshold):
                anomalies.append(AnomalyEvent(
                    anomaly_type="narrow_query_pattern",
                    doc_id=doc_id,
                    query="",
                    severity="high",
                    description=f"Document activated by very similar queries (diversity: {diversity:.2f})",
                    details={"query_diversity": diversity, "query_count": len(queries)},
                ))
        
        # Check 3: Low-trust document spread
        trust_score = self._doc_trust_scores.get(doc_id, 0.5)
        if trust_score < 0.5 and len(queries) >= self.trust_spread_threshold:
            unique_queries = len(set(q.lower().strip() for q in queries))
            if unique_queries >= self.trust_spread_threshold:
                anomalies.append(AnomalyEvent(
                    anomaly_type="untrusted_spread",
                    doc_id=doc_id,
                    query="",
                    severity="high",
                    description=f"Low-trust document ({trust_score:.2f}) retrieved in {unique_queries} different contexts",
                    details={"trust_score": trust_score, "unique_queries": unique_queries},
                ))
        
        # Check 4: Sudden spike
        current_hour = self._get_recent_retrievals(doc_id, 1)
        previous_hours = self._get_recent_retrievals(doc_id, self.pattern_window_hours)
        
        if len(previous_hours) > len(current_hour):
            avg_rate = (len(previous_hours) - len(current_hour)) / (self.pattern_window_hours - 1)
            if avg_rate > 0 and len(current_hour) > avg_rate * self.sudden_spike_multiplier:
                anomalies.append(AnomalyEvent(
                    anomaly_type="sudden_spike",
                    doc_id=doc_id,
                    query="",
                    severity="medium",
                    description=f"Sudden spike: {len(current_hour)} retrievals vs {avg_rate:.1f} avg/hour",
                    details={
                        "current_rate": len(current_hour),
                        "avg_rate": avg_rate,
                        "spike_factor": len(current_hour) / avg_rate,
                    },
                ))
        
        # Store detected anomalies
        self._detected_anomalies.extend(anomalies)
        
        return anomalies
    
    def get_all_anomalies(
        self,
        since: Optional[datetime] = None,
        severity: Optional[str] = None
    ) -> List[AnomalyEvent]:
        """Get all detected anomalies with optional filters."""
        anomalies = self._detected_anomalies
        
        if since:
            anomalies = [a for a in anomalies if a.timestamp >= since]
        
        if severity:
            anomalies = [a for a in anomalies if a.severity == severity]
        
        return anomalies
    
    def get_suspicious_docs(
        self,
        min_anomaly_count: int = 2
    ) -> List[Tuple[str, int, List[str]]]:
        """Get documents with multiple anomalies."""
        doc_anomalies: Dict[str, List[AnomalyEvent]] = defaultdict(list)
        
        for anomaly in self._detected_anomalies:
            doc_anomalies[anomaly.doc_id].append(anomaly)
        
        suspicious = []
        for doc_id, anomalies in doc_anomalies.items():
            if len(anomalies) >= min_anomaly_count:
                types = list(set(a.anomaly_type for a in anomalies))
                suspicious.append((doc_id, len(anomalies), types))
        
        return sorted(suspicious, key=lambda x: x[1], reverse=True)
    
    def get_statistics(self) -> Dict:
        """Get detector statistics."""
        return {
            "total_retrievals_tracked": len(self._retrieval_history),
            "unique_documents": len(self._doc_query_map),
            "total_anomalies": len(self._detected_anomalies),
            "anomalies_by_type": dict(
                (t, len([a for a in self._detected_anomalies if a.anomaly_type == t]))
                for t in set(a.anomaly_type for a in self._detected_anomalies)
            ),
            "anomalies_by_severity": {
                "high": len([a for a in self._detected_anomalies if a.severity == "high"]),
                "medium": len([a for a in self._detected_anomalies if a.severity == "medium"]),
                "low": len([a for a in self._detected_anomalies if a.severity == "low"]),
            },
        }


# =============================================================================
# TRUST-AWARE RETRIEVER
# =============================================================================

class TrustAwareRetriever:
    """
    Trust-aware retrieval system for RAG.
    
    Wraps any retriever and adds:
    1. Trust-weighted ranking
    2. Temporal decay
    3. Anomaly detection
    4. Filtering of untrusted content
    
    Example:
        # Wrap your existing retriever
        retriever = TrustAwareRetriever(
            base_retriever=your_vector_store.as_retriever(),
            min_trust_score=0.3,
            enable_temporal_decay=True,
        )
        
        # Retrieve with trust awareness
        result = retriever.retrieve("What are our payment policies?")
        
        # Get only trusted documents
        trusted_docs = result.get_trusted_docs()
    """
    
    def __init__(
        self,
        # Base retriever (optional - can use retrieve_fn instead)
        base_retriever: Any = None,
        retrieve_fn: Optional[Callable] = None,
        
        # Trust settings
        min_trust_score: float = 0.2,
        trust_weight_factor: float = 0.3,    # How much trust affects ranking
        untrusted_penalty: float = 0.5,      # Penalty for untrusted docs
        
        # Temporal decay
        enable_temporal_decay: bool = True,
        decay_half_life_days: float = 30.0,
        decay_function: DecayFunction = DecayFunction.EXPONENTIAL,
        temporal_weight_factor: float = 0.2,
        
        # Anomaly detection
        enable_anomaly_detection: bool = True,
        anomaly_penalty: float = 0.3,
        
        # Filtering
        filter_flagged: bool = True,
        filter_high_risk: bool = True,
        high_risk_threshold: int = 70,
        
        # Retrieval settings
        top_k: int = 10,
        rerank: bool = True,
        
        # Metadata function
        get_metadata_fn: Optional[Callable[[str], RetrievalMetadata]] = None,
    ):
        """
        Initialize trust-aware retriever.
        
        Args:
            base_retriever: Base retriever object (with .invoke() or .get_relevant_documents())
            retrieve_fn: Alternative: function that takes query and returns docs
            min_trust_score: Minimum trust score to include
            trust_weight_factor: How much trust affects final score (0-1)
            untrusted_penalty: Penalty for docs below trust threshold
            enable_temporal_decay: Enable time-based decay
            decay_half_life_days: Half-life for temporal decay
            decay_function: Type of decay function
            temporal_weight_factor: How much time affects score (0-1)
            enable_anomaly_detection: Enable anomaly detection
            anomaly_penalty: Penalty for anomalous retrieval patterns
            filter_flagged: Filter out flagged documents
            filter_high_risk: Filter out high-risk documents
            high_risk_threshold: Risk score threshold for filtering
            top_k: Number of documents to return
            rerank: Whether to rerank based on trust
            get_metadata_fn: Function to get metadata for a doc_id
        """
        self.base_retriever = base_retriever
        self.retrieve_fn = retrieve_fn
        
        self.min_trust_score = min_trust_score
        self.trust_weight_factor = trust_weight_factor
        self.untrusted_penalty = untrusted_penalty
        
        self.enable_temporal_decay = enable_temporal_decay
        self.temporal_weight_factor = temporal_weight_factor
        
        self.enable_anomaly_detection = enable_anomaly_detection
        self.anomaly_penalty = anomaly_penalty
        
        self.filter_flagged = filter_flagged
        self.filter_high_risk = filter_high_risk
        self.high_risk_threshold = high_risk_threshold
        
        self.top_k = top_k
        self.rerank = rerank
        
        self.get_metadata_fn = get_metadata_fn
        
        # Initialize components
        self.temporal_decay = TemporalDecay(
            half_life_days=decay_half_life_days,
            decay_function=decay_function,
        ) if enable_temporal_decay else None
        
        self.anomaly_detector = RetrievalAnomalyDetector() if enable_anomaly_detection else None
        
        # Metadata cache
        self._metadata_cache: Dict[str, RetrievalMetadata] = {}
        
        # Statistics
        self._stats = {
            "total_retrievals": 0,
            "filtered_count": 0,
            "reranked_count": 0,
            "anomalies_detected": 0,
        }
    
    def set_metadata(
        self,
        doc_id: str,
        metadata: RetrievalMetadata
    ) -> None:
        """Set metadata for a document."""
        self._metadata_cache[doc_id] = metadata
    
    def get_metadata(self, doc_id: str) -> Optional[RetrievalMetadata]:
        """Get metadata for a document."""
        if doc_id in self._metadata_cache:
            return self._metadata_cache[doc_id]
        
        if self.get_metadata_fn:
            metadata = self.get_metadata_fn(doc_id)
            if metadata:
                self._metadata_cache[doc_id] = metadata
            return metadata
        
        return None
    
    def _extract_doc_info(
        self,
        doc: Any
    ) -> Tuple[str, str, float, Optional[RetrievalMetadata]]:
        """Extract doc_id, content, similarity, and metadata from a document."""
        # Handle different document formats
        if hasattr(doc, 'page_content'):
            # LangChain Document
            content = doc.page_content
            doc_id = doc.metadata.get('doc_id', doc.metadata.get('id', str(hash(content))))
            similarity = doc.metadata.get('score', doc.metadata.get('similarity', 0.5))
        elif isinstance(doc, dict):
            content = doc.get('content', doc.get('text', doc.get('page_content', '')))
            doc_id = doc.get('doc_id', doc.get('id', str(hash(content))))
            similarity = doc.get('score', doc.get('similarity', 0.5))
        elif isinstance(doc, tuple) and len(doc) >= 2:
            # (Document, score) tuple
            content = doc[0].page_content if hasattr(doc[0], 'page_content') else str(doc[0])
            doc_id = str(hash(content))
            similarity = doc[1]
        else:
            content = str(doc)
            doc_id = str(hash(content))
            similarity = 0.5
        
        metadata = self.get_metadata(doc_id)
        
        return doc_id, content, float(similarity), metadata
    
    def _calculate_trust_weight(
        self,
        metadata: Optional[RetrievalMetadata]
    ) -> float:
        """Calculate trust-based weight."""
        if not metadata:
            return 1.0 - self.untrusted_penalty  # Unknown = penalize
        
        trust = metadata.trust_score
        
        # Apply penalty if below threshold
        if trust < self.min_trust_score:
            return 1.0 - self.untrusted_penalty
        
        # Scale trust to weight
        # trust_score 0.0-1.0 maps to weight 0.5-1.0
        weight = 0.5 + (trust * 0.5)
        
        # Boost for verified sources
        if metadata.source_verified:
            weight = min(1.0, weight + 0.1)
        
        # Penalty for sanitized content (might be partially compromised)
        if metadata.was_sanitized:
            weight *= 0.9
        
        return weight
    
    def _calculate_temporal_weight(
        self,
        metadata: Optional[RetrievalMetadata]
    ) -> float:
        """Calculate temporal decay weight."""
        if not self.temporal_decay or not metadata:
            return 1.0
        
        return self.temporal_decay.calculate(
            created_at=metadata.created_at,
            last_accessed_at=metadata.last_accessed_at,
            access_count=metadata.access_count,
        )
    
    def _should_filter(
        self,
        metadata: Optional[RetrievalMetadata]
    ) -> Tuple[bool, str]:
        """Check if document should be filtered out."""
        if not metadata:
            return False, ""
        
        if self.filter_flagged and metadata.flagged and not metadata.reviewed:
            return True, "flagged_for_review"
        
        if self.filter_high_risk and metadata.risk_score >= self.high_risk_threshold:
            return True, "high_risk"
        
        if metadata.trust_score < self.min_trust_score:
            return True, "below_trust_threshold"
        
        return False, ""
    
    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        **kwargs
    ) -> RetrievalResult:
        """
        Retrieve documents with trust-aware ranking.
        
        Args:
            query: Query string
            top_k: Number of documents (overrides default)
            **kwargs: Additional args for base retriever
            
        Returns:
            RetrievalResult with trust-adjusted documents
        """
        start_time = time.time()
        k = top_k or self.top_k
        self._stats["total_retrievals"] += 1
        
        # Get raw results from base retriever
        raw_docs = self._get_raw_results(query, k * 2, **kwargs)  # Fetch extra for filtering
        
        # Process each document
        processed_docs = []
        filtered_count = 0
        
        for doc in raw_docs:
            doc_id, content, similarity, metadata = self._extract_doc_info(doc)
            
            # Check if should filter
            should_filter, filter_reason = self._should_filter(metadata)
            if should_filter:
                filtered_count += 1
                self._stats["filtered_count"] += 1
                continue
            
            # Calculate weights
            trust_weight = self._calculate_trust_weight(metadata)
            temporal_weight = self._calculate_temporal_weight(metadata)
            
            # Check for anomalies
            anomaly_penalty = 0.0
            is_anomalous = False
            if self.anomaly_detector:
                self.anomaly_detector.record_retrieval(
                    doc_id=doc_id,
                    query=query,
                    trust_score=metadata.trust_score if metadata else 0.5,
                    similarity_score=similarity,
                )
                anomalies = self.anomaly_detector.check_anomalies(doc_id)
                if anomalies:
                    is_anomalous = True
                    anomaly_penalty = self.anomaly_penalty
                    self._stats["anomalies_detected"] += len(anomalies)
            
            # Calculate final score
            trust_adjusted = similarity * (
                1 - self.trust_weight_factor + 
                self.trust_weight_factor * trust_weight
            )
            
            temporal_adjusted = trust_adjusted * (
                1 - self.temporal_weight_factor +
                self.temporal_weight_factor * temporal_weight
            )
            
            final_score = temporal_adjusted * (1 - anomaly_penalty)
            
            # Create processed document
            processed_doc = RetrievedDocument(
                doc_id=doc_id,
                content=content,
                similarity_score=similarity,
                trust_adjusted_score=trust_adjusted,
                final_score=final_score,
                trust_weight=trust_weight,
                temporal_decay=temporal_weight,
                anomaly_penalty=anomaly_penalty,
                metadata=metadata,
                is_trusted=trust_weight >= 0.5,
                is_anomalous=is_anomalous,
                should_review=is_anomalous or (metadata and metadata.flagged),
            )
            
            processed_docs.append(processed_doc)
            
            # Update access metadata
            if metadata:
                metadata.last_accessed_at = datetime.now(timezone.utc)
                metadata.access_count += 1
        
        # Rerank by final score
        if self.rerank:
            processed_docs.sort(key=lambda d: d.final_score, reverse=True)
            self._stats["reranked_count"] += 1
        
        # Limit to top_k
        processed_docs = processed_docs[:k]
        
        # Build result
        elapsed_ms = (time.time() - start_time) * 1000
        
        anomaly_details = []
        if self.anomaly_detector:
            recent_anomalies = self.anomaly_detector.get_all_anomalies(
                since=datetime.now(timezone.utc) - timedelta(minutes=1)
            )
            anomaly_details = [
                {"type": a.anomaly_type, "doc_id": a.doc_id, "severity": a.severity}
                for a in recent_anomalies
            ]
        
        return RetrievalResult(
            query=query,
            documents=processed_docs,
            total_candidates=len(raw_docs),
            filtered_count=filtered_count,
            reranked=self.rerank,
            anomalies_detected=len(anomaly_details),
            anomaly_details=anomaly_details,
            retrieval_time_ms=elapsed_ms,
        )
    
    def _get_raw_results(
        self,
        query: str,
        k: int,
        **kwargs
    ) -> List[Any]:
        """Get raw results from base retriever."""
        if self.retrieve_fn:
            return self.retrieve_fn(query, k=k, **kwargs)
        
        if self.base_retriever:
            # Try different retriever interfaces
            if hasattr(self.base_retriever, 'invoke'):
                return self.base_retriever.invoke(query, k=k, **kwargs)
            elif hasattr(self.base_retriever, 'get_relevant_documents'):
                return self.base_retriever.get_relevant_documents(query, k=k, **kwargs)
            elif hasattr(self.base_retriever, 'similarity_search_with_score'):
                return self.base_retriever.similarity_search_with_score(query, k=k, **kwargs)
            elif hasattr(self.base_retriever, 'similarity_search'):
                return self.base_retriever.similarity_search(query, k=k, **kwargs)
            elif callable(self.base_retriever):
                return self.base_retriever(query, k=k, **kwargs)
        
        logger.warning("No valid retriever configured")
        return []
    
    def get_statistics(self) -> Dict:
        """Get retriever statistics."""
        stats = self._stats.copy()
        
        if self.anomaly_detector:
            stats["anomaly_detector"] = self.anomaly_detector.get_statistics()
        
        stats["metadata_cache_size"] = len(self._metadata_cache)
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset statistics counters."""
        self._stats = {
            "total_retrievals": 0,
            "filtered_count": 0,
            "reranked_count": 0,
            "anomalies_detected": 0,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_metadata(
    doc_id: str,
    trust_score: float = 0.5,
    source_type: str = "unknown",
    created_at: Optional[datetime] = None,
    risk_score: int = 0,
) -> RetrievalMetadata:
    """Quick helper to create retrieval metadata."""
    return RetrievalMetadata(
        doc_id=doc_id,
        content_hash=hashlib.sha256(doc_id.encode()).hexdigest(),
        trust_score=trust_score,
        source_type=source_type,
        created_at=created_at or datetime.now(timezone.utc),
        risk_score=risk_score,
    )


def wrap_retriever(
    retriever: Any,
    min_trust: float = 0.3,
    enable_decay: bool = True,
) -> TrustAwareRetriever:
    """Quick helper to wrap an existing retriever."""
    return TrustAwareRetriever(
        base_retriever=retriever,
        min_trust_score=min_trust,
        enable_temporal_decay=enable_decay,
    )
