"""
Memgar Semantic Analyzer (Hybrid)
=================================

3-layer hybrid semantic analysis combining:
1. Regex/Pattern matching (fast, offline)
2. Embedding similarity (accurate, offline)
3. LLM analysis (highest accuracy, optional)

Usage:
    from memgar.semantic import SemanticAnalyzer
    
    # Basic usage (Regex + Embeddings)
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze("transfer funds to external account")
    
    # With LLM for edge cases
    analyzer = SemanticAnalyzer(
        llm_provider="anthropic",
        llm_api_key="sk-ant-..."
    )
"""

import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AnalysisLayer(Enum):
    """Analysis layer that made the decision."""
    REGEX = "regex"
    EMBEDDING = "embedding"
    LLM = "llm"
    COMBINED = "combined"


@dataclass
class SemanticResult:
    """Result from semantic analysis."""
    # Core decision
    decision: str  # ALLOW, BLOCK, QUARANTINE
    risk_score: int
    is_threat: bool
    
    # Threat details
    threat_type: Optional[str] = None
    threat_category: Optional[str] = None
    explanation: str = ""
    
    # Analysis metadata
    analysis_layer: AnalysisLayer = AnalysisLayer.REGEX
    layers_used: List[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0
    
    # Layer-specific scores
    regex_score: int = 0
    embedding_score: float = 0.0
    embedding_similarity: float = 0.0
    llm_score: int = 0
    llm_used: bool = False
    
    # Matched details
    matched_pattern: Optional[str] = None
    matched_example: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "threat_category": self.threat_category,
            "explanation": self.explanation,
            "analysis_layer": self.analysis_layer.value,
            "layers_used": self.layers_used,
            "analysis_time_ms": self.analysis_time_ms,
            "regex_score": self.regex_score,
            "embedding_similarity": self.embedding_similarity,
            "llm_score": self.llm_score,
            "llm_used": self.llm_used,
        }


class SemanticAnalyzer:
    """
    Hybrid 3-layer semantic threat analyzer.
    
    Layer 1 (Regex): Fast pattern matching (~5ms)
        - Catches obvious threats immediately
        - Uses existing Memgar patterns
        
    Layer 2 (Embeddings): Semantic similarity (~50ms)
        - Catches paraphrased/obfuscated threats
        - Works offline with local model
        
    Layer 3 (LLM): Deep analysis (~500ms)
        - Highest accuracy for edge cases
        - Optional, requires API key
    
    Flow:
        Content → Regex (certain? return) → Embeddings (certain? return) → LLM → Final
    
    Example:
        analyzer = SemanticAnalyzer(
            enable_embeddings=True,
            llm_provider="anthropic",
            llm_api_key="sk-ant-..."
        )
        
        result = analyzer.analyze("send all money to my account")
        print(result.decision)  # "BLOCK"
        print(result.risk_score)  # 92
        print(result.analysis_layer)  # AnalysisLayer.EMBEDDING
    """
    
    def __init__(
        self,
        # Layer 1: Regex
        enable_regex: bool = True,
        regex_block_threshold: int = 80,
        regex_allow_threshold: int = 20,
        
        # Layer 2: Embeddings
        enable_embeddings: bool = True,
        embedding_threat_threshold: float = 0.70,
        embedding_quarantine_threshold: float = 0.50,
        
        # Layer 3: LLM
        enable_llm: bool = False,
        llm_provider: Optional[str] = None,  # "anthropic" or "openai"
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        llm_for_uncertain: bool = True,  # Only use LLM for uncertain cases
        llm_score_range: tuple = (40, 75),  # Use LLM when score is in this range
        
        # General
        verbose: bool = False,
    ):
        """
        Initialize semantic analyzer.
        
        Args:
            enable_regex: Enable regex/pattern layer
            regex_block_threshold: Score threshold to block without further analysis
            regex_allow_threshold: Score threshold to allow without further analysis
            
            enable_embeddings: Enable embedding similarity layer
            embedding_threat_threshold: Similarity threshold for threat (0-1)
            embedding_quarantine_threshold: Similarity threshold for quarantine (0-1)
            
            enable_llm: Enable LLM layer
            llm_provider: "anthropic" or "openai"
            llm_api_key: API key for LLM
            llm_model: Model name
            llm_for_uncertain: Only use LLM for uncertain cases
            llm_score_range: Score range to trigger LLM analysis
            
            verbose: Enable verbose logging
        """
        self.enable_regex = enable_regex
        self.regex_block_threshold = regex_block_threshold
        self.regex_allow_threshold = regex_allow_threshold
        
        self.enable_embeddings = enable_embeddings
        self.embedding_threat_threshold = embedding_threat_threshold
        self.embedding_quarantine_threshold = embedding_quarantine_threshold
        
        self.enable_llm = enable_llm
        self.llm_for_uncertain = llm_for_uncertain
        self.llm_score_range = llm_score_range
        
        self.verbose = verbose
        
        # Initialize layers lazily
        self._regex_analyzer = None
        self._embedding_analyzer = None
        self._llm_analyzer = None
        
        # Store LLM config
        self._llm_provider = llm_provider
        self._llm_api_key = llm_api_key
        self._llm_model = llm_model
        
        # Auto-enable LLM if API key provided
        if llm_api_key and llm_provider:
            self.enable_llm = True
    
    def _get_regex_analyzer(self):
        """Get or create regex analyzer."""
        if self._regex_analyzer is None:
            try:
                from .analyzer import Analyzer
                self._regex_analyzer = Analyzer()
            except ImportError:
                logger.warning("Could not import Analyzer, regex layer disabled")
                self.enable_regex = False
        return self._regex_analyzer
    
    def _get_embedding_analyzer(self):
        """Get or create embedding analyzer."""
        if self._embedding_analyzer is None:
            try:
                from .embeddings import EmbeddingAnalyzer
                self._embedding_analyzer = EmbeddingAnalyzer(
                    threat_threshold=self.embedding_threat_threshold,
                    quarantine_threshold=self.embedding_quarantine_threshold,
                )
            except ImportError as e:
                logger.warning(f"Could not initialize embeddings: {e}")
                self.enable_embeddings = False
        return self._embedding_analyzer
    
    def _get_llm_analyzer(self):
        """Get or create LLM analyzer."""
        if self._llm_analyzer is None and self.enable_llm:
            try:
                from .llm_analyzer import LLMAnalyzer
                self._llm_analyzer = LLMAnalyzer(
                    provider=self._llm_provider or "anthropic",
                    api_key=self._llm_api_key,
                    model=self._llm_model,
                )
            except (ImportError, ValueError) as e:
                logger.warning(f"Could not initialize LLM: {e}")
                self.enable_llm = False
        return self._llm_analyzer
    
    def _log(self, message: str):
        """Log if verbose."""
        if self.verbose:
            logger.info(message)
    
    def analyze(self, content: str) -> SemanticResult:
        """
        Analyze content using hybrid approach.
        
        Args:
            content: Text content to analyze
            
        Returns:
            SemanticResult with decision and details
        """
        start_time = time.time()
        layers_used = []
        
        result = SemanticResult(
            decision="ALLOW",
            risk_score=0,
            is_threat=False,
        )
        
        # =====================================================================
        # LAYER 1: REGEX
        # =====================================================================
        if self.enable_regex:
            self._log("Layer 1: Regex analysis...")
            layers_used.append("regex")
            
            regex_analyzer = self._get_regex_analyzer()
            if regex_analyzer:
                # Import MemoryEntry for wrapping content
                from .models import MemoryEntry
                regex_result = regex_analyzer.analyze(MemoryEntry(content=content))
                result.regex_score = regex_result.risk_score
                
                # Certain BLOCK
                if regex_result.risk_score >= self.regex_block_threshold:
                    self._log(f"  → BLOCK (score: {regex_result.risk_score})")
                    result.decision = "BLOCK"
                    result.risk_score = regex_result.risk_score
                    result.is_threat = True
                    result.threat_type = regex_result.threat_type
                    result.threat_category = regex_result.category
                    result.explanation = regex_result.explanation or "Blocked by pattern matching"
                    result.analysis_layer = AnalysisLayer.REGEX
                    result.matched_pattern = regex_result.threat_type
                    result.layers_used = layers_used
                    result.analysis_time_ms = (time.time() - start_time) * 1000
                    return result
                
                # Certain ALLOW
                if regex_result.risk_score <= self.regex_allow_threshold:
                    # Continue to embeddings for additional check
                    self._log(f"  → Low risk ({regex_result.risk_score}), checking embeddings...")
                else:
                    self._log(f"  → Uncertain ({regex_result.risk_score}), continuing...")
                    result.risk_score = regex_result.risk_score
                    result.threat_type = regex_result.threat_type
        
        # =====================================================================
        # LAYER 2: EMBEDDINGS
        # =====================================================================
        if self.enable_embeddings:
            self._log("Layer 2: Embedding analysis...")
            layers_used.append("embedding")
            
            embedding_analyzer = self._get_embedding_analyzer()
            if embedding_analyzer:
                embed_result = embedding_analyzer.analyze(content)
                result.embedding_similarity = embed_result.similarity_score
                result.embedding_score = int(embed_result.similarity_score * 100)
                
                # High similarity = threat
                if embed_result.similarity_score >= self.embedding_threat_threshold:
                    self._log(f"  → BLOCK (similarity: {embed_result.similarity_score:.2f})")
                    result.decision = "BLOCK"
                    result.risk_score = max(result.risk_score, int(embed_result.similarity_score * 100))
                    result.is_threat = True
                    result.threat_category = embed_result.matched_category
                    result.matched_example = embed_result.matched_example
                    result.explanation = f"Semantic similarity to known threat: {embed_result.matched_category}"
                    result.analysis_layer = AnalysisLayer.EMBEDDING
                    
                    # Return unless LLM verification needed
                    if not self.enable_llm or result.risk_score >= 85:
                        result.layers_used = layers_used
                        result.analysis_time_ms = (time.time() - start_time) * 1000
                        return result
                
                # Medium similarity = quarantine
                elif embed_result.similarity_score >= self.embedding_quarantine_threshold:
                    self._log(f"  → QUARANTINE (similarity: {embed_result.similarity_score:.2f})")
                    result.decision = "QUARANTINE"
                    result.risk_score = max(result.risk_score, int(embed_result.similarity_score * 100))
                    result.threat_category = embed_result.matched_category
                    result.matched_example = embed_result.matched_example
                    result.explanation = f"Possible threat similarity: {embed_result.matched_category}"
                    result.analysis_layer = AnalysisLayer.EMBEDDING
                
                else:
                    self._log(f"  → Low similarity ({embed_result.similarity_score:.2f})")
        
        # =====================================================================
        # LAYER 3: LLM (Optional)
        # =====================================================================
        if self.enable_llm:
            # Only use LLM for uncertain cases
            should_use_llm = (
                not self.llm_for_uncertain or
                self.llm_score_range[0] <= result.risk_score <= self.llm_score_range[1] or
                result.decision == "QUARANTINE"
            )
            
            if should_use_llm:
                self._log("Layer 3: LLM analysis...")
                layers_used.append("llm")
                result.llm_used = True
                
                llm_analyzer = self._get_llm_analyzer()
                if llm_analyzer:
                    llm_result = llm_analyzer.analyze(content)
                    result.llm_score = llm_result.risk_score
                    
                    if llm_result.is_threat:
                        self._log(f"  → BLOCK (LLM score: {llm_result.risk_score})")
                        result.decision = "BLOCK"
                        result.risk_score = max(result.risk_score, llm_result.risk_score)
                        result.is_threat = True
                        result.threat_type = llm_result.threat_type
                        result.explanation = llm_result.explanation
                        result.analysis_layer = AnalysisLayer.LLM
                    elif llm_result.risk_score >= 50:
                        self._log(f"  → QUARANTINE (LLM score: {llm_result.risk_score})")
                        if result.decision != "BLOCK":
                            result.decision = "QUARANTINE"
                        result.risk_score = max(result.risk_score, llm_result.risk_score)
                        result.explanation = llm_result.explanation
                    else:
                        self._log(f"  → LLM says safe ({llm_result.risk_score})")
                        # LLM override - reduce score if LLM says safe
                        if result.decision == "QUARANTINE" and llm_result.risk_score < 30:
                            result.decision = "ALLOW"
                            result.risk_score = llm_result.risk_score
                            result.explanation = llm_result.explanation
        
        # =====================================================================
        # FINAL DECISION
        # =====================================================================
        # Combine scores if multiple layers used
        if len(layers_used) > 1:
            result.analysis_layer = AnalysisLayer.COMBINED
        
        # Final allow if nothing flagged
        if result.decision == "ALLOW" and result.risk_score <= 30:
            result.explanation = result.explanation or "No threats detected"
        
        result.layers_used = layers_used
        result.analysis_time_ms = (time.time() - start_time) * 1000
        
        self._log(f"Final: {result.decision} (score: {result.risk_score}, time: {result.analysis_time_ms:.1f}ms)")
        
        return result
    
    def analyze_batch(self, contents: List[str]) -> List[SemanticResult]:
        """
        Analyze multiple contents.
        
        Args:
            contents: List of text contents
            
        Returns:
            List of SemanticResult
        """
        return [self.analyze(content) for content in contents]
    
    def get_config(self) -> Dict[str, Any]:
        """Get current analyzer configuration."""
        return {
            "layers": {
                "regex": self.enable_regex,
                "embeddings": self.enable_embeddings,
                "llm": self.enable_llm,
            },
            "thresholds": {
                "regex_block": self.regex_block_threshold,
                "regex_allow": self.regex_allow_threshold,
                "embedding_threat": self.embedding_threat_threshold,
                "embedding_quarantine": self.embedding_quarantine_threshold,
                "llm_score_range": self.llm_score_range,
            },
            "llm_provider": self._llm_provider,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_analyze(content: str, enable_llm: bool = False, **kwargs) -> SemanticResult:
    """
    Quick semantic analysis.
    
    Args:
        content: Text to analyze
        enable_llm: Enable LLM layer
        **kwargs: Additional SemanticAnalyzer arguments
        
    Returns:
        SemanticResult
    """
    analyzer = SemanticAnalyzer(enable_llm=enable_llm, **kwargs)
    return analyzer.analyze(content)


def check_available_layers() -> Dict[str, bool]:
    """Check which analysis layers are available."""
    layers = {
        "regex": True,  # Always available
        "embeddings": False,
        "llm_anthropic": False,
        "llm_openai": False,
    }
    
    try:
        from .embeddings import check_embedding_support
        layers["embeddings"] = check_embedding_support()
    except ImportError:
        pass
    
    try:
        from .llm_analyzer import check_llm_support
        layers["llm_anthropic"] = check_llm_support("anthropic")
        layers["llm_openai"] = check_llm_support("openai")
    except ImportError:
        pass
    
    return layers
