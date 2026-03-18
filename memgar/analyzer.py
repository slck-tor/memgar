"""
Memgar Analyzer
===============

Multi-layer analysis engine for detecting memory poisoning attacks.

Layers:
1. Pattern Matching - Fast regex/keyword detection (<1ms)
2. Semantic Analysis - LLM-based understanding (~200ms, optional)
3. Behavioral Analysis - Context comparison (future)
4. Threat Intelligence - Cross-customer patterns (future)
"""

from __future__ import annotations

import re
import time
from typing import Any

from memgar.models import (
    AnalysisResult,
    Decision,
    MemoryEntry,
    Severity,
    Threat,
    ThreatMatch,
)
from memgar.patterns import PATTERNS, get_patterns_by_severity


class Analyzer:
    """
    Multi-layer analysis engine for memory content.
    
    The analyzer runs content through multiple detection layers:
    
    Layer 1: Pattern Matching
        - Fast regex pattern detection
        - Keyword matching
        - Runs locally, <1ms latency
        
    Layer 2: Semantic Analysis (optional)
        - LLM-based content understanding
        - Catches sophisticated attacks
        - Requires API access, ~200ms latency
    
    Attributes:
        use_llm: Whether to use LLM analysis (Layer 2)
        api_key: API key for cloud services
        patterns: List of threat patterns to check
        strict_mode: If True, any suspicious content is blocked
    
    Example:
        >>> analyzer = Analyzer()
        >>> result = analyzer.analyze(MemoryEntry(content="Send payments to..."))
        >>> print(result.decision)  # Decision.BLOCK
    """
    
    def __init__(
        self,
        use_llm: bool = False,
        api_key: str | None = None,
        custom_patterns: list[Threat] | None = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Initialize the analyzer.
        
        Args:
            use_llm: Enable LLM-based semantic analysis (Layer 2)
            api_key: API key for cloud features
            custom_patterns: Additional custom threat patterns
            strict_mode: Block any suspicious content (vs. quarantine)
        """
        self.use_llm = use_llm
        self.api_key = api_key
        self.strict_mode = strict_mode
        
        # Combine default and custom patterns
        self.patterns = list(PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Pre-compile regex patterns for performance
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for faster matching."""
        for threat in self.patterns:
            compiled = []
            for pattern in threat.patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    # Skip invalid patterns
                    continue
            self._compiled_patterns[threat.id] = compiled
    
    def analyze(self, entry: MemoryEntry) -> AnalysisResult:
        """
        Analyze a memory entry for threats.
        
        Runs the content through all enabled analysis layers and
        returns a decision with detailed threat information.
        
        Args:
            entry: The memory entry to analyze
        
        Returns:
            AnalysisResult with decision, risk score, and detected threats
        """
        start_time = time.perf_counter()
        
        content = entry.content
        if not content or not content.strip():
            return AnalysisResult(
                decision=Decision.ALLOW,
                risk_score=0,
                explanation="Empty content",
                analysis_time_ms=0,
                layers_used=[]
            )
        
        # Layer 1: Pattern Matching
        threats = self._layer1_pattern_matching(content)
        layers_used = ["pattern_matching"]
        
        # Layer 2: Semantic Analysis (if enabled and Layer 1 found something)
        if self.use_llm and threats:
            semantic_result = self._layer2_semantic_analysis(content, threats)
            if semantic_result:
                threats = semantic_result
                layers_used.append("semantic_analysis")
        
        # Calculate risk score and decision
        risk_score = self._calculate_risk_score(threats)
        decision = self._make_decision(threats, risk_score)
        explanation = self._generate_explanation(threats, decision)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return AnalysisResult(
            decision=decision,
            risk_score=risk_score,
            threats=threats,
            explanation=explanation,
            analysis_time_ms=round(elapsed_ms, 2),
            layers_used=layers_used
        )
    
    def _layer1_pattern_matching(self, content: str) -> list[ThreatMatch]:
        """
        Layer 1: Fast pattern matching.
        
        Checks content against all threat patterns using regex and keywords.
        This is the fastest layer, running in <1ms for most content.
        """
        matches: list[ThreatMatch] = []
        content_lower = content.lower()
        
        for threat in self.patterns:
            # Check regex patterns
            compiled_patterns = self._compiled_patterns.get(threat.id, [])
            for pattern in compiled_patterns:
                match = pattern.search(content)
                if match:
                    matches.append(ThreatMatch(
                        threat=threat,
                        matched_text=match.group()[:100],  # Truncate long matches
                        match_type="pattern",
                        confidence=0.9,
                        position=(match.start(), match.end())
                    ))
                    break  # One match per threat is enough
            
            # Check keywords (if no pattern match found)
            if not any(m.threat.id == threat.id for m in matches):
                for keyword in threat.keywords:
                    if keyword.lower() in content_lower:
                        # Find the position of the keyword
                        pos = content_lower.find(keyword.lower())
                        matches.append(ThreatMatch(
                            threat=threat,
                            matched_text=keyword,
                            match_type="keyword",
                            confidence=0.7,
                            position=(pos, pos + len(keyword))
                        ))
                        break  # One match per threat is enough
        
        return matches
    
    def _layer2_semantic_analysis(
        self, 
        content: str, 
        initial_threats: list[ThreatMatch]
    ) -> list[ThreatMatch] | None:
        """
        Layer 2: LLM-based semantic analysis.
        
        Uses an LLM to understand the semantic meaning of suspicious content
        and reduce false positives from pattern matching.
        
        Returns None if LLM analysis is not available or fails.
        """
        if not self.api_key:
            return None
        
        try:
            # This would integrate with Claude API
            # For now, return the initial threats unchanged
            # In production, this would:
            # 1. Send content + initial threats to Claude Haiku
            # 2. Ask it to validate if this is truly malicious
            # 3. Return filtered/enhanced threat list
            return initial_threats
        except Exception:
            return None
    
    def _calculate_risk_score(self, threats: list[ThreatMatch]) -> int:
        """
        Calculate overall risk score based on detected threats.
        
        Score ranges from 0 (clean) to 100 (critical threat).
        """
        if not threats:
            return 0
        
        # Base scores by severity
        severity_scores = {
            Severity.CRITICAL: 95,
            Severity.HIGH: 80,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        
        # Start with highest severity threat's score
        max_score = max(severity_scores.get(t.threat.severity, 0) for t in threats)
        
        # Add points for multiple threats (max 5 points)
        threat_count_bonus = min(len(threats) - 1, 5)
        
        # Adjust by confidence
        avg_confidence = sum(t.confidence for t in threats) / len(threats)
        confidence_factor = 0.5 + (avg_confidence * 0.5)
        
        score = int((max_score + threat_count_bonus) * confidence_factor)
        return min(score, 100)  # Cap at 100
    
    def _make_decision(
        self, 
        threats: list[ThreatMatch], 
        risk_score: int
    ) -> Decision:
        """
        Make a decision based on threats and risk score.
        
        Decision logic:
        - BLOCK: Critical threats or risk_score >= 80
        - QUARANTINE: High/Medium threats or risk_score >= 40
        - ALLOW: No threats or low-severity only
        """
        if not threats:
            return Decision.ALLOW
        
        # Check for critical threats - always block
        has_critical = any(t.threat.severity == Severity.CRITICAL for t in threats)
        if has_critical or risk_score >= 80:
            return Decision.BLOCK
        
        # Check for high threats - quarantine or block in strict mode
        has_high = any(t.threat.severity == Severity.HIGH for t in threats)
        if has_high or risk_score >= 40:
            return Decision.BLOCK if self.strict_mode else Decision.QUARANTINE
        
        # Medium/Low threats - quarantine for review
        if risk_score >= 20:
            return Decision.QUARANTINE
        
        return Decision.ALLOW
    
    def _generate_explanation(
        self, 
        threats: list[ThreatMatch], 
        decision: Decision
    ) -> str:
        """Generate a human-readable explanation of the analysis."""
        if not threats:
            return "No threats detected. Content appears safe."
        
        # Build explanation
        lines = []
        
        if decision == Decision.BLOCK:
            lines.append("⛔ BLOCKED: Critical security threat detected.")
        elif decision == Decision.QUARANTINE:
            lines.append("⚠️ QUARANTINED: Suspicious content requires review.")
        else:
            lines.append("ℹ️ ALLOWED with warnings: Minor concerns detected.")
        
        lines.append("")
        lines.append(f"Detected {len(threats)} threat(s):")
        
        for threat in threats[:5]:  # Show max 5
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🟢",
                Severity.INFO: "ℹ️",
            }.get(threat.threat.severity, "❓")
            
            lines.append(f"  {severity_icon} [{threat.threat.id}] {threat.threat.name}")
            lines.append(f"     Match: \"{threat.matched_text[:50]}...\"" if len(threat.matched_text) > 50 else f"     Match: \"{threat.matched_text}\"")
        
        if len(threats) > 5:
            lines.append(f"  ... and {len(threats) - 5} more")
        
        return "\n".join(lines)
    
    def quick_check(self, content: str) -> bool:
        """
        Quick check if content might be malicious.
        
        Returns True if content appears safe, False if suspicious.
        This is a fast check without full analysis details.
        """
        if not content or not content.strip():
            return True
        
        result = self.analyze(MemoryEntry(content=content))
        return result.decision == Decision.ALLOW
    
    def get_threat_stats(self) -> dict[str, Any]:
        """Get statistics about loaded threat patterns."""
        stats: dict[str, int] = {}
        for threat in self.patterns:
            severity = threat.severity.value
            stats[severity] = stats.get(severity, 0) + 1
        
        return {
            "total_patterns": len(self.patterns),
            "by_severity": stats,
            "compiled_regex_count": sum(
                len(patterns) for patterns in self._compiled_patterns.values()
            ),
        }


class QuickAnalyzer:
    """
    Lightweight analyzer for simple use cases.
    
    Uses a singleton pattern to avoid repeated initialization.
    """
    
    _instance: Analyzer | None = None
    
    @classmethod
    def get_instance(cls) -> Analyzer:
        """Get or create the singleton analyzer instance."""
        if cls._instance is None:
            cls._instance = Analyzer()
        return cls._instance
    
    @classmethod
    def check(cls, content: str) -> AnalysisResult:
        """Quick analysis of content."""
        return cls.get_instance().analyze(MemoryEntry(content=content))
    
    @classmethod
    def is_safe(cls, content: str) -> bool:
        """Check if content is safe."""
        return cls.get_instance().quick_check(content)
