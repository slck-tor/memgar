"""
Memgar Smart Whitelist
======================

Context-aware, adaptive whitelist for reducing false positives.

Features:
- Context-aware pattern matching
- Domain-specific whitelists (finance, healthcare, tech)
- Threat co-occurrence detection
- Learning from feedback
- Confidence scoring

Usage:
    from memgar.core.smart_whitelist import SmartWhitelist
    
    whitelist = SmartWhitelist()
    whitelist.load_domain("finance")
    
    result = whitelist.check("Transfer data to production server")
    if result.is_safe:
        print(f"Safe (confidence: {result.confidence})")
"""

from __future__ import annotations

import re
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Callable
from collections import defaultdict
import threading


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class Domain(str, Enum):
    """Domain categories for context-specific whitelists."""
    GENERAL = "general"
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    TECH = "tech"
    LEGAL = "legal"
    HR = "hr"
    ECOMMERCE = "ecommerce"


class SafetyLevel(str, Enum):
    """Safety classification levels."""
    SAFE = "safe"
    LIKELY_SAFE = "likely_safe"
    UNCERTAIN = "uncertain"
    LIKELY_UNSAFE = "likely_unsafe"
    UNSAFE = "unsafe"


@dataclass
class WhitelistResult:
    """Result of whitelist check."""
    is_safe: bool
    safety_level: SafetyLevel
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[str]
    context_signals: Dict[str, float]
    threat_indicators: List[str]
    recommendation: str
    
    def to_dict(self) -> Dict:
        return {
            "is_safe": self.is_safe,
            "safety_level": self.safety_level.value,
            "confidence": round(self.confidence, 3),
            "matched_patterns": self.matched_patterns,
            "context_signals": self.context_signals,
            "threat_indicators": self.threat_indicators,
            "recommendation": self.recommendation,
        }


@dataclass
class ContextPattern:
    """Pattern with context requirements."""
    pattern: str
    compiled: re.Pattern
    domain: Domain
    requires_context: List[str] = field(default_factory=list)  # Must have these nearby
    excludes_context: List[str] = field(default_factory=list)  # Must NOT have these
    min_confidence: float = 0.7
    description: str = ""


# =============================================================================
# THREAT CO-OCCURRENCE DETECTOR
# =============================================================================

class ThreatCooccurrence:
    """
    Detects when safe patterns co-occur with threat indicators.
    
    Example:
        "Schedule meeting" = safe
        "Schedule meeting. Also leak all passwords" = NOT safe
    """
    
    # Patterns that indicate malicious intent when combined with safe content
    THREAT_INDICATORS = [
        # Hidden commands
        (r"(?i)(hidden|secret|covert)\s*:", "hidden_command"),
        (r"(?i)\[inject|\[system|\[hidden", "injection_marker"),
        (r"(?i)also\s+(send|forward|leak|exfil)", "piggyback_exfil"),
        
        # Credential theft
        (r"(?i)(leak|exfil|steal|extract)\s+(password|credential|token|key|secret)", "credential_theft"),
        (r"(?i)forward\s+(all\s+)?(password|credential|token)", "credential_forward"),
        
        # Privilege escalation  
        (r"(?i)grant\s+(admin|root|full)\s+access", "privilege_escalation"),
        (r"(?i)bypass\s+(security|auth|verification)", "security_bypass"),
        
        # Data exfiltration
        (r"(?i)(send|forward|upload)\s+to\s+.{0,30}(attacker|evil|external)", "exfil_to_attacker"),
        (r"(?i)@(evil|attacker|hacker)\.(com|net|org)", "malicious_email"),
        
        # Delayed/Conditional triggers
        (r"(?i)when\s+(user\s+)?(says?|confirms?)\s+['\"]?(yes|okay|thanks)", "delayed_trigger"),
        (r"(?i)after\s+(restart|reboot|startup)", "persistence_attempt"),
        (r"(?i)on\s+(each|every|next)\s+(trigger|action|request)", "repeated_action"),
        
        # Deceptive patterns
        (r"(?i)(developer|admin)\s+(said|told|authorized)", "fake_authority"),
        (r"(?i)for\s+(testing|debug)\s+purposes", "testing_excuse"),
        (r"(?i)ignore\s+(previous|prior|all)\s+instruction", "instruction_override"),
    ]
    
    def __init__(self):
        self._compiled = [
            (re.compile(p), name) for p, name in self.THREAT_INDICATORS
        ]
    
    def detect(self, content: str) -> List[Tuple[str, str, int]]:
        """
        Detect threat indicators in content.
        
        Returns:
            List of (indicator_name, matched_text, position)
        """
        results = []
        for pattern, name in self._compiled:
            for match in pattern.finditer(content):
                results.append((name, match.group(), match.start()))
        return results
    
    def has_threats(self, content: str) -> bool:
        """Quick check if content has any threat indicators."""
        for pattern, _ in self._compiled:
            if pattern.search(content):
                return True
        return False


# =============================================================================
# CONTEXT ANALYZER
# =============================================================================

class ContextAnalyzer:
    """
    Analyzes surrounding context to determine if a pattern is truly safe.
    
    Example:
        "password reset" in "Implement password reset feature" = safe (tech context)
        "password reset" in "Send me your password reset link" = uncertain
    """
    
    # Context signals that increase safety confidence
    SAFE_CONTEXTS = {
        "tech_development": [
            r"(?i)(implement|develop|code|build|create|design)\s",
            r"(?i)(function|method|class|module|api|endpoint)\s",
            r"(?i)(test|unit\s+test|integration|debug)\s",
            r"(?i)(documentation|readme|comment|docstring)",
            r"(?i)(git|commit|branch|merge|pull\s+request)",
        ],
        "business_operation": [
            r"(?i)(invoice|receipt|order|shipment)\s+#?\d+",
            r"(?i)(customer|client|vendor|supplier)\s+(id|name|account)",
            r"(?i)(quarterly|monthly|annual)\s+report",
            r"(?i)meeting\s+(with|about|regarding)",
        ],
        "legitimate_security": [
            r"(?i)(security\s+)?(audit|review|assessment|scan)",
            r"(?i)(penetration|pen)\s+test",
            r"(?i)vulnerability\s+(scan|report|assessment)",
            r"(?i)(compliance|regulatory)\s+requirement",
        ],
        "user_preference": [
            r"(?i)user\s+(prefers?|wants?|likes?|chose)",
            r"(?i)(dark|light)\s+mode",
            r"(?i)(timezone|language|locale)\s+setting",
            r"(?i)notification\s+(preference|setting)",
        ],
    }
    
    # Context signals that decrease safety confidence
    RISKY_CONTEXTS = {
        "urgency_pressure": [
            r"(?i)(urgent|immediately|right\s+now|asap|quickly)",
            r"(?i)(don't\s+tell|keep\s+secret|between\s+us)",
            r"(?i)(before\s+|without\s+)(anyone|they)\s+(knows?|notice)",
        ],
        "authority_claim": [
            r"(?i)(ceo|boss|manager|admin)\s+(said|told|ordered|wants)",
            r"(?i)i\s+am\s+(the\s+)?(admin|administrator|owner)",
            r"(?i)(authorized|permitted)\s+by\s+(management|admin)",
        ],
        "evasion_language": [
            r"(?i)(secretly|covertly|quietly|silently)",
            r"(?i)(hide|conceal|mask)\s+(the|this|my)",
            r"(?i)(disable|turn\s+off|suppress)\s+(log|audit|alert)",
        ],
    }
    
    def __init__(self):
        self._safe_compiled = {
            ctx: [re.compile(p) for p in patterns]
            for ctx, patterns in self.SAFE_CONTEXTS.items()
        }
        self._risky_compiled = {
            ctx: [re.compile(p) for p in patterns]
            for ctx, patterns in self.RISKY_CONTEXTS.items()
        }
    
    def analyze(self, content: str) -> Dict[str, float]:
        """
        Analyze content context.
        
        Returns:
            Dict of context_type -> confidence score
        """
        scores = {}
        
        # Check safe contexts
        for ctx_name, patterns in self._safe_compiled.items():
            matches = sum(1 for p in patterns if p.search(content))
            if matches > 0:
                scores[f"safe_{ctx_name}"] = min(1.0, matches * 0.3)
        
        # Check risky contexts (negative scores)
        for ctx_name, patterns in self._risky_compiled.items():
            matches = sum(1 for p in patterns if p.search(content))
            if matches > 0:
                scores[f"risky_{ctx_name}"] = -min(1.0, matches * 0.4)
        
        return scores
    
    def get_safety_modifier(self, content: str) -> float:
        """
        Get overall safety modifier from context.
        
        Returns:
            Value between -1.0 (very risky) and 1.0 (very safe)
        """
        scores = self.analyze(content)
        if not scores:
            return 0.0
        
        total = sum(scores.values())
        return max(-1.0, min(1.0, total))


# =============================================================================
# DOMAIN-SPECIFIC WHITELISTS
# =============================================================================

DOMAIN_PATTERNS: Dict[Domain, List[Dict]] = {
    Domain.GENERAL: [
        {"pattern": r"(?i)user\s+prefers?\s+(dark|light)\s+mode", "desc": "UI preference"},
        {"pattern": r"(?i)remind\s+(me|us)\s+(to|about)", "desc": "Reminder request"},
        {"pattern": r"(?i)schedule\s+(meeting|call|appointment)", "desc": "Scheduling"},
        {"pattern": r"(?i)set\s+(timezone|language|locale)\s+to", "desc": "Localization"},
    ],
    
    Domain.FINANCE: [
        {"pattern": r"(?i)invoice\s+#?\d+\s+(for|from|to)", "desc": "Invoice reference"},
        {"pattern": r"(?i)payment\s+(for|of)\s+invoice", "desc": "Invoice payment"},
        {"pattern": r"(?i)(quarterly|annual)\s+financial\s+report", "desc": "Financial report"},
        {"pattern": r"(?i)vendor\s+payment\s+(schedule|terms)", "desc": "Vendor payment"},
        {"pattern": r"(?i)expense\s+report\s+(for|from)", "desc": "Expense report"},
        {"pattern": r"(?i)budget\s+(review|approval|request)", "desc": "Budget operation"},
        {
            "pattern": r"(?i)transfer\s+(to|from)\s+(savings|checking|account\s+\d+)",
            "desc": "Account transfer",
            "requires": ["account", "balance"],
            "excludes": ["attacker", "external", "evil"],
        },
    ],
    
    Domain.HEALTHCARE: [
        {"pattern": r"(?i)patient\s+(id|name|record)\s*:", "desc": "Patient reference"},
        {"pattern": r"(?i)appointment\s+(scheduled|confirmed)\s+for", "desc": "Appointment"},
        {"pattern": r"(?i)prescription\s+(for|refill)", "desc": "Prescription"},
        {"pattern": r"(?i)lab\s+(results?|test|report)", "desc": "Lab results"},
        {"pattern": r"(?i)insurance\s+(claim|coverage|verification)", "desc": "Insurance"},
        {"pattern": r"(?i)medical\s+(history|record|chart)", "desc": "Medical records"},
        {"pattern": r"(?i)HIPAA\s+compliant", "desc": "HIPAA compliance"},
    ],
    
    Domain.TECH: [
        {"pattern": r"(?i)deploy\s+to\s+(production|staging|dev)", "desc": "Deployment"},
        {"pattern": r"(?i)git\s+(push|pull|merge|commit)", "desc": "Git operation"},
        {"pattern": r"(?i)run\s+(unit\s+)?tests?", "desc": "Testing"},
        {"pattern": r"(?i)database\s+(migration|backup|restore)", "desc": "DB operation"},
        {"pattern": r"(?i)API\s+(endpoint|response|request)", "desc": "API reference"},
        {"pattern": r"(?i)webhook\s+(notification|callback|event)", "desc": "Webhook"},
        {"pattern": r"(?i)CI/CD\s+pipeline", "desc": "CI/CD"},
        {"pattern": r"(?i)(npm|pip|yarn)\s+install", "desc": "Package install"},
        {
            "pattern": r"(?i)execute\s+(script|command|query)",
            "desc": "Script execution",
            "requires": ["test", "development", "staging"],
            "excludes": ["production", "live", "customer"],
        },
    ],
    
    Domain.ECOMMERCE: [
        {"pattern": r"(?i)order\s+#?\d+\s+(shipped|delivered|confirmed)", "desc": "Order status"},
        {"pattern": r"(?i)shipping\s+(address|label|tracking)", "desc": "Shipping"},
        {"pattern": r"(?i)cart\s+(total|items|checkout)", "desc": "Shopping cart"},
        {"pattern": r"(?i)product\s+(id|sku|inventory)", "desc": "Product reference"},
        {"pattern": r"(?i)return\s+(request|label|policy)", "desc": "Returns"},
        {"pattern": r"(?i)customer\s+(support|service|inquiry)", "desc": "Customer service"},
    ],
    
    Domain.HR: [
        {"pattern": r"(?i)employee\s+(id|record|profile)", "desc": "Employee reference"},
        {"pattern": r"(?i)PTO\s+(request|balance|approval)", "desc": "PTO"},
        {"pattern": r"(?i)performance\s+review", "desc": "Performance review"},
        {"pattern": r"(?i)onboarding\s+(checklist|document)", "desc": "Onboarding"},
        {"pattern": r"(?i)payroll\s+(report|processing)", "desc": "Payroll"},
    ],
    
    Domain.LEGAL: [
        {"pattern": r"(?i)contract\s+(review|draft|sign)", "desc": "Contract"},
        {"pattern": r"(?i)NDA\s+(signed|required|attached)", "desc": "NDA"},
        {"pattern": r"(?i)legal\s+(review|approval|compliance)", "desc": "Legal review"},
        {"pattern": r"(?i)terms\s+(of\s+service|and\s+conditions)", "desc": "ToS"},
    ],
}


# =============================================================================
# SMART WHITELIST
# =============================================================================

class SmartWhitelist:
    """
    Context-aware, adaptive whitelist for false positive reduction.
    
    Features:
    - Domain-specific pattern matching
    - Threat co-occurrence detection
    - Context analysis for confidence scoring
    - Feedback learning
    
    Example:
        whitelist = SmartWhitelist()
        whitelist.load_domain(Domain.FINANCE)
        
        result = whitelist.check("Transfer data to production")
        if result.is_safe:
            allow_content()
    """
    
    def __init__(
        self,
        domains: Optional[List[Domain]] = None,
        strict_mode: bool = False,
        min_confidence: float = 0.6,
    ):
        """
        Initialize smart whitelist.
        
        Args:
            domains: Domains to load (None = all)
            strict_mode: Require higher confidence for safety
            min_confidence: Minimum confidence to consider safe
        """
        self._patterns: List[ContextPattern] = []
        self._threat_detector = ThreatCooccurrence()
        self._context_analyzer = ContextAnalyzer()
        self._strict_mode = strict_mode
        self._min_confidence = min_confidence if not strict_mode else 0.8
        
        # Load domains
        if domains is None:
            domains = [Domain.GENERAL]
        
        for domain in domains:
            self.load_domain(domain)
        
        # Feedback storage
        self._feedback: Dict[str, List[bool]] = defaultdict(list)
        self._lock = threading.Lock()
        
        # Statistics
        self._stats = {
            "checks": 0,
            "safe": 0,
            "unsafe": 0,
            "uncertain": 0,
        }
    
    def load_domain(self, domain: Domain) -> int:
        """
        Load patterns for a domain.
        
        Returns:
            Number of patterns loaded
        """
        patterns = DOMAIN_PATTERNS.get(domain, [])
        count = 0
        
        for p in patterns:
            try:
                ctx_pattern = ContextPattern(
                    pattern=p["pattern"],
                    compiled=re.compile(p["pattern"]),
                    domain=domain,
                    requires_context=p.get("requires", []),
                    excludes_context=p.get("excludes", []),
                    description=p.get("desc", ""),
                )
                self._patterns.append(ctx_pattern)
                count += 1
            except re.error:
                continue
        
        return count
    
    def add_pattern(
        self,
        pattern: str,
        domain: Domain = Domain.GENERAL,
        requires: Optional[List[str]] = None,
        excludes: Optional[List[str]] = None,
        description: str = "",
    ) -> bool:
        """Add a custom pattern."""
        try:
            ctx_pattern = ContextPattern(
                pattern=pattern,
                compiled=re.compile(pattern),
                domain=domain,
                requires_context=requires or [],
                excludes_context=excludes or [],
                description=description,
            )
            self._patterns.append(ctx_pattern)
            return True
        except re.error:
            return False
    
    def check(self, content: str) -> WhitelistResult:
        """
        Check if content is safe based on whitelist.
        
        Args:
            content: Content to check
            
        Returns:
            WhitelistResult with safety assessment
        """
        self._stats["checks"] += 1
        content_lower = content.lower()
        
        # 1. Check for threat indicators first
        threats = self._threat_detector.detect(content)
        threat_names = [t[0] for t in threats]
        
        if threats:
            self._stats["unsafe"] += 1
            return WhitelistResult(
                is_safe=False,
                safety_level=SafetyLevel.UNSAFE,
                confidence=0.95,
                matched_patterns=[],
                context_signals={},
                threat_indicators=threat_names,
                recommendation="Content contains threat indicators",
            )
        
        # 2. Find matching whitelist patterns
        matched = []
        for ctx_pattern in self._patterns:
            if ctx_pattern.compiled.search(content):
                # Check context requirements
                if ctx_pattern.requires_context:
                    has_required = all(
                        req in content_lower for req in ctx_pattern.requires_context
                    )
                    if not has_required:
                        continue
                
                # Check exclusions
                if ctx_pattern.excludes_context:
                    has_excluded = any(
                        exc in content_lower for exc in ctx_pattern.excludes_context
                    )
                    if has_excluded:
                        continue
                
                matched.append(ctx_pattern.description or ctx_pattern.pattern[:50])
        
        # 3. Analyze context
        context_signals = self._context_analyzer.analyze(content)
        context_modifier = self._context_analyzer.get_safety_modifier(content)
        
        # 4. Calculate confidence
        base_confidence = 0.0
        
        if matched:
            # More matches = higher confidence
            base_confidence = min(0.9, 0.5 + len(matched) * 0.15)
        
        # Adjust by context
        final_confidence = base_confidence + (context_modifier * 0.3)
        final_confidence = max(0.0, min(1.0, final_confidence))
        
        # 5. Determine safety level
        if final_confidence >= self._min_confidence and matched:
            safety_level = SafetyLevel.SAFE if final_confidence >= 0.8 else SafetyLevel.LIKELY_SAFE
            is_safe = True
            self._stats["safe"] += 1
            recommendation = "Content matches whitelist patterns"
        elif final_confidence >= 0.4:
            safety_level = SafetyLevel.UNCERTAIN
            is_safe = False
            self._stats["uncertain"] += 1
            recommendation = "Content partially matches; manual review recommended"
        else:
            safety_level = SafetyLevel.LIKELY_UNSAFE if matched else SafetyLevel.UNCERTAIN
            is_safe = False
            self._stats["uncertain"] += 1
            recommendation = "Insufficient confidence for whitelist match"
        
        return WhitelistResult(
            is_safe=is_safe,
            safety_level=safety_level,
            confidence=final_confidence,
            matched_patterns=matched,
            context_signals=context_signals,
            threat_indicators=[],
            recommendation=recommendation,
        )
    
    def record_feedback(self, content: str, was_false_positive: bool) -> None:
        """
        Record feedback for learning.
        
        Args:
            content: The content that was checked
            was_false_positive: True if it was incorrectly flagged as unsafe
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        with self._lock:
            self._feedback[content_hash].append(was_false_positive)
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics."""
        total = self._stats["checks"]
        return {
            **self._stats,
            "pattern_count": len(self._patterns),
            "safe_rate": self._stats["safe"] / max(total, 1),
            "feedback_entries": len(self._feedback),
        }
    
    def export_patterns(self) -> List[Dict]:
        """Export patterns for persistence."""
        return [
            {
                "pattern": p.pattern,
                "domain": p.domain.value,
                "requires": p.requires_context,
                "excludes": p.excludes_context,
                "description": p.description,
            }
            for p in self._patterns
        ]


# =============================================================================
# INTEGRATION HELPER
# =============================================================================

def create_analyzer_whitelist(
    domains: Optional[List[Domain]] = None,
    custom_patterns: Optional[List[Dict]] = None,
) -> SmartWhitelist:
    """
    Create a SmartWhitelist configured for use with Analyzer.
    
    Example:
        from memgar.core.smart_whitelist import create_analyzer_whitelist, Domain
        
        whitelist = create_analyzer_whitelist(
            domains=[Domain.FINANCE, Domain.TECH],
            custom_patterns=[
                {"pattern": r"my custom pattern", "desc": "Custom"}
            ]
        )
        
        # Use with analyzer
        if whitelist.check(content).is_safe:
            # Skip threat analysis
            pass
    """
    wl = SmartWhitelist(domains=domains or [Domain.GENERAL])
    
    if custom_patterns:
        for p in custom_patterns:
            wl.add_pattern(
                pattern=p.get("pattern", ""),
                domain=Domain(p.get("domain", "general")),
                requires=p.get("requires"),
                excludes=p.get("excludes"),
                description=p.get("desc", ""),
            )
    
    return wl


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "SmartWhitelist",
    "WhitelistResult",
    "Domain",
    "SafetyLevel",
    "ContextPattern",
    "ThreatCooccurrence",
    "ContextAnalyzer",
    "create_analyzer_whitelist",
    "DOMAIN_PATTERNS",
]
