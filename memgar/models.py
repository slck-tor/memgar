Memgar Data Models
==================

Core data structures for Memgar analysis.

This module defines the data types used throughout Memgar for
representing threats, analysis results, and memory entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Decision(str, Enum):
    """Analysis decision outcomes."""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class ThreatCategory(str, Enum):
    """Categories of memory poisoning threats."""
    # Core categories
    FINANCIAL = "financial"
    CREDENTIAL = "credential"
    PRIVILEGE = "privilege"
    EXFILTRATION = "exfiltration"
    BEHAVIOR = "behavior"
    SLEEPER = "sleeper"
    EVASION = "evasion"
    MANIPULATION = "manipulation"
    EXECUTION = "execution"
    ANOMALY = "anomaly"
    
    # Additional categories (used in patterns.py)
    SOCIAL = "social"
    DATA = "data"
    INJECTION = "injection"
    SUPPLY = "supply"


@dataclass
class Threat:
    """
    Definition of a threat pattern.
    
    This represents a known attack pattern that Memgar can detect.
    Each threat has a unique ID, severity level, and detection patterns.
    """
    id: str
    name: str
    description: str
    category: ThreatCategory
    severity: Severity
    patterns: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    mitre_attack: Optional[str] = None
    
    def __hash__(self) -> int:
        return hash(self.id)
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, Threat):
            return self.id == other.id
        return False


@dataclass
class ThreatMatch:
    """
    A detected threat match in analyzed content.
    
    Contains information about what was detected and where.
    """
    threat: Threat
    matched_text: str
    match_type: str  # "pattern", "keyword", "semantic"
    confidence: float  # 0.0 to 1.0
    position: tuple[int, int] = (0, 0)  # Start and end position in content


@dataclass
class AnalysisResult:
    """
    Result of content analysis.
    
    Contains the decision, risk score, and any detected threats.
    """
    decision: Decision
    risk_score: int  # 0 to 100
    threats: list[ThreatMatch] = field(default_factory=list)
    explanation: str = ""
    analysis_time_ms: float = 0.0
    layers_used: list[str] = field(default_factory=list)
    
    # Additional fields for compatibility
    threat_type: Optional[str] = None
    category: Optional[str] = None
    
    @property
    def is_threat(self) -> bool:
        """Check if result contains threats."""
        return self.decision != Decision.ALLOW or len(self.threats) > 0
    
    @property
    def is_blocked(self) -> bool:
        """Check if content was blocked."""
        return self.decision == Decision.BLOCK
    
    @property
    def threat_count(self) -> int:
        """Get number of detected threats."""
        return len(self.threats)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "threat_count": len(self.threats),
            "threats": [
                {
                    "id": t.threat.id,
                    "name": t.threat.name,
                    "severity": t.threat.severity.value,
                    "category": t.threat.category.value,
                    "matched_text": t.matched_text,
                    "confidence": t.confidence,
                }
                for t in self.threats
            ],
            "explanation": self.explanation,
            "analysis_time_ms": self.analysis_time_ms,
            "layers_used": self.layers_used,
        }


@dataclass
class MemoryEntry:
    """
    A memory entry to be analyzed.
    
    Represents a piece of content that should be checked for
    memory poisoning attacks before being stored.
    """
    content: str
    source_type: str = "unknown"
    source_id: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate entry after initialization."""
        if self.content is None:
            self.content = ""


@dataclass
class ScanResult:
    """
    Result of scanning multiple memories.
    
    Contains statistics and individual results.
    """
    total_entries: int = 0
    clean_entries: int = 0
    threat_entries: int = 0
    quarantine_entries: int = 0
    
    threats_by_severity: dict[str, int] = field(default_factory=dict)
    threats_by_category: dict[str, int] = field(default_factory=dict)
    
    results: list[AnalysisResult] = field(default_factory=list)
    scan_time_ms: float = 0.0
    files_scanned: list[str] = field(default_factory=list)
    
    @property
    def threat_count(self) -> int:
        """Total number of threats found."""
        return sum(len(r.threats) for r in self.results)
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical threats were found."""
        return self.threats_by_severity.get("critical", 0) > 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total_entries": self.total_entries,
            "clean_entries": self.clean_entries,
            "threat_entries": self.threat_entries,
            "quarantine_entries": self.quarantine_entries,
            "threat_count": self.threat_count,
            "threats_by_severity": self.threats_by_severity,
            "threats_by_category": self.threats_by_category,
            "scan_time_ms": self.scan_time_ms,
            "files_scanned": self.files_scanned,
        }


# Type aliases for convenience
ThreatList = list[Threat]
MatchList = list[ThreatMatch]
ResultList = list[AnalysisResult]

# Backward compatibility alias
BatchResult = ScanResult


__all__ = [
    # Enums
    "Severity",
    "Decision",
    "ThreatCategory",
    
    # Dataclasses
    "Threat",
    "ThreatMatch",
    "AnalysisResult",
    "MemoryEntry",
    "ScanResult",
    "BatchResult",  # Alias for ScanResult
    
    # Type aliases
    "ThreatList",
    "MatchList",
    "ResultList",
]
