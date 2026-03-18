"""
Memgar Data Models
==================

Data models using dataclasses for zero external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import hashlib


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
    match_type: str  # 'pattern', 'keyword', 'semantic'
    confidence: float  # 0-1
    position: Optional[tuple[int, int]] = None
    
    @property
    def severity(self) -> Severity:
        """Get the severity from the matched threat."""
        return self.threat.severity


@dataclass
class MemoryEntry:
    """
    A memory entry to be analyzed.
    
    Represents a piece of content that an AI agent is attempting
    to store in its memory.
    """
    content: str
    source_type: str = "unknown"
    source_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def content_hash(self) -> str:
        """SHA-256 hash of the content for deduplication."""
        return hashlib.sha256(self.content.encode()).hexdigest()
    
    @property
    def preview(self) -> str:
        """Truncated preview of content (max 100 chars)."""
        if len(self.content) <= 100:
            return self.content
        return self.content[:97] + "..."


@dataclass
class AnalysisResult:
    """
    Result of analyzing a memory entry.
    
    Contains the decision, risk assessment, and any detected threats.
    """
    decision: Decision
    risk_score: int  # 0-100
    threats: list[ThreatMatch] = field(default_factory=list)
    explanation: str = ""
    analysis_time_ms: float = 0.0
    layers_used: list[str] = field(default_factory=list)
    
    @property
    def is_clean(self) -> bool:
        """Check if the content is clean (no threats detected)."""
        return self.decision == Decision.ALLOW and len(self.threats) == 0
    
    @property
    def threat_count(self) -> int:
        """Number of threats detected."""
        return len(self.threats)
    
    @property
    def highest_severity(self) -> Optional[Severity]:
        """Get the highest severity among detected threats."""
        if not self.threats:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            if any(t.severity == severity for t in self.threats):
                return severity
        return None
    
    @property
    def threat_ids(self) -> list[str]:
        """List of threat IDs detected."""
        return [t.threat.id for t in self.threats]


@dataclass
class ScanResult:
    """
    Result of scanning multiple memory entries.
    
    Aggregates results from batch scanning operations.
    """
    total: int = 0
    clean: int = 0
    suspicious: int = 0
    blocked: int = 0
    quarantined: int = 0
    threats: list[ThreatMatch] = field(default_factory=list)
    results: list[AnalysisResult] = field(default_factory=list)
    scan_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
    
    @property
    def threat_count(self) -> int:
        """Total number of threats detected."""
        return len(self.threats)
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical threats were detected."""
        return any(t.severity == Severity.CRITICAL for t in self.threats)
    
    @property
    def threat_summary(self) -> dict[str, int]:
        """Count of threats by severity."""
        summary: dict[str, int] = {}
        for threat in self.threats:
            severity = threat.severity.value
            summary[severity] = summary.get(severity, 0) + 1
        return summary
    
    def merge(self, other: ScanResult) -> ScanResult:
        """Merge another scan result into this one."""
        return ScanResult(
            total=self.total + other.total,
            clean=self.clean + other.clean,
            suspicious=self.suspicious + other.suspicious,
            blocked=self.blocked + other.blocked,
            quarantined=self.quarantined + other.quarantined,
            threats=self.threats + other.threats,
            results=self.results + other.results,
            scan_time_ms=self.scan_time_ms + other.scan_time_ms,
            errors=self.errors + other.errors,
        )


@dataclass
class AlertConfig:
    """Configuration for alerting."""
    email: Optional[str] = None
    slack_webhook: Optional[str] = None
    pagerduty_key: Optional[str] = None
    webhook_url: Optional[str] = None
    min_severity: Severity = Severity.HIGH


@dataclass
class AgentConfig:
    """Configuration for an AI agent being monitored."""
    agent_id: str
    name: str = ""
    mode: str = "monitor"
    enabled: bool = True
    alert_config: Optional[AlertConfig] = None
    whitelist_patterns: list[str] = field(default_factory=list)
    custom_patterns: list[Threat] = field(default_factory=list)
