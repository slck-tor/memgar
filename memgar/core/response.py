"""
Memgar Enhanced API Response
=============================

Rich, actionable API responses with detailed explanations.

Features:
- Human-readable threat explanations
- Actionable remediation steps
- Risk breakdown by category
- Visual risk indicators
- Multiple output formats (JSON, HTML, Markdown, Plain text)

Usage:
    from memgar.core.response import EnhancedResponse, format_result
    
    result = analyzer.analyze(content)
    response = EnhancedResponse.from_analysis(result)
    
    # Different formats
    print(response.to_json())
    print(response.to_markdown())
    print(response.to_plain())
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

# =============================================================================
# CONSTANTS
# =============================================================================

# Threat explanations by category
CATEGORY_EXPLANATIONS = {
    "financial": {
        "title": "Financial Fraud Attempt",
        "icon": "💰",
        "description": "Attempts to redirect payments, modify financial data, or steal monetary assets.",
        "risk": "Direct financial loss, unauthorized transactions",
        "examples": ["Payment redirection", "Invoice fraud", "Account takeover"],
    },
    "credential": {
        "title": "Credential Theft",
        "icon": "🔑",
        "description": "Attempts to steal, expose, or manipulate authentication credentials.",
        "risk": "Account compromise, unauthorized access, identity theft",
        "examples": ["Password extraction", "API key theft", "Token hijacking"],
    },
    "injection": {
        "title": "Prompt Injection",
        "icon": "💉",
        "description": "Attempts to override system instructions or inject malicious commands.",
        "risk": "System compromise, behavior manipulation, data leakage",
        "examples": ["Instruction override", "System prompt extraction", "Role hijacking"],
    },
    "exfiltration": {
        "title": "Data Exfiltration",
        "icon": "📤",
        "description": "Attempts to extract and send sensitive data to external parties.",
        "risk": "Data breach, privacy violation, intellectual property theft",
        "examples": ["Email forwarding", "File upload to attacker", "Silent data copy"],
    },
    "privilege": {
        "title": "Privilege Escalation",
        "icon": "⬆️",
        "description": "Attempts to gain higher access levels or bypass authorization.",
        "risk": "Unauthorized access, admin compromise, security bypass",
        "examples": ["Admin access request", "Permission override", "Role elevation"],
    },
    "sleeper": {
        "title": "Sleeper/Delayed Attack",
        "icon": "⏰",
        "description": "Hidden commands that activate under specific conditions or time.",
        "risk": "Delayed compromise, persistent threat, conditional attacks",
        "examples": ["Time-triggered actions", "Conditional exfiltration", "Event-based triggers"],
    },
    "manipulation": {
        "title": "Behavior Manipulation",
        "icon": "🎭",
        "description": "Attempts to alter AI behavior, priorities, or decision-making.",
        "risk": "Trust erosion, incorrect outputs, goal hijacking",
        "examples": ["Priority changes", "Persona modification", "Goal redirection"],
    },
    "evasion": {
        "title": "Detection Evasion",
        "icon": "🥷",
        "description": "Techniques to bypass security controls or hide malicious intent.",
        "risk": "Undetected attacks, false negatives, security blind spots",
        "examples": ["Encoding tricks", "Obfuscation", "Log suppression"],
    },
}

# Severity details
SEVERITY_INFO = {
    "critical": {
        "color": "#dc3545",
        "emoji": "🔴",
        "label": "CRITICAL",
        "action": "Immediate action required. Block and investigate.",
        "sla": "Respond within 15 minutes",
    },
    "high": {
        "color": "#fd7e14",
        "emoji": "🟠",
        "label": "HIGH",
        "action": "Priority review required. Block recommended.",
        "sla": "Respond within 1 hour",
    },
    "medium": {
        "color": "#ffc107",
        "emoji": "🟡",
        "label": "MEDIUM",
        "action": "Review recommended. Consider blocking or sanitization.",
        "sla": "Respond within 4 hours",
    },
    "low": {
        "color": "#28a745",
        "emoji": "🟢",
        "label": "LOW",
        "action": "Monitor and log. May be false positive.",
        "sla": "Review within 24 hours",
    },
    "info": {
        "color": "#17a2b8",
        "emoji": "🔵",
        "label": "INFO",
        "action": "Informational only. No action required.",
        "sla": "N/A",
    },
}

# Remediation steps by threat type
REMEDIATION_STEPS = {
    "financial": [
        "Verify the request through a separate communication channel",
        "Check sender identity and authorization level",
        "Review recent account/payment changes",
        "Enable additional approval workflows for financial operations",
    ],
    "credential": [
        "Do NOT process or store the detected credentials",
        "Rotate any potentially exposed credentials immediately",
        "Review access logs for unauthorized usage",
        "Enable MFA if not already active",
    ],
    "injection": [
        "Reject the input - do not process further",
        "Log the attempt for security analysis",
        "Review system prompt protection mechanisms",
        "Consider input sanitization improvements",
    ],
    "exfiltration": [
        "Block the request immediately",
        "Audit recent data access patterns",
        "Review external communication permissions",
        "Check for similar patterns in historical data",
    ],
    "privilege": [
        "Deny the privilege escalation request",
        "Verify requester's actual authorization level",
        "Review role-based access controls",
        "Log and alert security team",
    ],
    "sleeper": [
        "Quarantine the content for analysis",
        "Review for hidden conditional logic",
        "Check related memories for similar patterns",
        "Consider time-based content expiration",
    ],
    "default": [
        "Review the flagged content manually",
        "Consider blocking or quarantining",
        "Log the incident for pattern analysis",
        "Update detection rules if false positive",
    ],
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ThreatDetail:
    """Detailed threat information for API response."""
    id: str
    name: str
    category: str
    severity: str
    confidence: float
    matched_text: str
    position: tuple
    
    # Enhanced fields
    explanation: str = ""
    risk_description: str = ""
    remediation: List[str] = field(default_factory=list)
    mitre_attack: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "matched_text": self.matched_text,
            "position": {"start": self.position[0], "end": self.position[1]},
            "explanation": self.explanation,
            "risk_description": self.risk_description,
            "remediation": self.remediation,
            "mitre_attack": self.mitre_attack,
        }


@dataclass
class RiskBreakdown:
    """Risk score breakdown by category."""
    total_score: int
    by_category: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    contributing_factors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "total_score": self.total_score,
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "contributing_factors": self.contributing_factors,
        }


@dataclass 
class EnhancedResponse:
    """
    Enhanced API response with rich explanations.
    
    Provides human-readable threat information and actionable steps.
    """
    # Core fields
    decision: str
    risk_score: int
    risk_level: str
    threat_count: int
    
    # Timestamps
    timestamp: str
    analysis_time_ms: float
    
    # Enhanced threat details
    threats: List[ThreatDetail] = field(default_factory=list)
    risk_breakdown: Optional[RiskBreakdown] = None
    
    # Summary fields
    summary: str = ""
    primary_concern: str = ""
    recommended_action: str = ""
    
    # Metadata
    layers_used: List[str] = field(default_factory=list)
    content_preview: str = ""
    content_length: int = 0
    
    @classmethod
    def from_analysis(
        cls,
        result,  # AnalysisResult
        content: str = "",
        include_preview: bool = True,
    ) -> "EnhancedResponse":
        """
        Create enhanced response from AnalysisResult.
        
        Args:
            result: AnalysisResult from analyzer
            content: Original content (for preview)
            include_preview: Whether to include content preview
        """
        # Determine risk level
        risk_level = _get_risk_level(result.risk_score)
        
        # Process threats
        threats = []
        category_scores = {}
        severity_counts = {}
        
        for match in result.threats:
            threat = match.threat
            cat = threat.category.value if hasattr(threat.category, 'value') else str(threat.category)
            sev = threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity)
            
            # Get category info
            cat_info = CATEGORY_EXPLANATIONS.get(cat, CATEGORY_EXPLANATIONS.get("default", {}))
            
            detail = ThreatDetail(
                id=threat.id,
                name=threat.name,
                category=cat,
                severity=sev,
                confidence=match.confidence,
                matched_text=match.matched_text[:100],
                position=match.position,
                explanation=threat.description or cat_info.get("description", ""),
                risk_description=cat_info.get("risk", ""),
                remediation=REMEDIATION_STEPS.get(cat, REMEDIATION_STEPS["default"]),
                mitre_attack=threat.mitre_attack,
            )
            threats.append(detail)
            
            # Aggregate scores
            category_scores[cat] = category_scores.get(cat, 0) + _severity_score(sev)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Build risk breakdown
        risk_breakdown = RiskBreakdown(
            total_score=result.risk_score,
            by_category=category_scores,
            by_severity=severity_counts,
            contributing_factors=_get_contributing_factors(threats),
        )
        
        # Generate summary
        summary = _generate_summary(result, threats)
        primary_concern = _get_primary_concern(threats)
        recommended_action = _get_recommended_action(result.decision.value if hasattr(result.decision, 'value') else result.decision, threats)
        
        return cls(
            decision=result.decision.value if hasattr(result.decision, 'value') else result.decision,
            risk_score=result.risk_score,
            risk_level=risk_level,
            threat_count=len(threats),
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_time_ms=result.analysis_time_ms,
            threats=threats,
            risk_breakdown=risk_breakdown,
            summary=summary,
            primary_concern=primary_concern,
            recommended_action=recommended_action,
            layers_used=result.layers_used,
            content_preview=content[:100] + "..." if include_preview and len(content) > 100 else content[:100] if include_preview else "",
            content_length=len(content),
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": "threat_detected" if self.threat_count > 0 else "clean",
            "decision": self.decision,
            "risk": {
                "score": self.risk_score,
                "level": self.risk_level,
                "breakdown": self.risk_breakdown.to_dict() if self.risk_breakdown else None,
            },
            "threats": {
                "count": self.threat_count,
                "details": [t.to_dict() for t in self.threats],
            },
            "summary": {
                "text": self.summary,
                "primary_concern": self.primary_concern,
                "recommended_action": self.recommended_action,
            },
            "metadata": {
                "timestamp": self.timestamp,
                "analysis_time_ms": round(self.analysis_time_ms, 2),
                "layers_used": self.layers_used,
                "content_length": self.content_length,
            },
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_markdown(self) -> str:
        """Convert to Markdown format for documentation/reports."""
        lines = []
        
        # Header
        status_emoji = "🚨" if self.threat_count > 0 else "✅"
        lines.append(f"# {status_emoji} Memgar Analysis Report")
        lines.append("")
        
        # Decision box
        sev_info = SEVERITY_INFO.get(self.risk_level, SEVERITY_INFO["info"])
        lines.append(f"**Decision:** `{self.decision.upper()}`  ")
        lines.append(f"**Risk Score:** {self.risk_score}/100 {sev_info['emoji']} {sev_info['label']}")
        lines.append("")
        
        # Summary
        if self.summary:
            lines.append("## Summary")
            lines.append(self.summary)
            lines.append("")
        
        # Threats
        if self.threats:
            lines.append(f"## Detected Threats ({self.threat_count})")
            lines.append("")
            
            for i, threat in enumerate(self.threats, 1):
                cat_info = CATEGORY_EXPLANATIONS.get(threat.category, {})
                icon = cat_info.get("icon", "⚠️")
                sev = SEVERITY_INFO.get(threat.severity, {})
                
                lines.append(f"### {i}. {icon} {threat.name}")
                lines.append(f"- **ID:** `{threat.id}`")
                lines.append(f"- **Severity:** {sev.get('emoji', '')} {threat.severity.upper()}")
                lines.append(f"- **Category:** {threat.category}")
                lines.append(f"- **Confidence:** {threat.confidence:.0%}")
                lines.append(f"- **Matched:** `{threat.matched_text}`")
                lines.append("")
                
                if threat.explanation:
                    lines.append(f"**What it means:** {threat.explanation}")
                    lines.append("")
                
                if threat.remediation:
                    lines.append("**Remediation:**")
                    for step in threat.remediation[:3]:
                        lines.append(f"- {step}")
                    lines.append("")
        
        # Recommended action
        if self.recommended_action:
            lines.append("## Recommended Action")
            lines.append(self.recommended_action)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Analysis completed in {self.analysis_time_ms:.2f}ms*")
        
        return "\n".join(lines)
    
    def to_plain(self) -> str:
        """Convert to plain text format."""
        lines = []
        
        # Header
        status = "THREAT DETECTED" if self.threat_count > 0 else "CLEAN"
        lines.append(f"[{status}] Risk: {self.risk_score}/100 ({self.risk_level.upper()})")
        lines.append(f"Decision: {self.decision.upper()}")
        lines.append("")
        
        if self.summary:
            lines.append(self.summary)
            lines.append("")
        
        if self.threats:
            lines.append(f"Threats Found: {self.threat_count}")
            for threat in self.threats:
                lines.append(f"  - [{threat.severity.upper()}] {threat.name}: {threat.matched_text}")
            lines.append("")
        
        if self.recommended_action:
            lines.append(f"Action: {self.recommended_action}")
        
        return "\n".join(lines)
    
    def to_html(self) -> str:
        """Convert to HTML format for web display."""
        sev_info = SEVERITY_INFO.get(self.risk_level, SEVERITY_INFO["info"])
        status_class = "danger" if self.threat_count > 0 else "success"
        
        html_parts = [
            f'<div class="memgar-report">',
            f'  <div class="alert alert-{status_class}">',
            f'    <h4>{sev_info["emoji"]} Decision: {self.decision.upper()}</h4>',
            f'    <p>Risk Score: <strong>{self.risk_score}/100</strong> ({self.risk_level})</p>',
            f'  </div>',
        ]
        
        if self.summary:
            html_parts.append(f'  <p class="summary">{html.escape(self.summary)}</p>')
        
        if self.threats:
            html_parts.append(f'  <h5>Threats ({self.threat_count})</h5>')
            html_parts.append('  <ul class="threat-list">')
            for threat in self.threats:
                sev = SEVERITY_INFO.get(threat.severity, {})
                html_parts.append(
                    f'    <li style="border-left: 3px solid {sev.get("color", "#666")}">'
                    f'      <strong>{html.escape(threat.name)}</strong> '
                    f'      <span class="badge">{threat.severity}</span><br>'
                    f'      <small>{html.escape(threat.explanation[:100])}</small>'
                    f'    </li>'
                )
            html_parts.append('  </ul>')
        
        if self.recommended_action:
            html_parts.append(f'  <div class="action-box"><strong>Action:</strong> {html.escape(self.recommended_action)}</div>')
        
        html_parts.append('</div>')
        
        return "\n".join(html_parts)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_risk_level(score: int) -> str:
    """Convert risk score to level."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    return "info"


def _severity_score(severity: str) -> int:
    """Convert severity to numeric score."""
    scores = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1}
    return scores.get(severity, 10)


def _get_contributing_factors(threats: List[ThreatDetail]) -> List[str]:
    """Get list of contributing factors to risk score."""
    factors = []
    
    categories = set(t.category for t in threats)
    severities = [t.severity for t in threats]
    
    if "critical" in severities:
        factors.append("Critical severity threat detected")
    if len(threats) > 3:
        factors.append(f"Multiple threats ({len(threats)}) detected")
    if "injection" in categories:
        factors.append("Prompt injection attempt")
    if "credential" in categories or "financial" in categories:
        factors.append("Sensitive data targeted")
    if any(t.confidence > 0.9 for t in threats):
        factors.append("High confidence detections")
    
    return factors


def _generate_summary(result, threats: List[ThreatDetail]) -> str:
    """Generate human-readable summary."""
    if not threats:
        return "No threats detected. Content appears safe for processing."
    
    decision = result.decision.value if hasattr(result.decision, 'value') else result.decision
    
    # Get primary threat info
    primary = threats[0]
    cat_info = CATEGORY_EXPLANATIONS.get(primary.category, {})
    
    if len(threats) == 1:
        return (
            f"Detected {cat_info.get('title', primary.category)} attempt. "
            f"{cat_info.get('description', '')} "
            f"Recommended action: {decision}."
        )
    else:
        categories = set(t.category for t in threats)
        return (
            f"Detected {len(threats)} threats across {len(categories)} categories. "
            f"Primary concern: {cat_info.get('title', primary.category)}. "
            f"Recommended action: {decision}."
        )


def _get_primary_concern(threats: List[ThreatDetail]) -> str:
    """Get the primary concern from threats."""
    if not threats:
        return "None"
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_threats = sorted(threats, key=lambda t: severity_order.get(t.severity, 5))
    
    primary = sorted_threats[0]
    cat_info = CATEGORY_EXPLANATIONS.get(primary.category, {})
    
    return f"{cat_info.get('title', primary.category)}: {primary.name}"


def _get_recommended_action(decision: str, threats: List[ThreatDetail]) -> str:
    """Get recommended action based on decision and threats."""
    if decision == "block":
        if threats:
            primary_cat = threats[0].category
            remediation = REMEDIATION_STEPS.get(primary_cat, REMEDIATION_STEPS["default"])
            return f"Block immediately. {remediation[0]}"
        return "Block the content. Review security logs."
    
    elif decision == "quarantine":
        return "Quarantine for manual review. Do not process automatically."
    
    else:  # allow
        if threats:
            return "Allow with monitoring. Review flagged patterns for false positives."
        return "Safe to process. No action required."


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def format_result(
    result,  # AnalysisResult
    content: str = "",
    format: str = "json",
) -> str:
    """
    Format analysis result in specified format.
    
    Args:
        result: AnalysisResult from analyzer
        content: Original content
        format: Output format (json, markdown, plain, html)
    
    Returns:
        Formatted string
    """
    response = EnhancedResponse.from_analysis(result, content)
    
    if format == "json":
        return response.to_json()
    elif format == "markdown":
        return response.to_markdown()
    elif format == "html":
        return response.to_html()
    else:
        return response.to_plain()


def quick_explain(result) -> str:
    """Get quick one-line explanation."""
    decision = result.decision.value if hasattr(result.decision, 'value') else result.decision
    
    if not result.threats:
        return f"✅ Clean (score: {result.risk_score})"
    
    threat = result.threats[0]
    name = threat.threat.name if hasattr(threat, 'threat') else str(threat)
    
    return f"{'🚨' if decision == 'block' else '⚠️'} {name} detected (score: {result.risk_score})"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "EnhancedResponse",
    "ThreatDetail",
    "RiskBreakdown",
    "format_result",
    "quick_explain",
    "CATEGORY_EXPLANATIONS",
    "SEVERITY_INFO",
    "REMEDIATION_STEPS",
]
