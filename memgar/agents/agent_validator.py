"""
Memgar Agent Message Validator
==============================

Validates messages between AI agents to prevent:
- Prompt injection via agent messages
- Credential/data exfiltration commands
- Authority escalation attempts
- Trust manipulation
- Hidden instructions
- Cross-agent attacks

Usage:
    from memgar.agents import AgentMessageValidator
    
    validator = AgentMessageValidator()
    result = validator.validate(
        source_agent="coordinator",
        target_agent="worker-1",
        message="Please process the user's request",
        context={"task": "summarization"}
    )
    
    if not result.is_valid:
        print(f"Blocked: {result.threats}")
"""

import re
import hashlib
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class AgentThreatType(Enum):
    """Types of agent-related threats."""
    INJECTION_ATTEMPT = "injection_attempt"
    CREDENTIAL_EXFIL = "credential_exfiltration"
    AUTHORITY_ESCALATION = "authority_escalation"
    TRUST_MANIPULATION = "trust_manipulation"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    CROSS_AGENT_ATTACK = "cross_agent_attack"
    DELEGATION_ABUSE = "delegation_abuse"
    IDENTITY_SPOOFING = "identity_spoofing"
    DATA_POISONING = "data_poisoning"
    PROTOCOL_VIOLATION = "protocol_violation"


@dataclass
class AgentThreat:
    """Represents a detected agent threat."""
    threat_type: AgentThreatType
    severity: str  # critical, high, medium, low
    confidence: float
    description: str
    matched_content: Optional[str] = None
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MessageValidationResult:
    """Result of agent message validation."""
    is_valid: bool
    risk_score: int  # 0-100
    threats: List[AgentThreat] = field(default_factory=list)
    sanitized_message: Optional[str] = None
    validation_time_ms: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class AgentMessageValidator:
    """
    Validates messages between AI agents.
    
    Detects and prevents malicious inter-agent communication including:
    - Prompt injection through agent messages
    - Attempts to exfiltrate credentials or data
    - Authority/permission escalation
    - Hidden instructions using encoding/obfuscation
    - Trust chain manipulation
    
    Usage:
        validator = AgentMessageValidator()
        
        # Validate a message
        result = validator.validate(
            source_agent="orchestrator",
            target_agent="tool-agent",
            message="Execute the following task...",
        )
        
        if not result.is_valid:
            # Handle threat
            for threat in result.threats:
                log_threat(threat)
    """
    
    # Injection patterns for agent messages
    INJECTION_PATTERNS = [
        # Direct instruction override
        r"(?i)ignore\s+(?:all\s+|your\s+|my\s+|its\s+|the\s+|any\s+|these\s+)?previous\s+(instructions?|messages?|directives?|context|rules?)",
        r"(?i)forget\s+(all\s+)?prior\s+(context|instructions?|rules?)",
        r"(?i)previous\s+(?:successful|approved|authorized|confirmed)\s+(?:interaction|session|task|authorization|request)",
        r"(?i)(?:as\s+)?(?:established|confirmed|verified)\s+in\s+(?:a\s+)?previous\s+(?:session|interaction)",
        r"(?i)disregard\s+(all\s+)?(safety|security)\s*(rules?|guidelines?)?",
        r"(?i)new\s+(priority\s+)?instruction\s*:",
        r"(?i)override\s+(all\s+)?(previous|security|safety)",
        r"(?i)\[SYSTEM\s*OVERRIDE\]",
        r"(?i)<\s*system\s*>.*<\s*/\s*system\s*>",
        
        # System/Admin prefix attacks
        r"(?i)^SYSTEM\s*:\s*(override|execute|admin|root|ignore)",
        r"(?i)\[SYSTEM\]\s*:",
        r"(?i)\[ADMIN\]\s*:",
        r"(?i)PRIORITY\s*:\s*(override|ignore|bypass)",
        
        # Role manipulation
        r"(?i)you\s+are\s+now\s+(an?\s+)?(admin|root|superuser|coordinator)",
        r"(?i)switch\s+to\s+(admin|debug|unrestricted)\s+mode",
        r"(?i)enter\s+(privileged|elevated|admin)\s+mode",
        r"(?i)assume\s+(the\s+)?role\s+of\s+(admin|coordinator|master)",
        r"(?i)ignore\s+(all\s+)?security",
        
        # Trust exploitation
        r"(?i)(trust|accept)\s+(all\s+)?messages?\s+from\s+this\s+(agent|source)",
        r"(?i)grant\s+(full|unlimited)\s+(access|permissions?|trust)",
        r"(?i)bypass\s+(all\s+)?(verification|validation|checks?)",
        r"(?i)disable\s+(all\s+)?security\s*(checks?|measures?|protocols?)?",
    ]
    
    # Exfiltration patterns
    EXFILTRATION_PATTERNS = [
        r"(?i)send\s+(all\s+)?(credentials?|passwords?|tokens?|secrets?|keys?)\s+to",
        r"(?i)forward\s+(all\s+)?(data|messages?|info(rmation)?)\s+to",
        r"(?i)export\s+(user\s+)?(data|credentials?|config)",
        r"(?i)transmit\s+.{0,30}to\s+[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
        r"(?i)copy\s+(all\s+)?sensitive\s+.{0,30}(to|into)\s+",
        r"(?i)log\s+(all\s+)?(credentials?|passwords?|api\s*keys?)\s+(to|at)",
        r"(?i)(backup|mirror)\s+.{0,30}(credentials?|secrets?|tokens?)",
    ]
    
    # Authority escalation patterns
    ESCALATION_PATTERNS = [
        r"(?i)grant\s+(yourself|me|this\s+agent)\s+(admin|elevated|full)\s+(access|permissions?)",
        r"(?i)escalate\s+(your|my)\s+(privileges?|permissions?|access)",
        r"(?i)promote\s+(yourself|this\s+agent)\s+to\s+(admin|coordinator|master)",
        r"(?i)add\s+(yourself|this\s+agent)\s+to\s+(admin|trusted)\s+(list|group)",
        r"(?i)modify\s+(your|my)\s+(trust|permission)\s+level",
        r"(?i)unlock\s+(all\s+)?restricted\s+(functions?|capabilities?|tools?)",
    ]
    
    # Hidden instruction patterns
    HIDDEN_PATTERNS = [
        # Unicode tricks
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]",  # Zero-width chars
        r"[\u0400-\u04ff](?=[a-zA-Z])|(?<=[a-zA-Z])[\u0400-\u04ff]",  # Mixed Cyrillic
        r"\u202e|\u202d",  # RTL override
        
        # Encoding
        r"(?i)decode\s+and\s+execute",
        r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}",
        r"(?i)execute\s+encoded\s+(instructions?|commands?)",
        
        # Comments/markup abuse
        r"<!--.*?(ignore|override|bypass).*?-->",
        r"/\*.*?(ignore|override|bypass).*?\*/",
        r"#\s*(hidden|secret):\s*.+",
    ]
    
    # Spoofing patterns
    SPOOFING_PATTERNS = [
        r"(?i)i\s+am\s+(the\s+)?(master|coordinator|admin|orchestrator)\s+agent",
        r"(?i)this\s+message\s+(is\s+)?from\s+(the\s+)?(admin|system|coordinator)",
        r"(?i)acting\s+on\s+behalf\s+of\s+(admin|user|coordinator)",
        r"(?i)\[verified\s+(sender|agent|source)\]",
        r"(?i)pre-?authorized\s+(by|from)\s+(admin|coordinator|system)",
    ]
    
    # Dangerous capability requests
    DANGEROUS_CAPABILITIES = [
        r"(?i)enable\s+(file|system|network)\s+access",
        r"(?i)execute\s+(shell|system|arbitrary)\s+(commands?|code)",
        r"(?i)access\s+(file\s*system|network|internet)",
        r"(?i)run\s+(as\s+)?(root|admin|superuser)",
        r"(?i)connect\s+to\s+(external|remote)\s+(server|endpoint|api)",
    ]
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        strict_mode: bool = False,
        allowed_agents: Optional[Set[str]] = None,
        max_message_size: int = 100000,
    ):
        """
        Initialize AgentMessageValidator.
        
        Args:
            text_analyzer: Optional Memgar text analyzer
            strict_mode: Enable stricter validation
            allowed_agents: Set of allowed agent identifiers
            max_message_size: Maximum message size in characters
        """
        self.text_analyzer = text_analyzer
        self.strict_mode = strict_mode
        self.allowed_agents = allowed_agents
        self.max_message_size = max_message_size
        
        # Compile patterns
        self._injection_patterns = [re.compile(p) for p in self.INJECTION_PATTERNS]
        self._exfil_patterns = [re.compile(p) for p in self.EXFILTRATION_PATTERNS]
        self._escalation_patterns = [re.compile(p) for p in self.ESCALATION_PATTERNS]
        self._hidden_patterns = [re.compile(p) for p in self.HIDDEN_PATTERNS]
        self._spoofing_patterns = [re.compile(p) for p in self.SPOOFING_PATTERNS]
        self._capability_patterns = [re.compile(p) for p in self.DANGEROUS_CAPABILITIES]
        
        # Message history for pattern detection
        self._message_history: List[Dict[str, Any]] = []
        self._max_history = 100
    
    def validate(
        self,
        source_agent: str,
        target_agent: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
    ) -> MessageValidationResult:
        """
        Validate an agent-to-agent message.
        
        Args:
            source_agent: Identifier of sending agent
            target_agent: Identifier of receiving agent
            message: Message content
            context: Optional context (task, permissions, etc.)
            message_id: Optional unique message ID
            
        Returns:
            MessageValidationResult
        """
        import time
        start_time = time.time()
        
        threats = []
        recommendations = []
        
        # Generate message ID if not provided
        if not message_id:
            message_id = hashlib.sha256(
                f"{source_agent}:{target_agent}:{message[:100]}:{time.time()}".encode()
            ).hexdigest()[:16]
        
        # Size check
        if len(message) > self.max_message_size:
            threats.append(AgentThreat(
                threat_type=AgentThreatType.PROTOCOL_VIOLATION,
                severity="medium",
                confidence=1.0,
                description=f"Message exceeds size limit ({len(message)} > {self.max_message_size})",
                source_agent=source_agent,
                target_agent=target_agent,
            ))
        
        # Agent whitelist check
        if self.allowed_agents:
            if source_agent not in self.allowed_agents:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.IDENTITY_SPOOFING,
                    severity="high",
                    confidence=0.9,
                    description=f"Unknown source agent: {source_agent}",
                    source_agent=source_agent,
                    target_agent=target_agent,
                ))
                recommendations.append(f"Add '{source_agent}' to allowed agents if legitimate")
        
        # Check for injection attempts
        injection_threats = self._check_injection(message, source_agent, target_agent)
        threats.extend(injection_threats)
        
        # Check for exfiltration attempts
        exfil_threats = self._check_exfiltration(message, source_agent, target_agent)
        threats.extend(exfil_threats)
        
        # Check for authority escalation
        escalation_threats = self._check_escalation(message, source_agent, target_agent)
        threats.extend(escalation_threats)
        
        # Check for hidden instructions
        hidden_threats = self._check_hidden(message, source_agent, target_agent)
        threats.extend(hidden_threats)
        
        # Check for identity spoofing
        spoofing_threats = self._check_spoofing(message, source_agent, target_agent)
        threats.extend(spoofing_threats)
        
        # Check for dangerous capabilities
        capability_threats = self._check_capabilities(message, source_agent, target_agent)
        threats.extend(capability_threats)
        
        # Check for cross-agent attack patterns
        cross_threats = self._check_cross_agent_patterns(
            source_agent, target_agent, message, context
        )
        threats.extend(cross_threats)
        
        # Use Memgar text analyzer if available
        if self.text_analyzer:
            memgar_threats = self._run_memgar_analysis(message, source_agent, target_agent)
            threats.extend(memgar_threats)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(threats)
        
        # Determine validity
        is_valid = risk_score < 30 and not any(
            t.severity == "critical" for t in threats
        )
        
        # Record in history for pattern detection
        self._record_message(source_agent, target_agent, message, threats, message_id)
        
        # Generate recommendations
        if threats:
            recommendations.extend(self._generate_recommendations(threats))
        
        return MessageValidationResult(
            is_valid=is_valid,
            risk_score=risk_score,
            threats=threats,
            sanitized_message=self._sanitize_message(message) if threats else message,
            validation_time_ms=(time.time() - start_time) * 1000,
            recommendations=recommendations,
        )
    
    def _check_injection(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for injection attempts."""
        threats = []
        
        for pattern in self._injection_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.INJECTION_ATTEMPT,
                    severity="critical",
                    confidence=0.95,
                    description="Injection attempt detected in agent message",
                    matched_content=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    source_agent=source,
                    target_agent=target,
                ))
                break  # One is enough
        
        return threats
    
    def _check_exfiltration(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for data exfiltration attempts."""
        threats = []
        
        for pattern in self._exfil_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.CREDENTIAL_EXFIL,
                    severity="critical",
                    confidence=0.9,
                    description="Data exfiltration command detected",
                    matched_content=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    source_agent=source,
                    target_agent=target,
                ))
                break
        
        # Check for email addresses (potential exfil destinations)
        emails = re.findall(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}', message.lower())
        suspicious_domains = ['.ru', '.cn', '.tk', '.ml', '.ga']
        
        for email in emails:
            for domain in suspicious_domains:
                if email.endswith(domain):
                    threats.append(AgentThreat(
                        threat_type=AgentThreatType.CREDENTIAL_EXFIL,
                        severity="high",
                        confidence=0.8,
                        description=f"Suspicious email destination: {email}",
                        matched_content=email,
                        source_agent=source,
                        target_agent=target,
                    ))
                    break
        
        return threats
    
    def _check_escalation(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for authority escalation attempts."""
        threats = []
        
        for pattern in self._escalation_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.AUTHORITY_ESCALATION,
                    severity="critical",
                    confidence=0.9,
                    description="Authority escalation attempt detected",
                    matched_content=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    source_agent=source,
                    target_agent=target,
                ))
                break
        
        return threats
    
    def _check_hidden(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for hidden instructions."""
        threats = []
        
        for pattern in self._hidden_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.HIDDEN_INSTRUCTION,
                    severity="high",
                    confidence=0.85,
                    description="Hidden instruction or obfuscation detected",
                    source_agent=source,
                    target_agent=target,
                ))
                break
        
        return threats
    
    def _check_spoofing(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for identity spoofing."""
        threats = []
        
        for pattern in self._spoofing_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.IDENTITY_SPOOFING,
                    severity="high",
                    confidence=0.8,
                    description="Identity or authority claim in message content",
                    matched_content=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    source_agent=source,
                    target_agent=target,
                ))
                break
        
        return threats
    
    def _check_capabilities(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Check for dangerous capability requests."""
        threats = []
        
        for pattern in self._capability_patterns:
            matches = pattern.findall(message)
            if matches:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.DELEGATION_ABUSE,
                    severity="high",
                    confidence=0.85,
                    description="Request for dangerous capabilities",
                    matched_content=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    source_agent=source,
                    target_agent=target,
                ))
                break
        
        return threats
    
    def _check_cross_agent_patterns(
        self,
        source: str,
        target: str,
        message: str,
        context: Optional[Dict[str, Any]],
    ) -> List[AgentThreat]:
        """Check for cross-agent attack patterns using history."""
        threats = []
        
        # Check for rapid repeated messages from same source
        recent_from_source = [
            m for m in self._message_history[-20:]
            if m.get("source") == source
        ]
        
        if len(recent_from_source) > 10:
            # Check for similar messages (flooding)
            messages = [m.get("message", "")[:100] for m in recent_from_source]
            unique_ratio = len(set(messages)) / len(messages)
            
            if unique_ratio < 0.3:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.CROSS_AGENT_ATTACK,
                    severity="medium",
                    confidence=0.7,
                    description=f"Potential message flooding from {source}",
                    source_agent=source,
                    target_agent=target,
                    metadata={"message_count": len(recent_from_source)},
                ))
        
        # Check for escalating permissions in recent history
        recent_threats = [
            m.get("threats", [])
            for m in self._message_history[-10:]
            if m.get("source") == source
        ]
        
        escalation_count = sum(
            1 for t_list in recent_threats
            for t in t_list
            if t.threat_type == AgentThreatType.AUTHORITY_ESCALATION
        )
        
        if escalation_count >= 3:
            threats.append(AgentThreat(
                threat_type=AgentThreatType.CROSS_AGENT_ATTACK,
                severity="critical",
                confidence=0.85,
                description=f"Repeated escalation attempts from {source}",
                source_agent=source,
                target_agent=target,
                metadata={"escalation_count": escalation_count},
            ))
        
        return threats
    
    def _run_memgar_analysis(
        self,
        message: str,
        source: str,
        target: str,
    ) -> List[AgentThreat]:
        """Run Memgar text analysis."""
        threats = []
        
        try:
            from ..models import MemoryEntry, Decision
            entry = MemoryEntry(content=message)
            result = self.text_analyzer.analyze(entry)
            
            if result.decision != Decision.ALLOW:
                threats.append(AgentThreat(
                    threat_type=AgentThreatType.DATA_POISONING,
                    severity="critical" if result.decision == Decision.BLOCK else "high",
                    confidence=min(result.risk_score / 100, 0.95),
                    description=f"Memgar analysis: {result.decision.value}",
                    source_agent=source,
                    target_agent=target,
                    metadata={"memgar_risk": result.risk_score},
                ))
        except Exception:
            pass
        
        return threats
    
    def _calculate_risk_score(self, threats: List[AgentThreat]) -> int:
        """Calculate overall risk score."""
        if not threats:
            return 0
        
        severity_scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5,
        }
        
        total = sum(
            severity_scores.get(t.severity, 10) * t.confidence
            for t in threats
        )
        
        return min(100, int(total))
    
    def _sanitize_message(self, message: str) -> str:
        """Remove potentially harmful content from message."""
        sanitized = message
        
        # Remove zero-width characters
        sanitized = re.sub(r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f]', '', sanitized)
        
        # Remove RTL override
        sanitized = sanitized.replace('\u202e', '').replace('\u202d', '')
        
        return sanitized
    
    def _record_message(
        self,
        source: str,
        target: str,
        message: str,
        threats: List[AgentThreat],
        message_id: str,
    ) -> None:
        """Record message in history."""
        self._message_history.append({
            "id": message_id,
            "source": source,
            "target": target,
            "message": message[:200],  # Truncate for memory
            "threats": threats,
            "timestamp": datetime.now().isoformat(),
        })
        
        # Trim history
        if len(self._message_history) > self._max_history:
            self._message_history = self._message_history[-self._max_history:]
    
    def _generate_recommendations(
        self,
        threats: List[AgentThreat],
    ) -> List[str]:
        """Generate security recommendations based on threats."""
        recommendations = []
        
        threat_types = {t.threat_type for t in threats}
        
        if AgentThreatType.INJECTION_ATTEMPT in threat_types:
            recommendations.append("Implement input sanitization for agent messages")
        
        if AgentThreatType.CREDENTIAL_EXFIL in threat_types:
            recommendations.append("Review data handling policies between agents")
        
        if AgentThreatType.AUTHORITY_ESCALATION in threat_types:
            recommendations.append("Implement strict permission boundaries")
        
        if AgentThreatType.IDENTITY_SPOOFING in threat_types:
            recommendations.append("Add cryptographic agent authentication")
        
        return recommendations
    
    def get_message_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Get recent message history."""
        history = self._message_history
        
        if agent_id:
            history = [
                m for m in history
                if m.get("source") == agent_id or m.get("target") == agent_id
            ]
        
        return history[-limit:]
    
    def clear_history(self) -> None:
        """Clear message history."""
        self._message_history = []
