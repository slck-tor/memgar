"""
Memgar Agent Security Guard
===========================

Main security interface for multi-agent AI systems.
Combines all agent security components into a unified API.

Components:
- AgentMessageValidator: Inter-agent message security
- TrustChainManager: Trust relationship management
- DelegationMonitor: Permission delegation tracking
- SwarmDetector: Coordinated attack detection
- MCPSecurityLayer: MCP tool security

Usage:
    from memgar.agents import AgentSecurityGuard
    
    guard = AgentSecurityGuard()
    
    # Validate agent message
    result = guard.validate_message(
        source="coordinator",
        target="worker-1",
        message="Process this task"
    )
    
    # Validate tool call
    result = guard.validate_tool_call(
        agent_id="worker-1",
        tool_name="file_read",
        parameters={"path": "/data/file.txt"}
    )
    
    # Check for swarm attacks
    threats = guard.detect_swarm_attacks()
"""

from typing import Optional, Dict, List, Set, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .agent_validator import AgentMessageValidator, MessageValidationResult, AgentThreat
from .trust_chain import TrustChainManager, TrustLevel, TrustRelationship
from .delegation_monitor import DelegationMonitor, DelegationEvent
from .swarm_detector import SwarmDetector, SwarmThreat
from .mcp_security import MCPSecurityLayer, MCPValidationResult


class SecurityAction(Enum):
    """Actions to take based on security assessment."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"


@dataclass
class SecurityAssessment:
    """Comprehensive security assessment."""
    action: SecurityAction
    overall_risk: int  # 0-100
    is_safe: bool
    
    # Component results
    message_result: Optional[MessageValidationResult] = None
    mcp_result: Optional[MCPValidationResult] = None
    swarm_threats: List[SwarmThreat] = field(default_factory=list)
    
    # Summary
    threat_count: int = 0
    critical_threats: int = 0
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    assessment_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


class AgentSecurityGuard:
    """
    Unified security guard for multi-agent AI systems.
    
    Provides comprehensive security including:
    - Message validation between agents
    - Trust chain management
    - Permission delegation monitoring
    - Swarm attack detection
    - MCP tool security
    
    Usage:
        # Initialize with components
        guard = AgentSecurityGuard()
        
        # Validate agent message
        result = guard.validate_message(
            source="orchestrator",
            target="tool-agent",
            message="Execute this query",
        )
        
        # Manage trust
        guard.set_trust("orchestrator", "tool-agent", TrustLevel.HIGH)
        
        # Validate tool usage
        result = guard.validate_tool_call(
            agent_id="tool-agent",
            tool_name="database_query",
            parameters={"query": "SELECT * FROM users"}
        )
        
        # Monitor for swarm attacks
        threats = guard.detect_swarm_attacks()
    """
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        strict_mode: bool = False,
        allowed_agents: Optional[Set[str]] = None,
        allowed_tools: Optional[Set[str]] = None,
        trust_scorer: Optional[Any] = None,
    ):
        """
        Initialize AgentSecurityGuard.
        
        Args:
            text_analyzer: Optional Memgar text analyzer for content analysis
            strict_mode: Enable stricter security policies
            allowed_agents: Whitelist of allowed agent IDs
            allowed_tools: Whitelist of allowed MCP tools
        """
        self.text_analyzer = text_analyzer
        self.strict_mode   = strict_mode
        # CompositeTrustScorer for L1 inter-agent message analysis
        self._trust_scorer = trust_scorer or self._build_default_trust_scorer()
        
        # Initialize components
        self.message_validator = AgentMessageValidator(
            text_analyzer=text_analyzer,
            strict_mode=strict_mode,
            allowed_agents=allowed_agents,
        )
        
        self.trust_manager = TrustChainManager(
            allow_transitive_trust=not strict_mode,
        )
        
        self.delegation_monitor = DelegationMonitor(
            alert_on_sensitive=True,
        )
        
        self.swarm_detector = SwarmDetector()
        
        self.mcp_security = MCPSecurityLayer(
            text_analyzer=text_analyzer,
            allowed_tools=allowed_tools,
            strict_mode=strict_mode,
        )
        
        # Security event log
        self._security_log: List[Dict[str, Any]] = []
        self._max_log_size = 1000
    
    def _build_default_trust_scorer(self) -> Any:
        """Build a CompositeTrustScorer with allow=65 (higher than L1 default=60)."""
        try:
            from ..trust_scorer import CompositeTrustScorer
            return CompositeTrustScorer(allow_threshold=65.0, block_threshold=30.0)
        except Exception:
            return None

    def _run_composite_trust(
        self,
        message: str,
        source: str,
        target: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Run the 7-signal CompositeTrustScorer on an inter-agent message.

        Returns a dict with trust_score, risk_score, decision, blocked_by,
        or None if scorer unavailable.

        This bridges Layer 1 (composite trust) into the agents layer so that
        inter-agent messages receive the same 7-signal analysis as direct inputs.
        """
        if self._trust_scorer is None:
            return None
        try:
            from ..trust_scorer import TrustContext
            ctx = TrustContext(
                source_type = "agent",
                agent_id    = target,
                principal   = source,
            )
            result = self._trust_scorer.score(message, ctx)
            return {
                "trust_score": result.trust_score,
                "risk_score":  result.risk_score,
                "decision":    result.decision.value,
                "blocked_by":  result.blocked_by,
                "signals": [
                    {"name": s.name.value, "score": round(s.raw_score, 1), "critical": s.is_critical}
                    for s in result.signals if s.raw_score < 50 or s.is_critical
                ],
            }
        except Exception:
            return None

    def validate_message(
        self,
        source: str,
        target: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityAssessment:
        """
        Validate a message between agents.
        
        Args:
            source: Source agent ID
            target: Target agent ID
            context: Optional context
            
        Returns:
            SecurityAssessment
        """
        import time
        start_time = time.time()
        
        recommendations = []
        
        # Check trust relationship
        trust_level = self.trust_manager.get_trust_level(source, target)
        
        if trust_level == TrustLevel.NONE:
            if self.strict_mode:
                return SecurityAssessment(
                    action=SecurityAction.BLOCK,
                    overall_risk=80,
                    is_safe=False,
                    recommendations=["Establish trust relationship first"],
                    assessment_time_ms=(time.time() - start_time) * 1000,
                )
            else:
                recommendations.append(f"No trust relationship between {source} and {target}")
        
        # Validate message content
        msg_result = self.message_validator.validate(
            source_agent=source,
            target_agent=target,
            message=message,
            context=context,
        )
        
        # Layer 1: CompositeTrustScorer on inter-agent message
        # This runs the 7-signal analysis that standalone pattern checks miss.
        trust_analysis = self._run_composite_trust(message, source, target)
        if trust_analysis and trust_analysis["decision"] == "block":
            from ..agents.agent_validator import AgentThreat, AgentThreatType
            msg_result.threats.append(AgentThreat(
                threat_type  = AgentThreatType.DATA_POISONING,
                severity     = "critical",
                confidence   = 0.95,
                description  = (
                    f"Composite trust scorer BLOCK: "
                    f"trust={trust_analysis['trust_score']:.1f} "
                    f"blocked_by={trust_analysis['blocked_by']}"
                ),
                source_agent = source,
                target_agent = target,
                metadata     = trust_analysis,
            ))

        # Report activity for swarm detection
        self.swarm_detector.report_activity(
            agent_id=source,
            action="message",
            target=target,
            content=message[:100],
        )
        
        # Determine action
        action = SecurityAction.ALLOW
        if not msg_result.is_valid:
            if any(t.severity == "critical" for t in msg_result.threats):
                action = SecurityAction.BLOCK
            else:
                action = SecurityAction.WARN
        
        recommendations.extend(msg_result.recommendations)
        
        # Log event
        self._log_event("message_validation", {
            "source": source,
            "target": target,
            "action": action.value,
            "risk": msg_result.risk_score,
        })
        
        return SecurityAssessment(
            action=action,
            overall_risk=msg_result.risk_score,
            is_safe=msg_result.is_valid,
            message_result=msg_result,
            threat_count=len(msg_result.threats),
            critical_threats=sum(1 for t in msg_result.threats if t.severity == "critical"),
            recommendations=recommendations,
            assessment_time_ms=(time.time() - start_time) * 1000,
        )
    
    def validate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityAssessment:
        """
        Validate an MCP tool call from an agent.
        
        Args:
            agent_id: Calling agent
            tool_name: Tool being called
            parameters: Tool parameters
            context: Optional context
            
        Returns:
            SecurityAssessment
        """
        import time
        start_time = time.time()
        
        recommendations = []
        
        # Check if agent has tool capability
        delegated_caps = self.delegation_monitor.get_agent_capabilities(agent_id)
        has_capability = tool_name in delegated_caps or "tool_use" in delegated_caps
        
        if not has_capability and self.strict_mode:
            recommendations.append(f"Agent {agent_id} needs '{tool_name}' capability")
        
        # Validate tool call
        mcp_result = self.mcp_security.validate_tool_call(
            agent_id=agent_id,
            tool_name=tool_name,
            parameters=parameters,
            context=context,
        )
        
        # Report for swarm detection
        self.swarm_detector.report_activity(
            agent_id=agent_id,
            action=f"tool:{tool_name}",
            target=None,
            content=str(parameters)[:100],
        )
        
        # Determine action
        action = SecurityAction.ALLOW
        if not mcp_result.is_allowed:
            if any(t.severity == "critical" for t in mcp_result.threats):
                action = SecurityAction.BLOCK
            else:
                action = SecurityAction.WARN
        
        # Log event
        self._log_event("tool_call", {
            "agent": agent_id,
            "tool": tool_name,
            "action": action.value,
            "risk": mcp_result.risk_score,
        })
        
        return SecurityAssessment(
            action=action,
            overall_risk=mcp_result.risk_score,
            is_safe=mcp_result.is_allowed,
            mcp_result=mcp_result,
            threat_count=len(mcp_result.threats),
            critical_threats=sum(1 for t in mcp_result.threats if t.severity == "critical"),
            recommendations=recommendations,
            assessment_time_ms=(time.time() - start_time) * 1000,
        )
    
    def detect_swarm_attacks(self) -> List[SwarmThreat]:
        """
        Check for coordinated swarm attacks.
        
        Returns:
            List of detected SwarmThreat objects
        """
        threats = self.swarm_detector.detect_swarm_threats()
        
        # Log if threats found
        if threats:
            self._log_event("swarm_detected", {
                "threat_count": len(threats),
                "agents": [t.agents_involved for t in threats],
            })
        
        return threats
    
    def set_trust(
        self,
        source: str,
        target: str,
        level: TrustLevel,
        capabilities: Optional[Set[str]] = None,
        duration_hours: int = 24,
    ) -> bool:
        """
        Set trust relationship between agents.
        
        Args:
            source: Trusting agent
            target: Trusted agent
            level: Trust level
            capabilities: Specific capabilities to grant
            duration_hours: Trust duration
            
        Returns:
            True if trust was set
        """
        success = self.trust_manager.set_trust(
            source_agent=source,
            target_agent=target,
            trust_level=level,
            capabilities=capabilities,
            duration_hours=duration_hours,
        )
        
        if success:
            self._log_event("trust_established", {
                "source": source,
                "target": target,
                "level": level.name if hasattr(level, 'name') else str(level),
            })
        
        return success
    
    def revoke_trust(self, source: str, target: str) -> bool:
        """Revoke trust between agents."""
        success = self.trust_manager.revoke_trust(source, target)
        
        if success:
            self._log_event("trust_revoked", {
                "source": source,
                "target": target,
            })
        
        return success
    
    def delegate_capability(
        self,
        delegator: str,
        delegate: str,
        capability: str,
        duration_hours: int = 1,
    ) -> DelegationEvent:
        """
        Delegate a capability from one agent to another.
        
        Args:
            delegator: Agent granting capability
            delegate: Agent receiving capability
            capability: The capability
            duration_hours: Duration
            
        Returns:
            DelegationEvent
        """
        # Check trust first
        trust_level = self.trust_manager.get_trust_level(delegator, delegate)
        
        if trust_level.value < TrustLevel.MEDIUM.value:
            self._log_event("delegation_denied", {
                "delegator": delegator,
                "delegate": delegate,
                "capability": capability,
                "reason": "insufficient_trust",
            })
        
        event = self.delegation_monitor.record_delegation(
            delegator=delegator,
            delegate=delegate,
            capability=capability,
            duration_hours=duration_hours,
        )
        
        self._log_event("delegation", {
            "delegator": delegator,
            "delegate": delegate,
            "capability": capability,
            "status": event.status.value,
        })
        
        return event
    
    def block_agent(self, agent_id: str, reason: str = "") -> None:
        """
        Block an agent from all interactions.
        
        Args:
            agent_id: Agent to block
            reason: Reason for blocking
        """
        self.trust_manager.block_agent(agent_id, reason)
        
        self._log_event("agent_blocked", {
            "agent": agent_id,
            "reason": reason,
        })
    
    def unblock_agent(self, agent_id: str) -> bool:
        """Unblock a previously blocked agent."""
        success = self.trust_manager.unblock_agent(agent_id)
        
        if success:
            self._log_event("agent_unblocked", {"agent": agent_id})
        
        return success
    
    def is_agent_blocked(self, agent_id: str) -> bool:
        """Check if agent is blocked."""
        return self.trust_manager.is_blocked(agent_id)
    
    def get_agent_profile(self, agent_id: str) -> Dict[str, Any]:
        """
        Get comprehensive profile for an agent.
        
        Returns profile including trust, capabilities, and behavior.
        """
        return {
            "agent_id": agent_id,
            "is_blocked": self.trust_manager.is_blocked(agent_id),
            "trust_relationships": [
                {
                    "trusts": rel.target_agent,
                    "level": rel.trust_level.name,
                    "capabilities": list(rel.capabilities),
                }
                for rel in self.trust_manager.get_trusts(agent_id)
            ],
            "trusted_by": [
                {
                    "by": rel.source_agent,
                    "level": rel.trust_level.name,
                }
                for rel in self.trust_manager.get_trusted_by(agent_id)
            ],
            "delegated_capabilities": list(
                self.delegation_monitor.get_agent_capabilities(agent_id)
            ),
            "behavior_profile": self.swarm_detector.get_agent_profile(agent_id),
        }
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get overall security summary.
        
        Returns:
            Summary of security state
        """
        swarm_stats = self.swarm_detector.get_statistics()
        delegation_stats = self.delegation_monitor.get_statistics()
        mcp_stats = self.mcp_security.get_statistics()
        
        recent_events = self._security_log[-20:]
        recent_blocks = sum(1 for e in recent_events if e.get("data", {}).get("action") == "block")
        
        return {
            "timestamp": datetime.now().isoformat(),
            "components": {
                "message_validator": "active",
                "trust_manager": "active",
                "delegation_monitor": "active",
                "swarm_detector": "active",
                "mcp_security": "active",
            },
            "statistics": {
                "tracked_agents": swarm_stats["tracked_agents"],
                "active_delegations": delegation_stats["active_delegations"],
                "swarm_candidates": swarm_stats["swarm_candidates"],
                "total_mcp_threats": mcp_stats["total_threats"],
                "trust_relationships": len(self.trust_manager.get_all_relationships()),
            },
            "recent_activity": {
                "events": len(recent_events),
                "blocks": recent_blocks,
            },
            "alerts": {
                "swarm_threats": len(self.swarm_detector.get_threats(limit=10)),
                "delegation_alerts": len(self.delegation_monitor.get_alerts(limit=10)),
                "trust_violations": len(self.trust_manager.get_violations(limit=10)),
            },
            "mode": "strict" if self.strict_mode else "standard",
        }
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent security threats across all components."""
        threats = []
        
        # Message threats
        for t in self.message_validator.get_message_history(limit=limit):
            if t.get("threats"):
                threats.extend([
                    {
                        "source": "message_validator",
                        "type": threat.threat_type.value,
                        "severity": threat.severity,
                        "agents": [t.get("source"), t.get("target")],
                        "timestamp": t.get("timestamp"),
                    }
                    for threat in t.get("threats", [])
                ])
        
        # MCP threats
        for t in self.mcp_security.get_threats(limit=limit):
            threats.append({
                "source": "mcp_security",
                "type": t.threat_type.value,
                "severity": t.severity,
                "tool": t.tool_name,
                "agent": t.agent_id,
            })
        
        # Swarm threats
        for t in self.swarm_detector.get_threats(limit=limit):
            threats.append({
                "source": "swarm_detector",
                "type": t.threat_type.value,
                "severity": t.severity,
                "agents": t.agents_involved,
                "timestamp": t.timestamp.isoformat(),
            })
        
        # Sort by timestamp (most recent first)
        return sorted(threats, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    
    def _log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log a security event."""
        self._security_log.append({
            "type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        })
        
        if len(self._security_log) > self._max_log_size:
            self._security_log = self._security_log[-self._max_log_size:]
    
    def get_security_log(
        self,
        event_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get security event log."""
        log = self._security_log
        
        if event_type:
            log = [e for e in log if e.get("type") == event_type]
        
        return log[-limit:]
    
    def export_security_state(self) -> Dict[str, Any]:
        """Export complete security state."""
        return {
            "exported_at": datetime.now().isoformat(),
            "trust_graph": self.trust_manager.export_trust_graph(),
            "delegation_stats": self.delegation_monitor.get_statistics(),
            "swarm_stats": self.swarm_detector.get_statistics(),
            "mcp_stats": self.mcp_security.get_statistics(),
            "recent_events": self.get_security_log(limit=100),
            "summary": self.get_security_summary(),
        }
