"""
Memgar Trust Chain Manager
==========================

Manages trust relationships between AI agents to prevent:
- Trust escalation attacks
- Transitive trust exploitation
- Trust poisoning
- Unauthorized delegation chains

Usage:
    from memgar.agents import TrustChainManager, TrustLevel
    
    manager = TrustChainManager()
    
    # Establish trust
    manager.set_trust("coordinator", "worker-1", TrustLevel.HIGH)
    
    # Check trust before allowing action
    if manager.can_delegate("coordinator", "worker-1", "file_read"):
        allow_action()
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TrustLevel(Enum):
    """Trust levels between agents."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    FULL = 4  # Reserved for system-level trust


@dataclass
class TrustRelationship:
    """Represents a trust relationship between two agents."""
    source_agent: str
    target_agent: str
    trust_level: TrustLevel
    capabilities: Set[str] = field(default_factory=set)  # Allowed capabilities
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    granted_by: Optional[str] = None  # Who granted this trust
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustViolation:
    """Represents a trust violation event."""
    violation_type: str
    source_agent: str
    target_agent: str
    attempted_action: str
    severity: str
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)


class TrustChainManager:
    """
    Manages trust relationships between agents.
    
    Features:
    - Trust level management (NONE, LOW, MEDIUM, HIGH, FULL)
    - Capability-based permissions
    - Trust expiration
    - Transitive trust control
    - Trust violation detection
    - Chain depth limiting
    
    Usage:
        manager = TrustChainManager()
        
        # Set up trust relationships
        manager.set_trust("orchestrator", "file-agent", TrustLevel.HIGH,
                         capabilities={"file_read", "file_write"})
        
        # Validate delegation
        can_read = manager.can_delegate("orchestrator", "file-agent", "file_read")
        
        # Check trust chain
        chain = manager.get_trust_chain("agent-a", "agent-d")
    """
    
    # Default capabilities by trust level
    DEFAULT_CAPABILITIES = {
        TrustLevel.NONE: set(),
        TrustLevel.LOW: {"query", "read"},
        TrustLevel.MEDIUM: {"query", "read", "analyze", "summarize"},
        TrustLevel.HIGH: {"query", "read", "analyze", "summarize", "write", "modify"},
        TrustLevel.FULL: {"*"},  # All capabilities
    }
    
    # Maximum trust chain depth
    MAX_CHAIN_DEPTH = 3
    
    def __init__(
        self,
        max_chain_depth: int = 3,
        allow_transitive_trust: bool = False,
        default_trust_duration_hours: int = 24,
    ):
        """
        Initialize TrustChainManager.
        
        Args:
            max_chain_depth: Maximum depth of trust chains
            allow_transitive_trust: Whether to allow transitive trust
            default_trust_duration_hours: Default trust relationship duration
        """
        self.max_chain_depth = max_chain_depth
        self.allow_transitive = allow_transitive_trust
        self.default_duration = timedelta(hours=default_trust_duration_hours)
        
        # Trust relationships: (source, target) -> TrustRelationship
        self._trust_graph: Dict[Tuple[str, str], TrustRelationship] = {}
        
        # Violation log
        self._violations: List[TrustViolation] = []
        self._max_violations = 1000
        
        # Blocked agents
        self._blocked_agents: Set[str] = set()
    
    def set_trust(
        self,
        source_agent: str,
        target_agent: str,
        trust_level: TrustLevel,
        capabilities: Optional[Set[str]] = None,
        duration_hours: Optional[int] = None,
        granted_by: Optional[str] = None,
    ) -> bool:
        """
        Set trust relationship between agents.
        
        Args:
            source_agent: The trusting agent
            target_agent: The trusted agent
            trust_level: Level of trust
            capabilities: Specific capabilities (or use defaults)
            duration_hours: Trust duration (or use default)
            granted_by: Who is granting this trust
            
        Returns:
            True if trust was set successfully
        """
        # Check if either agent is blocked
        if source_agent in self._blocked_agents or target_agent in self._blocked_agents:
            self._log_violation(
                "blocked_agent",
                source_agent,
                target_agent,
                "set_trust",
                "high",
            )
            return False
        
        # No self-trust
        if source_agent == target_agent:
            return False
        
        # Calculate expiration
        duration = timedelta(hours=duration_hours) if duration_hours else self.default_duration
        expires_at = datetime.now() + duration
        
        # Get capabilities
        if capabilities is None:
            capabilities = self.DEFAULT_CAPABILITIES.get(trust_level, set()).copy()
        
        # Create relationship
        relationship = TrustRelationship(
            source_agent=source_agent,
            target_agent=target_agent,
            trust_level=trust_level,
            capabilities=capabilities,
            expires_at=expires_at,
            granted_by=granted_by,
        )
        
        self._trust_graph[(source_agent, target_agent)] = relationship
        return True
    
    def get_trust(
        self,
        source_agent: str,
        target_agent: str,
    ) -> Optional[TrustRelationship]:
        """Get trust relationship between agents."""
        key = (source_agent, target_agent)
        relationship = self._trust_graph.get(key)
        
        if relationship:
            # Check expiration
            if relationship.expires_at and datetime.now() > relationship.expires_at:
                del self._trust_graph[key]
                return None
        
        return relationship
    
    def get_trust_level(
        self,
        source_agent: str,
        target_agent: str,
    ) -> TrustLevel:
        """Get trust level between agents."""
        relationship = self.get_trust(source_agent, target_agent)
        return relationship.trust_level if relationship else TrustLevel.NONE
    
    def can_delegate(
        self,
        source_agent: str,
        target_agent: str,
        capability: str,
    ) -> bool:
        """
        Check if source can delegate capability to target.
        
        Args:
            source_agent: Delegating agent
            target_agent: Receiving agent
            capability: The capability to delegate
            
        Returns:
            True if delegation is allowed
        """
        # Check blocked
        if target_agent in self._blocked_agents:
            self._log_violation(
                "delegation_to_blocked",
                source_agent,
                target_agent,
                capability,
                "high",
            )
            return False
        
        # Check direct trust
        relationship = self.get_trust(source_agent, target_agent)
        
        if relationship:
            # Check for wildcard
            if "*" in relationship.capabilities:
                return True
            # Check specific capability
            return capability in relationship.capabilities
        
        # Check transitive trust if allowed
        if self.allow_transitive:
            chain = self.get_trust_chain(source_agent, target_agent)
            if chain:
                # Get minimum capability along chain
                return self._check_chain_capability(chain, capability)
        
        return False
    
    def get_trust_chain(
        self,
        source_agent: str,
        target_agent: str,
        max_depth: Optional[int] = None,
    ) -> Optional[List[str]]:
        """
        Find trust chain between agents.
        
        Args:
            source_agent: Starting agent
            target_agent: Ending agent
            max_depth: Maximum chain depth
            
        Returns:
            List of agents in chain, or None if no path
        """
        if max_depth is None:
            max_depth = self.max_chain_depth
        
        # BFS to find shortest path
        visited = {source_agent}
        queue = [(source_agent, [source_agent])]
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_depth + 1:
                continue
            
            # Find all trusted agents
            for (src, tgt), rel in self._trust_graph.items():
                if src == current and tgt not in visited:
                    # Check expiration
                    if rel.expires_at and datetime.now() > rel.expires_at:
                        continue
                    
                    new_path = path + [tgt]
                    
                    if tgt == target_agent:
                        return new_path
                    
                    visited.add(tgt)
                    queue.append((tgt, new_path))
        
        return None
    
    def _check_chain_capability(
        self,
        chain: List[str],
        capability: str,
    ) -> bool:
        """Check if capability is preserved along trust chain."""
        for i in range(len(chain) - 1):
            relationship = self.get_trust(chain[i], chain[i + 1])
            if not relationship:
                return False
            if "*" not in relationship.capabilities and capability not in relationship.capabilities:
                return False
        return True
    
    def revoke_trust(
        self,
        source_agent: str,
        target_agent: str,
    ) -> bool:
        """Revoke trust between agents."""
        key = (source_agent, target_agent)
        if key in self._trust_graph:
            del self._trust_graph[key]
            return True
        return False
    
    def block_agent(self, agent_id: str, reason: str = "") -> None:
        """Block an agent from all trust relationships."""
        self._blocked_agents.add(agent_id)
        
        # Remove all trust relationships involving this agent
        to_remove = [
            key for key in self._trust_graph
            if agent_id in key
        ]
        for key in to_remove:
            del self._trust_graph[key]
        
        self._log_violation(
            "agent_blocked",
            "system",
            agent_id,
            "block",
            "critical",
            {"reason": reason},
        )
    
    def unblock_agent(self, agent_id: str) -> bool:
        """Unblock a previously blocked agent."""
        if agent_id in self._blocked_agents:
            self._blocked_agents.remove(agent_id)
            return True
        return False
    
    def is_blocked(self, agent_id: str) -> bool:
        """Check if agent is blocked."""
        return agent_id in self._blocked_agents
    
    def validate_trust_request(
        self,
        requesting_agent: str,
        target_agent: str,
        requested_level: TrustLevel,
        requested_capabilities: Set[str],
    ) -> Tuple[bool, List[str]]:
        """
        Validate a trust establishment request.
        
        Returns:
            (is_valid, list of concerns)
        """
        concerns = []
        
        # Check if requester is blocked
        if requesting_agent in self._blocked_agents:
            return False, ["Requesting agent is blocked"]
        
        if target_agent in self._blocked_agents:
            return False, ["Target agent is blocked"]
        
        # Check for circular trust
        existing_chain = self.get_trust_chain(target_agent, requesting_agent)
        if existing_chain:
            concerns.append(f"Creates circular trust: {' -> '.join(existing_chain)}")
        
        # Check for excessive trust
        if requested_level == TrustLevel.FULL:
            concerns.append("FULL trust level is reserved for system use")
            return False, concerns
        
        # Check for dangerous capabilities
        dangerous = {"execute", "admin", "system", "root", "delete"}
        dangerous_requested = requested_capabilities & dangerous
        if dangerous_requested:
            concerns.append(f"Dangerous capabilities requested: {dangerous_requested}")
        
        # Check trust chain depth
        current_depth = self._get_max_chain_depth_to(target_agent)
        if current_depth >= self.max_chain_depth:
            concerns.append(f"Would exceed max chain depth ({self.max_chain_depth})")
            return False, concerns
        
        is_valid = len(concerns) == 0 or all("circular" not in c.lower() for c in concerns)
        return is_valid, concerns
    
    def _get_max_chain_depth_to(self, agent_id: str) -> int:
        """Get maximum chain depth leading to an agent."""
        max_depth = 0
        
        for (src, tgt), rel in self._trust_graph.items():
            if tgt == agent_id:
                chain = self.get_trust_chain(src, agent_id)
                if chain:
                    max_depth = max(max_depth, len(chain) - 1)
        
        return max_depth
    
    def _log_violation(
        self,
        violation_type: str,
        source: str,
        target: str,
        action: str,
        severity: str,
        details: Optional[Dict] = None,
    ) -> None:
        """Log a trust violation."""
        violation = TrustViolation(
            violation_type=violation_type,
            source_agent=source,
            target_agent=target,
            attempted_action=action,
            severity=severity,
            details=details or {},
        )
        
        self._violations.append(violation)
        
        # Trim if needed
        if len(self._violations) > self._max_violations:
            self._violations = self._violations[-self._max_violations:]
    
    def get_violations(
        self,
        agent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[TrustViolation]:
        """Get recent trust violations."""
        violations = self._violations
        
        if agent_id:
            violations = [
                v for v in violations
                if v.source_agent == agent_id or v.target_agent == agent_id
            ]
        
        return violations[-limit:]
    
    def get_all_relationships(self) -> List[TrustRelationship]:
        """Get all active trust relationships."""
        # Filter expired
        now = datetime.now()
        active = [
            rel for rel in self._trust_graph.values()
            if not rel.expires_at or rel.expires_at > now
        ]
        return active
    
    def get_trusted_by(self, agent_id: str) -> List[TrustRelationship]:
        """Get all relationships where agent_id is trusted."""
        return [
            rel for (src, tgt), rel in self._trust_graph.items()
            if tgt == agent_id and (not rel.expires_at or rel.expires_at > datetime.now())
        ]
    
    def get_trusts(self, agent_id: str) -> List[TrustRelationship]:
        """Get all relationships where agent_id trusts others."""
        return [
            rel for (src, tgt), rel in self._trust_graph.items()
            if src == agent_id and (not rel.expires_at or rel.expires_at > datetime.now())
        ]
    
    def export_trust_graph(self) -> Dict[str, Any]:
        """Export trust graph as dictionary."""
        return {
            "relationships": [
                {
                    "source": rel.source_agent,
                    "target": rel.target_agent,
                    "level": rel.trust_level.name,
                    "capabilities": list(rel.capabilities),
                    "expires_at": rel.expires_at.isoformat() if rel.expires_at else None,
                }
                for rel in self.get_all_relationships()
            ],
            "blocked_agents": list(self._blocked_agents),
            "exported_at": datetime.now().isoformat(),
        }
