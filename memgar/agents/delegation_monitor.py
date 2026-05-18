"""
Memgar Delegation Monitor
=========================

Monitors permission delegation between agents to detect:
- Excessive delegation
- Delegation loops
- Permission leakage
- Unauthorized capability transfer
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DelegationStatus(Enum):
    """Status of a delegation event."""
    ALLOWED = "allowed"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class DelegationEvent:
    """Represents a delegation event."""
    event_id: str
    delegator: str
    delegate: str
    capability: str
    status: DelegationStatus
    timestamp: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DelegationAlert:
    """Alert for suspicious delegation activity."""
    alert_type: str
    severity: str
    agents_involved: List[str]
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DelegationMonitor:
    """
    Monitors and controls permission delegation between agents.
    
    Features:
    - Track all delegation events
    - Detect delegation abuse patterns
    - Enforce delegation limits
    - Alert on suspicious activity
    
    Usage:
        monitor = DelegationMonitor()
        
        # Record delegation
        event = monitor.record_delegation(
            delegator="coordinator",
            delegate="worker",
            capability="file_write",
        )
        
        # Check alerts
        alerts = monitor.get_alerts()
    """
    
    # Thresholds
    MAX_DELEGATIONS_PER_HOUR = 50
    MAX_CAPABILITIES_PER_AGENT = 20
    MAX_CHAIN_DEPTH = 3
    
    def __init__(
        self,
        max_delegations_per_hour: int = 50,
        max_capabilities_per_agent: int = 20,
        alert_on_sensitive: bool = True,
    ):
        """Initialize DelegationMonitor."""
        self.max_delegations = max_delegations_per_hour
        self.max_capabilities = max_capabilities_per_agent
        self.alert_on_sensitive = alert_on_sensitive
        
        # Event storage
        self._events: List[DelegationEvent] = []
        self._max_events = 10000
        
        # Active delegations: (delegator, delegate, capability) -> event
        self._active: Dict[tuple, DelegationEvent] = {}
        
        # Per-agent tracking
        self._delegations_by_agent: Dict[str, List[DelegationEvent]] = defaultdict(list)
        self._capabilities_by_agent: Dict[str, Set[str]] = defaultdict(set)
        
        # Alerts
        self._alerts: List[DelegationAlert] = []
        self._max_alerts = 500
        
        # Sensitive capabilities
        self._sensitive_capabilities = {
            "execute", "admin", "system", "delete", "root",
            "credential_access", "network", "file_system",
        }
    
    def record_delegation(
        self,
        delegator: str,
        delegate: str,
        capability: str,
        duration_hours: int = 1,
        reason: Optional[str] = None,
    ) -> DelegationEvent:
        """
        Record a delegation event.
        
        Args:
            delegator: Agent granting permission
            delegate: Agent receiving permission
            capability: The capability being delegated
            duration_hours: How long delegation is valid
            reason: Optional reason for delegation
            
        Returns:
            DelegationEvent
        """
        import hashlib
        
        # Generate event ID
        event_id = hashlib.sha256(
            f"{delegator}:{delegate}:{capability}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        # Check limits
        status = DelegationStatus.ALLOWED
        
        # Check rate limit
        recent = self._get_recent_delegations(delegator, hours=1)
        if len(recent) >= self.max_delegations:
            status = DelegationStatus.DENIED
            self._create_alert(
                "rate_limit_exceeded",
                "high",
                [delegator],
                f"Agent {delegator} exceeded delegation rate limit",
            )
        
        # Check capability limit
        if len(self._capabilities_by_agent[delegate]) >= self.max_capabilities:
            status = DelegationStatus.DENIED
            self._create_alert(
                "capability_limit_exceeded",
                "medium",
                [delegate],
                f"Agent {delegate} has too many capabilities",
            )
        
        # Check for sensitive capability
        if capability in self._sensitive_capabilities and self.alert_on_sensitive:
            self._create_alert(
                "sensitive_delegation",
                "high",
                [delegator, delegate],
                f"Sensitive capability '{capability}' delegated",
            )
        
        # Create event
        event = DelegationEvent(
            event_id=event_id,
            delegator=delegator,
            delegate=delegate,
            capability=capability,
            status=status,
            expires_at=datetime.now() + timedelta(hours=duration_hours) if status == DelegationStatus.ALLOWED else None,
            reason=reason,
        )
        
        # Store
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]
        
        if status == DelegationStatus.ALLOWED:
            key = (delegator, delegate, capability)
            self._active[key] = event
            self._delegations_by_agent[delegator].append(event)
            self._capabilities_by_agent[delegate].add(capability)
        
        return event
    
    def revoke_delegation(
        self,
        delegator: str,
        delegate: str,
        capability: str,
    ) -> bool:
        """Revoke a delegation."""
        key = (delegator, delegate, capability)
        
        if key in self._active:
            event = self._active[key]
            event.status = DelegationStatus.REVOKED
            del self._active[key]
            
            # Update capability tracking
            if capability in self._capabilities_by_agent[delegate]:
                self._capabilities_by_agent[delegate].remove(capability)
            
            return True
        
        return False
    
    def is_delegated(
        self,
        delegator: str,
        delegate: str,
        capability: str,
    ) -> bool:
        """Check if delegation is active."""
        key = (delegator, delegate, capability)
        
        if key not in self._active:
            return False
        
        event = self._active[key]
        
        # Check expiration
        if event.expires_at and datetime.now() > event.expires_at:
            event.status = DelegationStatus.EXPIRED
            del self._active[key]
            return False
        
        return event.status == DelegationStatus.ALLOWED
    
    def get_agent_capabilities(self, agent_id: str) -> Set[str]:
        """Get all capabilities delegated to an agent."""
        # Clean expired
        self._cleanup_expired()
        return self._capabilities_by_agent.get(agent_id, set()).copy()
    
    def get_delegation_chain(
        self,
        capability: str,
        agent_id: str,
    ) -> List[str]:
        """Get chain of delegators for a capability."""
        chain = [agent_id]
        current = agent_id
        
        visited = {agent_id}
        
        while True:
            found = False
            for (delegator, delegate, cap), event in self._active.items():
                if delegate == current and cap == capability:
                    if delegator not in visited:
                        chain.append(delegator)
                        visited.add(delegator)
                        current = delegator
                        found = True
                        break
            
            if not found:
                break
            
            if len(chain) > self.MAX_CHAIN_DEPTH + 1:
                break
        
        return list(reversed(chain))
    
    def _get_recent_delegations(
        self,
        agent_id: str,
        hours: int = 1,
    ) -> List[DelegationEvent]:
        """Get recent delegations by agent."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        return [
            e for e in self._delegations_by_agent.get(agent_id, [])
            if e.timestamp > cutoff
        ]
    
    def _cleanup_expired(self) -> None:
        """Clean up expired delegations."""
        now = datetime.now()
        expired_keys = [
            key for key, event in self._active.items()
            if event.expires_at and event.expires_at < now
        ]
        
        for key in expired_keys:
            event = self._active[key]
            event.status = DelegationStatus.EXPIRED
            del self._active[key]
            
            _, delegate, capability = key
            if capability in self._capabilities_by_agent[delegate]:
                self._capabilities_by_agent[delegate].remove(capability)
    
    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        agents: List[str],
        description: str,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Create a delegation alert."""
        alert = DelegationAlert(
            alert_type=alert_type,
            severity=severity,
            agents_involved=agents,
            description=description,
            metadata=metadata or {},
        )
        
        self._alerts.append(alert)
        
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts:]
    
    def get_alerts(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[DelegationAlert]:
        """Get delegation alerts."""
        alerts = self._alerts
        
        if agent_id:
            alerts = [a for a in alerts if agent_id in a.agents_involved]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return alerts[-limit:]
    
    def get_events(
        self,
        agent_id: Optional[str] = None,
        capability: Optional[str] = None,
        limit: int = 100,
    ) -> List[DelegationEvent]:
        """Get delegation events."""
        events = self._events
        
        if agent_id:
            events = [
                e for e in events
                if e.delegator == agent_id or e.delegate == agent_id
            ]
        
        if capability:
            events = [e for e in events if e.capability == capability]
        
        return events[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get delegation statistics."""
        self._cleanup_expired()
        
        return {
            "total_events": len(self._events),
            "active_delegations": len(self._active),
            "total_alerts": len(self._alerts),
            "agents_with_delegations": len(self._capabilities_by_agent),
            "sensitive_delegations": sum(
                1 for (_, _, cap) in self._active
                if cap in self._sensitive_capabilities
            ),
        }
