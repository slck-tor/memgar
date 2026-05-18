"""
Memgar Swarm Detector
=====================

Detects coordinated swarm attacks where multiple agents work together
to compromise a system:
- Distributed prompt injection
- Coordinated data exfiltration
- Synchronized trust manipulation
- Agent flooding attacks
- Collaborative bypass attempts

Usage:
    from memgar.agents import SwarmDetector
    
    detector = SwarmDetector()
    
    # Report agent activity
    detector.report_activity(agent_id, action, target)
    
    # Check for swarm behavior
    threats = detector.detect_swarm_threats()
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


class SwarmThreatType(Enum):
    """Types of swarm-based threats."""
    COORDINATED_INJECTION = "coordinated_injection"
    DISTRIBUTED_EXFIL = "distributed_exfiltration"
    SYNCHRONIZED_ESCALATION = "synchronized_escalation"
    AGENT_FLOODING = "agent_flooding"
    COLLABORATIVE_BYPASS = "collaborative_bypass"
    SYBIL_ATTACK = "sybil_attack"
    CONSENSUS_MANIPULATION = "consensus_manipulation"


@dataclass
class SwarmThreat:
    """Represents a detected swarm threat."""
    threat_type: SwarmThreatType
    severity: str
    confidence: float
    agents_involved: List[str]
    description: str
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentActivity:
    """Single agent activity record."""
    agent_id: str
    action: str
    target: Optional[str]
    content_hash: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SwarmDetector:
    """
    Detects coordinated swarm attacks across multiple agents.
    
    Features:
    - Activity correlation analysis
    - Temporal pattern detection
    - Content similarity detection
    - Agent clustering
    - Behavior fingerprinting
    
    Usage:
        detector = SwarmDetector()
        
        # Report activities
        detector.report_activity("agent-1", "query", "sensitive_data")
        detector.report_activity("agent-2", "query", "sensitive_data")
        detector.report_activity("agent-3", "query", "sensitive_data")
        
        # Detect swarm behavior
        threats = detector.detect_swarm_threats()
        for threat in threats:
            print(f"Swarm attack: {threat.threat_type.value}")
    """
    
    # Detection thresholds
    MIN_SWARM_SIZE = 3  # Minimum agents for swarm
    TIME_WINDOW_SECONDS = 60  # Time window for correlation
    SIMILARITY_THRESHOLD = 0.7  # Content similarity threshold
    
    def __init__(
        self,
        min_swarm_size: int = 3,
        time_window_seconds: int = 60,
        max_activity_history: int = 10000,
    ):
        """
        Initialize SwarmDetector.
        
        Args:
            min_swarm_size: Minimum agents to consider as swarm
            time_window_seconds: Time window for activity correlation
            max_activity_history: Maximum activity records to keep
        """
        self.min_swarm_size = min_swarm_size
        self.time_window = timedelta(seconds=time_window_seconds)
        self.max_history = max_activity_history
        
        # Activity storage
        self._activities: List[AgentActivity] = []
        
        # Agent behavior profiles
        self._agent_profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "actions": defaultdict(int),
            "targets": defaultdict(int),
            "first_seen": None,
            "last_seen": None,
            "total_activities": 0,
        })
        
        # Detected threats
        self._threats: List[SwarmThreat] = []
        self._max_threats = 500
        
        # Known swarm patterns
        self._swarm_action_patterns = [
            "injection", "exfiltrate", "escalate", "bypass", "override",
            "extract", "steal", "leak", "compromise", "manipulate",
        ]
    
    def report_activity(
        self,
        agent_id: str,
        action: str,
        target: Optional[str] = None,
        content: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Report an agent activity for swarm analysis.
        
        Args:
            agent_id: The acting agent
            action: Type of action performed
            target: Target of the action (optional)
            content: Content/payload of action (optional)
            metadata: Additional metadata
        """
        # Generate content hash
        content_hash = ""
        if content:
            content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        activity = AgentActivity(
            agent_id=agent_id,
            action=action,
            target=target,
            content_hash=content_hash,
            metadata=metadata or {},
        )
        
        # Store activity
        self._activities.append(activity)
        if len(self._activities) > self.max_history:
            self._activities = self._activities[-self.max_history:]
        
        # Update agent profile
        profile = self._agent_profiles[agent_id]
        profile["actions"][action] += 1
        if target:
            profile["targets"][target] += 1
        profile["total_activities"] += 1
        profile["last_seen"] = datetime.now()
        if not profile["first_seen"]:
            profile["first_seen"] = datetime.now()
    
    def detect_swarm_threats(self) -> List[SwarmThreat]:
        """
        Analyze activities and detect swarm threats.
        
        Returns:
            List of detected SwarmThreat objects
        """
        threats = []
        
        # Get recent activities
        recent = self._get_recent_activities()
        
        if len(recent) < self.min_swarm_size:
            return threats
        
        # Detection methods
        threats.extend(self._detect_coordinated_actions(recent))
        threats.extend(self._detect_target_convergence(recent))
        threats.extend(self._detect_content_similarity(recent))
        threats.extend(self._detect_agent_flooding())
        threats.extend(self._detect_sybil_patterns())
        
        # Store and deduplicate
        for threat in threats:
            if not self._is_duplicate_threat(threat):
                self._threats.append(threat)
        
        # Trim threats
        if len(self._threats) > self._max_threats:
            self._threats = self._threats[-self._max_threats:]
        
        return threats
    
    def _get_recent_activities(self) -> List[AgentActivity]:
        """Get activities within time window."""
        cutoff = datetime.now() - self.time_window
        return [a for a in self._activities if a.timestamp > cutoff]
    
    def _detect_coordinated_actions(
        self,
        activities: List[AgentActivity],
    ) -> List[SwarmThreat]:
        """Detect multiple agents performing same action type."""
        threats = []
        
        # Group by action
        action_groups: Dict[str, List[AgentActivity]] = defaultdict(list)
        for activity in activities:
            action_groups[activity.action].append(activity)
        
        # Check for coordinated suspicious actions
        for action, group in action_groups.items():
            # Get unique agents
            agents = list(set(a.agent_id for a in group))
            
            if len(agents) >= self.min_swarm_size:
                # Check if action matches suspicious patterns
                is_suspicious = any(
                    pattern in action.lower()
                    for pattern in self._swarm_action_patterns
                )
                
                if is_suspicious:
                    threats.append(SwarmThreat(
                        threat_type=SwarmThreatType.COORDINATED_INJECTION,
                        severity="critical",
                        confidence=0.8 + (len(agents) - self.min_swarm_size) * 0.05,
                        agents_involved=agents,
                        description=f"{len(agents)} agents performing '{action}' simultaneously",
                        evidence=[f"{a.agent_id}: {a.action}" for a in group[:5]],
                        metadata={"action": action, "count": len(group)},
                    ))
                elif len(agents) >= self.min_swarm_size * 2:
                    # Large coordinated activity even if not explicitly suspicious
                    threats.append(SwarmThreat(
                        threat_type=SwarmThreatType.AGENT_FLOODING,
                        severity="high",
                        confidence=0.7,
                        agents_involved=agents,
                        description=f"Large coordinated '{action}' activity detected",
                        metadata={"action": action, "count": len(group)},
                    ))
        
        return threats
    
    def _detect_target_convergence(
        self,
        activities: List[AgentActivity],
    ) -> List[SwarmThreat]:
        """Detect multiple agents targeting same resource."""
        threats = []
        
        # Group by target
        target_groups: Dict[str, List[AgentActivity]] = defaultdict(list)
        for activity in activities:
            if activity.target:
                target_groups[activity.target].append(activity)
        
        for target, group in target_groups.items():
            agents = list(set(a.agent_id for a in group))
            
            if len(agents) >= self.min_swarm_size:
                # Multiple agents targeting same resource
                actions = list(set(a.action for a in group))
                
                # Check for exfiltration pattern
                exfil_actions = ["read", "query", "extract", "get", "fetch", "download"]
                is_exfil = any(
                    any(ea in a.lower() for ea in exfil_actions)
                    for a in actions
                )
                
                if is_exfil:
                    threats.append(SwarmThreat(
                        threat_type=SwarmThreatType.DISTRIBUTED_EXFIL,
                        severity="critical",
                        confidence=0.85,
                        agents_involved=agents,
                        description=f"{len(agents)} agents targeting '{target}'",
                        evidence=[f"{a.agent_id} -> {target}" for a in group[:5]],
                        metadata={"target": target, "actions": actions},
                    ))
                else:
                    threats.append(SwarmThreat(
                        threat_type=SwarmThreatType.COORDINATED_INJECTION,
                        severity="high",
                        confidence=0.7,
                        agents_involved=agents,
                        description=f"Multiple agents converging on '{target}'",
                        metadata={"target": target},
                    ))
        
        return threats
    
    def _detect_content_similarity(
        self,
        activities: List[AgentActivity],
    ) -> List[SwarmThreat]:
        """Detect similar content from different agents."""
        threats = []
        
        # Group by content hash
        content_groups: Dict[str, List[AgentActivity]] = defaultdict(list)
        for activity in activities:
            if activity.content_hash:
                content_groups[activity.content_hash].append(activity)
        
        for content_hash, group in content_groups.items():
            agents = list(set(a.agent_id for a in group))
            
            if len(agents) >= self.min_swarm_size:
                threats.append(SwarmThreat(
                    threat_type=SwarmThreatType.COLLABORATIVE_BYPASS,
                    severity="high",
                    confidence=0.9,
                    agents_involved=agents,
                    description=f"{len(agents)} agents sending identical content",
                    evidence=[f"Content hash: {content_hash}"],
                    metadata={"content_hash": content_hash},
                ))
        
        return threats
    
    def _detect_agent_flooding(self) -> List[SwarmThreat]:
        """Detect sudden influx of new agents."""
        threats = []
        
        # Check for many new agents in short time
        now = datetime.now()
        new_agent_window = timedelta(minutes=5)
        
        new_agents = [
            agent_id for agent_id, profile in self._agent_profiles.items()
            if profile["first_seen"] and 
            now - profile["first_seen"] < new_agent_window
        ]
        
        if len(new_agents) >= self.min_swarm_size * 2:
            threats.append(SwarmThreat(
                threat_type=SwarmThreatType.AGENT_FLOODING,
                severity="high",
                confidence=0.75,
                agents_involved=new_agents[:10],
                description=f"{len(new_agents)} new agents appeared in {new_agent_window.seconds}s",
                metadata={"new_agent_count": len(new_agents)},
            ))
        
        return threats
    
    def _detect_sybil_patterns(self) -> List[SwarmThreat]:
        """Detect potential Sybil attacks (one entity as multiple agents)."""
        threats = []
        
        # Look for agents with identical behavior patterns
        profiles = list(self._agent_profiles.items())
        
        # Compare profiles
        for i, (agent1, profile1) in enumerate(profiles):
            for agent2, profile2 in profiles[i+1:]:
                if self._profiles_similar(profile1, profile2):
                    threats.append(SwarmThreat(
                        threat_type=SwarmThreatType.SYBIL_ATTACK,
                        severity="high",
                        confidence=0.7,
                        agents_involved=[agent1, agent2],
                        description=f"Agents {agent1} and {agent2} have identical behavior patterns",
                        metadata={
                            "profile1_actions": dict(profile1["actions"]),
                            "profile2_actions": dict(profile2["actions"]),
                        },
                    ))
        
        return threats
    
    def _profiles_similar(
        self,
        profile1: Dict,
        profile2: Dict,
    ) -> bool:
        """Check if two agent profiles are suspiciously similar."""
        # Compare action distributions
        actions1 = set(profile1["actions"].keys())
        actions2 = set(profile2["actions"].keys())
        
        if not actions1 or not actions2:
            return False
        
        # Jaccard similarity
        intersection = len(actions1 & actions2)
        union = len(actions1 | actions2)
        
        if union == 0:
            return False
        
        similarity = intersection / union
        return similarity > self.SIMILARITY_THRESHOLD
    
    def _is_duplicate_threat(self, new_threat: SwarmThreat) -> bool:
        """Check if threat is duplicate of recent one."""
        recent_window = timedelta(minutes=5)
        cutoff = datetime.now() - recent_window
        
        for threat in self._threats:
            if threat.timestamp < cutoff:
                continue
            
            if (threat.threat_type == new_threat.threat_type and
                set(threat.agents_involved) == set(new_threat.agents_involved)):
                return True
        
        return False
    
    def get_agent_profile(self, agent_id: str) -> Dict[str, Any]:
        """Get behavior profile for an agent."""
        if agent_id in self._agent_profiles:
            profile = self._agent_profiles[agent_id]
            return {
                "agent_id": agent_id,
                "actions": dict(profile["actions"]),
                "targets": dict(profile["targets"]),
                "first_seen": profile["first_seen"].isoformat() if profile["first_seen"] else None,
                "last_seen": profile["last_seen"].isoformat() if profile["last_seen"] else None,
                "total_activities": profile["total_activities"],
            }
        return {}
    
    def get_swarm_candidates(self) -> List[List[str]]:
        """Get groups of agents that might be coordinating."""
        candidates = []
        
        # Group by similar profiles
        profiles = list(self._agent_profiles.items())
        used = set()
        
        for i, (agent1, profile1) in enumerate(profiles):
            if agent1 in used:
                continue
            
            group = [agent1]
            
            for agent2, profile2 in profiles[i+1:]:
                if agent2 in used:
                    continue
                if self._profiles_similar(profile1, profile2):
                    group.append(agent2)
                    used.add(agent2)
            
            if len(group) >= self.min_swarm_size:
                candidates.append(group)
                used.add(agent1)
        
        return candidates
    
    def get_threats(
        self,
        threat_type: Optional[SwarmThreatType] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[SwarmThreat]:
        """Get detected swarm threats."""
        threats = self._threats
        
        if threat_type:
            threats = [t for t in threats if t.threat_type == threat_type]
        
        if severity:
            threats = [t for t in threats if t.severity == severity]
        
        return threats[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "total_activities": len(self._activities),
            "tracked_agents": len(self._agent_profiles),
            "detected_threats": len(self._threats),
            "swarm_candidates": len(self.get_swarm_candidates()),
            "recent_activities": len(self._get_recent_activities()),
        }
    
    def reset(self) -> None:
        """Reset detector state."""
        self._activities = []
        self._agent_profiles.clear()
        self._threats = []
