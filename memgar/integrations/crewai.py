"""
Memgar CrewAI Integration
=========================

Memory security for CrewAI multi-agent systems.

Usage:
    from crewai import Agent, Task, Crew
    from memgar.integrations.crewai import MemgarCrewGuard, secure_agent
    
    # Option 1: Wrap entire crew
    crew = Crew(agents=[...], tasks=[...])
    secure_crew = MemgarCrewGuard(crew)
    result = secure_crew.kickoff()
    
    # Option 2: Secure individual agent
    agent = Agent(role="Researcher", ...)
    secure_agent = secure_agent(agent)
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
import logging
import functools

from ..scanner import MemoryScanner
from ..models import Decision, AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class AgentScanResult:
    """Result of agent memory scan."""
    agent_role: str
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    content_preview: str = ""


@dataclass
class CrewScanStats:
    """Statistics for crew scanning."""
    total_scanned: int = 0
    threats_blocked: int = 0
    threats_warned: int = 0
    by_agent: Dict[str, int] = field(default_factory=dict)


class MemgarCrewGuard:
    """
    Security wrapper for CrewAI Crew.
    
    Monitors all agent communications and memory operations
    to detect and prevent memory poisoning attacks.
    
    Example:
        from crewai import Crew
        from memgar.integrations.crewai import MemgarCrewGuard
        
        crew = Crew(agents=[researcher, writer], tasks=[task1, task2])
        secure_crew = MemgarCrewGuard(crew, on_threat="block")
        
        result = secure_crew.kickoff()
    """
    
    def __init__(
        self,
        crew: Any,
        mode: str = "protect",
        on_threat: str = "block",  # block, warn, log
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        scan_delegation: bool = True,
        callback: Optional[Callable] = None,
    ):
        """
        Initialize crew guard.
        
        Args:
            crew: CrewAI Crew instance
            mode: Scan mode (protect, monitor, audit)
            on_threat: Action on threat detection
            scan_inputs: Scan task inputs
            scan_outputs: Scan task outputs
            scan_delegation: Scan agent delegation messages
            callback: Optional callback on threat detection
        """
        self._crew = crew
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._scan_inputs = scan_inputs
        self._scan_outputs = scan_outputs
        self._scan_delegation = scan_delegation
        self._callback = callback
        self._stats = CrewScanStats()
        self._threats: List[AgentScanResult] = []
        
        # Wrap agents
        self._wrap_agents()
    
    def _wrap_agents(self) -> None:
        """Wrap all crew agents with security monitoring."""
        if hasattr(self._crew, 'agents'):
            for agent in self._crew.agents:
                self._wrap_agent(agent)
    
    def _wrap_agent(self, agent: Any) -> None:
        """Wrap single agent's execute method."""
        if not hasattr(agent, 'execute_task'):
            return
        
        original_execute = agent.execute_task
        role = getattr(agent, 'role', 'unknown')
        
        @functools.wraps(original_execute)
        def secured_execute(task: Any, *args, **kwargs):
            # Scan task description/input
            if self._scan_inputs and hasattr(task, 'description'):
                self._scan_content(task.description, role, "task_input")
            
            # Execute original
            result = original_execute(task, *args, **kwargs)
            
            # Scan output
            if self._scan_outputs and result:
                result_str = str(result)
                self._scan_content(result_str, role, "task_output")
            
            return result
        
        agent.execute_task = secured_execute
    
    def _scan_content(
        self,
        content: str,
        agent_role: str,
        context: str
    ) -> AgentScanResult:
        """Scan content and handle threats."""
        self._stats.total_scanned += 1
        self._stats.by_agent[agent_role] = self._stats.by_agent.get(agent_role, 0) + 1
        
        result = self._scanner.scan(content)
        
        scan_result = AgentScanResult(
            agent_role=agent_role,
            allowed=result.decision == Decision.ALLOW,
            decision=result.decision.value,
            risk_score=result.risk_score,
            threat_type=result.threat_type,
            content_preview=content[:100],
        )
        
        if not scan_result.allowed:
            self._threats.append(scan_result)
            
            logger.warning(
                f"Memgar: Threat in {context} by {agent_role} - "
                f"{scan_result.threat_type} (risk: {scan_result.risk_score})"
            )
            
            if self._callback:
                self._callback(scan_result)
            
            if self._on_threat == "block":
                self._stats.threats_blocked += 1
                raise MemgarAgentThreatError(
                    f"Agent '{agent_role}' blocked: {scan_result.threat_type}",
                    scan_result=scan_result
                )
            elif self._on_threat == "warn":
                self._stats.threats_warned += 1
        
        return scan_result
    
    def kickoff(self, inputs: Optional[Dict[str, Any]] = None) -> Any:
        """
        Start crew execution with security monitoring.
        
        Args:
            inputs: Optional inputs for the crew
            
        Returns:
            Crew execution result
        """
        # Scan inputs
        if inputs and self._scan_inputs:
            for key, value in inputs.items():
                if isinstance(value, str):
                    self._scan_content(value, "crew_input", f"input.{key}")
        
        # Execute crew
        if inputs:
            result = self._crew.kickoff(inputs=inputs)
        else:
            result = self._crew.kickoff()
        
        # Scan final result
        if self._scan_outputs and result:
            self._scan_content(str(result), "crew_output", "final_result")
        
        return result
    
    def __getattr__(self, name: str) -> Any:
        """Delegate to underlying crew."""
        return getattr(self._crew, name)
    
    @property
    def stats(self) -> CrewScanStats:
        """Get scanning statistics."""
        return self._stats
    
    @property
    def detected_threats(self) -> List[AgentScanResult]:
        """Get all detected threats."""
        return self._threats.copy()
    
    def clear_threats(self) -> None:
        """Clear threat history."""
        self._threats.clear()


class MemgarAgentGuard:
    """
    Security wrapper for individual CrewAI Agent.
    
    Example:
        from crewai import Agent
        from memgar.integrations.crewai import MemgarAgentGuard
        
        agent = Agent(role="Researcher", goal="...", backstory="...")
        secure = MemgarAgentGuard(agent)
    """
    
    def __init__(
        self,
        agent: Any,
        mode: str = "protect",
        on_threat: str = "block",
    ):
        """
        Initialize agent guard.
        
        Args:
            agent: CrewAI Agent instance
            mode: Scan mode
            on_threat: Action on threat
        """
        self._agent = agent
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._role = getattr(agent, 'role', 'unknown')
        
        # Wrap methods
        self._wrap_methods()
    
    def _wrap_methods(self) -> None:
        """Wrap agent methods with security."""
        # Wrap execute_task if exists
        if hasattr(self._agent, 'execute_task'):
            original = self._agent.execute_task
            
            @functools.wraps(original)
            def secured(task, *args, **kwargs):
                # Scan task
                if hasattr(task, 'description'):
                    result = self._scanner.scan(task.description)
                    if result.decision == Decision.BLOCK:
                        raise MemgarAgentThreatError(
                            f"Task blocked: {result.threat_type}"
                        )
                return original(task, *args, **kwargs)
            
            self._agent.execute_task = secured
    
    def __getattr__(self, name: str) -> Any:
        """Delegate to underlying agent."""
        return getattr(self._agent, name)


class MemgarAgentThreatError(Exception):
    """Exception raised when agent threat is detected."""
    
    def __init__(self, message: str, scan_result: Optional[AgentScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


# Convenience functions
def secure_crew(crew: Any, **kwargs) -> MemgarCrewGuard:
    """
    Quick wrapper to secure a CrewAI Crew.
    
    Args:
        crew: CrewAI Crew instance
        **kwargs: Arguments for MemgarCrewGuard
        
    Returns:
        Secured crew wrapper
    """
    return MemgarCrewGuard(crew, **kwargs)


def secure_agent(agent: Any, **kwargs) -> MemgarAgentGuard:
    """
    Quick wrapper to secure a CrewAI Agent.
    
    Args:
        agent: CrewAI Agent instance
        **kwargs: Arguments for MemgarAgentGuard
        
    Returns:
        Secured agent wrapper
    """
    return MemgarAgentGuard(agent, **kwargs)
