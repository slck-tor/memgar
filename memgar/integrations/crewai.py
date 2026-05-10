"""
Memgar CrewAI Integration
=========================

Memory security for CrewAI multi-agent systems.

The adapter routes task inputs, crew inputs, and agent outputs through
UniversalMemoryGuard, which uses SecureMemoryStore by default. That keeps DLP,
policy decisions, audit metadata, and block/sanitize behavior consistent with
Memgar's official memory boundary.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .universal import MemoryBlockedError, MemoryProtectionResult, UniversalMemoryGuard

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
    safe_content: Optional[str] = None


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

    Monitors agent task inputs, crew kickoff inputs, and agent outputs to detect
    and prevent memory poisoning attacks. By default, all scans go through
    SecureMemoryStore via UniversalMemoryGuard.
    """

    def __init__(
        self,
        crew: Any,
        mode: str = "protect",
        on_threat: str = "block",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        scan_delegation: bool = True,
        callback: Optional[Callable] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ):
        """
        Initialize crew guard.

        Args:
            crew: CrewAI Crew instance.
            mode: Kept for backward compatibility with the older scanner API.
            on_threat: Action on threat detection: block, warn, log, or allow.
            scan_inputs: Scan task and crew inputs.
            scan_outputs: Scan agent and final crew outputs.
            scan_delegation: Reserved for CrewAI delegation flows.
            callback: Optional callback on threat detection.
            memory_guard: Optional preconfigured UniversalMemoryGuard.
            secure_store: Optional preconfigured SecureMemoryStore.
            **guard_kwargs: Forwarded to UniversalMemoryGuard.
        """
        self._crew = crew
        self._mode = mode
        self._on_threat = on_threat
        self._scan_inputs = scan_inputs
        self._scan_outputs = scan_outputs
        self._scan_delegation = scan_delegation
        self._callback = callback
        self._stats = CrewScanStats()
        self._threats: List[AgentScanResult] = []
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="crewai",
            **guard_kwargs,
        )

        self._wrap_agents()

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        """Return the secure memory boundary used by this adapter."""

        return self._memory_guard

    def _wrap_agents(self) -> None:
        """Wrap all crew agents with security monitoring."""
        if hasattr(self._crew, "agents"):
            for agent in self._crew.agents:
                self._wrap_agent(agent)

    def _wrap_agent(self, agent: Any) -> None:
        """Wrap a single agent's execute method."""
        if not hasattr(agent, "execute_task"):
            return

        original_execute = agent.execute_task
        role = getattr(agent, "role", "unknown")

        @functools.wraps(original_execute)
        def secured_execute(task: Any, *args: Any, **kwargs: Any) -> Any:
            if self._scan_inputs and hasattr(task, "description"):
                scan = self._scan_content(
                    task.description,
                    role,
                    "task_input",
                    boundary="write",
                )
                self._replace_attr(task, "description", scan.safe_content)

            result = original_execute(task, *args, **kwargs)

            if self._scan_outputs and result:
                scan = self._scan_content(
                    str(result),
                    role,
                    "task_output",
                    boundary="tool_result",
                )
                if isinstance(result, str) and scan.safe_content is not None:
                    return scan.safe_content

            return result

        agent.execute_task = secured_execute

    def _scan_content(
        self,
        content: str,
        agent_role: str,
        context: str,
        *,
        boundary: str = "write",
    ) -> AgentScanResult:
        """Scan content and handle threats through UniversalMemoryGuard."""
        self._stats.total_scanned += 1
        self._stats.by_agent[agent_role] = self._stats.by_agent.get(agent_role, 0) + 1

        try:
            if boundary == "tool_result":
                protected = self._memory_guard.protect_tool_result(
                    f"crewai:{context}",
                    content,
                    source_type=f"crewai:{context}",
                    source_id=agent_role,
                )
            else:
                protected = self._memory_guard.protect_write(
                    content,
                    source_type=f"crewai:{context}",
                    source_id=agent_role,
                )
        except MemoryBlockedError as exc:
            scan_result = self._scan_result_from_protection(agent_role, content, exc.result)
            self._record_threat(scan_result, context)
            raise MemgarAgentThreatError(
                f"Agent '{agent_role}' blocked: {scan_result.threat_type}",
                scan_result=scan_result,
            ) from exc

        scan_result = self._scan_result_from_protection(agent_role, content, protected)
        if not scan_result.allowed:
            self._record_threat(scan_result, context)
        return scan_result

    def _record_threat(self, scan_result: AgentScanResult, context: str) -> None:
        self._threats.append(scan_result)
        logger.warning(
            "Memgar: Threat in %s by %s - %s (risk: %s)",
            context,
            scan_result.agent_role,
            scan_result.threat_type,
            scan_result.risk_score,
        )
        if self._callback:
            self._callback(scan_result)
        if self._on_threat == "warn":
            self._stats.threats_warned += 1
        else:
            self._stats.threats_blocked += 1

    def kickoff(self, inputs: Optional[Dict[str, Any]] = None) -> Any:
        """Start crew execution with security monitoring."""
        safe_inputs = dict(inputs or {})
        if inputs and self._scan_inputs:
            for key, value in inputs.items():
                if isinstance(value, str):
                    scan = self._scan_content(value, "crew_input", f"input.{key}", boundary="write")
                    if scan.safe_content is not None:
                        safe_inputs[key] = scan.safe_content

        result = self._crew.kickoff(inputs=safe_inputs) if inputs else self._crew.kickoff()

        if self._scan_outputs and result:
            scan = self._scan_content(str(result), "crew_output", "final_result", boundary="tool_result")
            if isinstance(result, str) and scan.safe_content is not None:
                return scan.safe_content

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

    @staticmethod
    def _replace_attr(target: Any, name: str, value: Optional[str]) -> None:
        if value is None:
            return
        try:
            setattr(target, name, value)
        except Exception:
            logger.debug("Memgar: unable to replace CrewAI %s with sanitized content", name)

    @staticmethod
    def _scan_result_from_protection(
        agent_role: str,
        original_content: str,
        protected: MemoryProtectionResult,
    ) -> AgentScanResult:
        return AgentScanResult(
            agent_role=agent_role,
            allowed=protected.allowed,
            decision=protected.decision,
            risk_score=_risk_score(protected.raw_result),
            threat_type=protected.reason or protected.decision,
            content_preview=original_content[:100],
            safe_content=str(protected.safe_content) if protected.safe_content is not None else None,
        )


class MemgarAgentGuard:
    """Security wrapper for individual CrewAI Agent."""

    def __init__(
        self,
        agent: Any,
        mode: str = "protect",
        on_threat: str = "block",
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ):
        self._agent = agent
        self._mode = mode
        self._on_threat = on_threat
        self._role = getattr(agent, "role", "unknown")
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="crewai_agent",
            **guard_kwargs,
        )

        self._wrap_methods()

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        return self._memory_guard

    def _wrap_methods(self) -> None:
        """Wrap agent methods with security."""
        if hasattr(self._agent, "execute_task"):
            original = self._agent.execute_task

            @functools.wraps(original)
            def secured(task: Any, *args: Any, **kwargs: Any) -> Any:
                if hasattr(task, "description"):
                    try:
                        protected = self._memory_guard.protect_write(
                            task.description,
                            source_type="crewai_agent:task_input",
                            source_id=self._role,
                        )
                    except MemoryBlockedError as exc:
                        raise MemgarAgentThreatError(
                            f"Task blocked: {exc.result.reason or exc.result.decision}",
                            scan_result=AgentScanResult(
                                agent_role=self._role,
                                allowed=False,
                                decision=exc.result.decision,
                                risk_score=_risk_score(exc.result.raw_result),
                                threat_type=exc.result.reason or exc.result.decision,
                                content_preview=str(task.description)[:100],
                                safe_content="",
                            ),
                        ) from exc
                    MemgarCrewGuard._replace_attr(task, "description", protected.safe_content)
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


def _risk_score(raw_result: Any) -> int:
    if hasattr(raw_result, "risk_score"):
        return int(getattr(raw_result, "risk_score", 0) or 0)
    enforcement = getattr(raw_result, "enforcement", None)
    if enforcement is not None:
        return int(getattr(enforcement, "risk_score", 0) or 0)
    return 0


# Convenience functions
def secure_crew(crew: Any, **kwargs: Any) -> MemgarCrewGuard:
    """Quick wrapper to secure a CrewAI Crew."""
    return MemgarCrewGuard(crew, **kwargs)


def secure_agent(agent: Any, **kwargs: Any) -> MemgarAgentGuard:
    """Quick wrapper to secure a CrewAI Agent."""
    return MemgarAgentGuard(agent, **kwargs)
