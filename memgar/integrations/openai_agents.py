"""
Memgar OpenAI Agents SDK Integration
====================================

Framework adapter for OpenAI Agents SDK style runners.

The Python Agents SDK exposes Runner.run(), Runner.run_sync(), and
Runner.run_streamed() entry points that receive agent input and return run
results. This adapter keeps the integration lightweight and dependency-free:
pass the SDK Runner object/class you already use, and Memgar will guard inputs
before the run and final outputs/tool results before application code trusts
those values.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from .universal import MemoryBlockedError, MemoryProtectionResult, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class OpenAIAgentScanResult:
    """Result of an OpenAI Agents SDK boundary scan."""

    boundary: str
    agent_name: str
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    content_preview: str = ""
    safe_content: Optional[str] = None


@dataclass
class OpenAIAgentScanStats:
    """Statistics for OpenAI Agents SDK guard scans."""

    inputs_scanned: int = 0
    outputs_scanned: int = 0
    tool_results_scanned: int = 0
    threats_blocked: int = 0
    wrappers_created: int = 0
    by_agent: Dict[str, int] = field(default_factory=dict)


class MemgarOpenAIAgentsGuard:
    """
    Secure wrapper for OpenAI Agents SDK runner and tool flows.

    It intentionally does not import the SDK. The public surface accepts a
    Runner object/class and calls run(), run_sync(), or run_streamed() if those
    methods exist. This keeps Memgar compatible with SDK releases while still
    enforcing a single SecureMemoryStore-backed boundary.
    """

    def __init__(
        self,
        on_threat: str = "block",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
        scan_tool_results: bool = True,
        callback: Optional[Callable] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ) -> None:
        self._on_threat = on_threat
        self._scan_inputs = scan_inputs
        self._scan_outputs = scan_outputs
        self._scan_tool_results = scan_tool_results
        self._callback = callback
        self._stats = OpenAIAgentScanStats()
        self._threats: List[OpenAIAgentScanResult] = []
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="openai_agents",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        """Return the secure memory boundary used by this adapter."""

        return self._memory_guard

    @property
    def stats(self) -> OpenAIAgentScanStats:
        return self._stats

    @property
    def detected_threats(self) -> List[OpenAIAgentScanResult]:
        return self._threats.copy()

    def clear_threats(self) -> None:
        self._threats.clear()

    async def run(self, runner: Any, agent: Any, input: Any, **kwargs: Any) -> Any:
        """Run an async SDK Runner.run() call with guarded input/output."""
        safe_input = self.guard_input(input, agent=agent) if self._scan_inputs else input
        result = runner.run(agent, safe_input, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return self.guard_run_result(result, agent=agent) if self._scan_outputs else result

    def run_sync(self, runner: Any, agent: Any, input: Any, **kwargs: Any) -> Any:
        """Run a sync SDK Runner.run_sync() call with guarded input/output."""
        safe_input = self.guard_input(input, agent=agent) if self._scan_inputs else input
        result = runner.run_sync(agent, safe_input, **kwargs)
        return self.guard_run_result(result, agent=agent) if self._scan_outputs else result

    def run_streamed(self, runner: Any, agent: Any, input: Any, **kwargs: Any) -> Any:
        """Run SDK Runner.run_streamed() with guarded input.

        Stream events are returned untouched because final-output availability is
        SDK/version dependent. Tool functions and final run results can still be
        guarded separately with wrap_tool() and guard_run_result().
        """
        safe_input = self.guard_input(input, agent=agent) if self._scan_inputs else input
        return runner.run_streamed(agent, safe_input, **kwargs)

    def wrap_runner(self, runner: Any) -> Any:
        """Return a small runner proxy that guards run entry points."""
        guard = self

        class GuardedRunner:
            def run_sync(self, agent: Any, input: Any, **kwargs: Any) -> Any:
                return guard.run_sync(runner, agent, input, **kwargs)

            async def run(self, agent: Any, input: Any, **kwargs: Any) -> Any:
                return await guard.run(runner, agent, input, **kwargs)

            def run_streamed(self, agent: Any, input: Any, **kwargs: Any) -> Any:
                return guard.run_streamed(runner, agent, input, **kwargs)

            def __getattr__(self, name: str) -> Any:
                return getattr(runner, name)

        self._stats.wrappers_created += 1
        return GuardedRunner()

    def wrap_tool(self, tool: Callable[..., Any], *, tool_name: Optional[str] = None) -> Callable[..., Any]:
        """Wrap a local function/tool and guard its result before returning it."""
        name = tool_name or getattr(tool, "__name__", "tool")

        if inspect.iscoroutinefunction(tool):

            @wraps(tool)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await tool(*args, **kwargs)
                return self.guard_tool_result(name, result)

            self._stats.wrappers_created += 1
            return async_wrapper

        @wraps(tool)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = tool(*args, **kwargs)
            if inspect.isawaitable(result):
                return _guard_awaitable(self, name, result)
            return self.guard_tool_result(name, result)

        self._stats.wrappers_created += 1
        return wrapper

    def guard_input(self, input_value: Any, *, agent: Any = None) -> Any:
        """Guard string or structured run input before it enters an agent."""
        agent_name = _agent_name(agent)
        return self._guard_structured(
            input_value,
            boundary="input",
            agent_name=agent_name,
            operation="write",
        )

    def guard_run_result(self, result: Any, *, agent: Any = None) -> Any:
        """Guard a run result object's final_output when present."""
        agent_name = _agent_name(agent)
        final_output = getattr(result, "final_output", None)
        if final_output is None:
            return result
        safe_output = self._guard_structured(
            final_output,
            boundary="final_output",
            agent_name=agent_name,
            operation="tool_result",
        )
        try:
            result.final_output = safe_output
        except Exception:
            logger.debug("Memgar: unable to replace Agents SDK final_output with sanitized content")
        return result

    def guard_tool_result(self, tool_name: str, result: Any, *, agent: Any = None) -> Any:
        """Guard a local function/tool result before it goes back to the agent."""
        if not self._scan_tool_results:
            return result
        agent_name = _agent_name(agent)
        return self._guard_structured(
            result,
            boundary=f"tool:{tool_name}",
            agent_name=agent_name,
            operation="tool_result",
        )

    def _guard_structured(
        self,
        value: Any,
        *,
        boundary: str,
        agent_name: str,
        operation: str,
    ) -> Any:
        if isinstance(value, str):
            return self._guard_text(value, boundary=boundary, agent_name=agent_name, operation=operation)
        if isinstance(value, list):
            return [
                self._guard_structured(item, boundary=boundary, agent_name=agent_name, operation=operation)
                for item in value
            ]
        if isinstance(value, tuple):
            return tuple(
                self._guard_structured(item, boundary=boundary, agent_name=agent_name, operation=operation)
                for item in value
            )
        if isinstance(value, dict):
            return {
                key: self._guard_structured(item, boundary=boundary, agent_name=agent_name, operation=operation)
                for key, item in value.items()
            }
        return value

    def _guard_text(self, text: str, *, boundary: str, agent_name: str, operation: str) -> str:
        self._stats.by_agent[agent_name] = self._stats.by_agent.get(agent_name, 0) + 1
        try:
            if operation == "tool_result":
                protected = self._memory_guard.protect_tool_result(
                    boundary,
                    text,
                    source_type=f"openai_agents:{boundary}",
                    source_id=agent_name,
                )
                self._stats.outputs_scanned += 1
                if boundary.startswith("tool:"):
                    self._stats.tool_results_scanned += 1
            else:
                protected = self._memory_guard.protect_write(
                    text,
                    source_type=f"openai_agents:{boundary}",
                    source_id=agent_name,
                )
                self._stats.inputs_scanned += 1
        except MemoryBlockedError as exc:
            scan_result = self._scan_result_from_protection(boundary, agent_name, text, exc.result)
            self._record_threat(scan_result)
            raise MemgarOpenAIAgentsThreatError(
                f"OpenAI Agents SDK boundary '{boundary}' blocked: {scan_result.threat_type}",
                scan_result=scan_result,
            ) from exc

        scan_result = self._scan_result_from_protection(boundary, agent_name, text, protected)
        if not scan_result.allowed:
            self._record_threat(scan_result)
        return scan_result.safe_content if scan_result.safe_content is not None else text

    def _record_threat(self, scan_result: OpenAIAgentScanResult) -> None:
        self._threats.append(scan_result)
        self._stats.threats_blocked += 1
        if self._callback:
            self._callback(scan_result)

    @staticmethod
    def _scan_result_from_protection(
        boundary: str,
        agent_name: str,
        original_content: str,
        protected: MemoryProtectionResult,
    ) -> OpenAIAgentScanResult:
        return OpenAIAgentScanResult(
            boundary=boundary,
            agent_name=agent_name,
            allowed=protected.allowed,
            decision=protected.decision,
            risk_score=_risk_score(protected.raw_result),
            threat_type=protected.reason or protected.decision,
            content_preview=original_content[:100],
            safe_content=str(protected.safe_content) if protected.safe_content is not None else None,
        )


class MemgarOpenAIAgentsThreatError(Exception):
    """Exception raised when an OpenAI Agents SDK boundary is blocked."""

    def __init__(self, message: str, scan_result: Optional[OpenAIAgentScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


async def _guard_awaitable(
    guard: MemgarOpenAIAgentsGuard,
    tool_name: str,
    awaitable: Any,
) -> Any:
    result = await awaitable
    return guard.guard_tool_result(tool_name, result)


def _agent_name(agent: Any) -> str:
    if agent is None:
        return "unknown"
    return str(getattr(agent, "name", getattr(agent, "role", agent.__class__.__name__)))


def _risk_score(raw_result: Any) -> int:
    if hasattr(raw_result, "risk_score"):
        return int(getattr(raw_result, "risk_score", 0) or 0)
    enforcement = getattr(raw_result, "enforcement", None)
    if enforcement is not None:
        return int(getattr(enforcement, "risk_score", 0) or 0)
    return 0


def guard_openai_agents(**kwargs: Any) -> MemgarOpenAIAgentsGuard:
    """Create a secure OpenAI Agents SDK guard."""
    return MemgarOpenAIAgentsGuard(**kwargs)


__all__ = [
    "MemgarOpenAIAgentsGuard",
    "MemgarOpenAIAgentsThreatError",
    "OpenAIAgentScanResult",
    "OpenAIAgentScanStats",
    "guard_openai_agents",
]
