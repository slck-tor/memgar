"""Framework-neutral memory guard adapter.

UniversalMemoryGuard protects arbitrary agent memory callables without depending
on LangChain, CrewAI, AutoGen, OpenAI Agents, MCP, or a specific vector store.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Iterable, Optional

from memgar.memory_guard import GuardDecision, MemoryGuard


class MemoryOperation(str, Enum):
    """Memory operation protected by the universal adapter."""

    WRITE = "write"
    READ = "read"
    TOOL_RESULT = "tool_result"
    MESSAGE = "message"


@dataclass
class MemoryProtectionResult:
    """Normalized result returned by the universal memory guard."""

    allowed: bool
    content: Any
    original_content: Any
    decision: str
    operation: str
    raw_result: Any
    reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def safe_content(self) -> Any:
        return self.content

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "operation": self.operation,
            "reason": self.reason,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class MemoryBlockedError(Exception):
    """Raised when a protected memory operation must not continue."""

    def __init__(self, message: str, result: MemoryProtectionResult):
        super().__init__(message)
        self.result = result


class UniversalMemoryGuard:
    """Protect arbitrary agent memory read/write callables.

    This adapter gives custom agents and not-yet-supported frameworks the same
    memory-poisoning guard surface: wrap a writer, wrap a reader, or call
    guard_write/guard_read directly.
    """

    BLOCK_ACTIONS = {"block", "raise", "human_review"}
    DROP_ACTIONS = {"drop", "quarantine"}
    PASS_ACTIONS = {"warn", "allow", "log"}

    def __init__(
        self,
        guard: Optional[Any] = None,
        *,
        on_write_threat: str = "block",
        on_read_threat: str = "drop",
        default_source_type: str = "agent_memory",
        default_source_id: Optional[str] = None,
        **guard_kwargs: Any,
    ) -> None:
        self.guard = guard or MemoryGuard(**guard_kwargs)
        self.on_write_threat = on_write_threat
        self.on_read_threat = on_read_threat
        self.default_source_type = default_source_type
        self.default_source_id = default_source_id

    def protect_write(self, content: Any, **context: Any) -> MemoryProtectionResult:
        """Inspect content before it is committed to memory."""
        return self._protect(
            content,
            operation=MemoryOperation.WRITE,
            on_threat=self.on_write_threat,
            **context,
        )

    def protect_read(self, content: Any, **context: Any) -> MemoryProtectionResult:
        """Inspect content retrieved from memory before it reaches the agent."""
        return self._protect(
            content,
            operation=MemoryOperation.READ,
            on_threat=self.on_read_threat,
            **context,
        )

    def guard_write(self, content: Any, **context: Any) -> Any:
        """Return safe write content or raise MemoryBlockedError."""
        return self.protect_write(content, **context).safe_content

    def guard_read(self, content: Any, **context: Any) -> Any:
        """Return safe read content. Threats are dropped by default."""
        return self.protect_read(content, **context).safe_content

    def wrap_writer(
        self,
        writer: Callable[..., Any],
        *,
        content_arg: int = 0,
        content_kw: Optional[str] = None,
        **context: Any,
    ) -> Callable[..., Any]:
        """Wrap a sync memory-write callable and replace unsafe content."""

        @wraps(writer)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            args, kwargs = self._replace_argument(
                args,
                kwargs,
                content_arg=content_arg,
                content_kw=content_kw,
                operation=MemoryOperation.WRITE,
                **context,
            )
            return writer(*args, **kwargs)

        return wrapper

    def wrap_async_writer(
        self,
        writer: Callable[..., Any],
        *,
        content_arg: int = 0,
        content_kw: Optional[str] = None,
        **context: Any,
    ) -> Callable[..., Any]:
        """Wrap an async or awaitable memory-write callable."""

        @wraps(writer)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            args, kwargs = self._replace_argument(
                args,
                kwargs,
                content_arg=content_arg,
                content_kw=content_kw,
                operation=MemoryOperation.WRITE,
                **context,
            )
            result = writer(*args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        return wrapper

    def wrap_reader(self, reader: Callable[..., Any], **context: Any) -> Callable[..., Any]:
        """Wrap a sync memory-read callable and filter retrieved content."""

        @wraps(reader)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return self.guard_read_results(reader(*args, **kwargs), **context)

        return wrapper

    def wrap_async_reader(self, reader: Callable[..., Any], **context: Any) -> Callable[..., Any]:
        """Wrap an async or awaitable memory-read callable."""

        @wraps(reader)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = reader(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
            return self.guard_read_results(result, **context)

        return wrapper

    def install_write_guard(
        self,
        target: Any,
        method_name: str,
        *,
        content_arg: int = 0,
        content_kw: Optional[str] = None,
        **context: Any,
    ) -> Any:
        """Patch target.method_name in place and return the target."""
        method = getattr(target, method_name)
        setattr(
            target,
            method_name,
            self.wrap_writer(method, content_arg=content_arg, content_kw=content_kw, **context),
        )
        return target

    def guard_read_results(self, records: Any, **context: Any) -> Any:
        """Filter common memory-read return shapes."""
        if isinstance(records, str):
            return self.guard_read(records, **context)
        if isinstance(records, tuple):
            return tuple(self._filter_record_list(records, **context))
        if isinstance(records, list):
            return self._filter_record_list(records, **context)
        if isinstance(records, dict) and "content" in records:
            return self._filter_record(records, **context)
        if records is not None:
            self.protect_read(records, **context)
        return records

    def _filter_record_list(self, records: Iterable[Any], **context: Any) -> list[Any]:
        filtered: list[Any] = []
        for record in records:
            guarded = self._filter_record(record, **context)
            if guarded is not None:
                filtered.append(guarded)
        return filtered

    def _filter_record(self, record: Any, **context: Any) -> Any:
        content = self._extract_content(record)
        result = self.protect_read(content, **context)
        if not result.allowed and result.safe_content in ("", None):
            return None
        if isinstance(record, str):
            return result.safe_content
        if isinstance(record, dict) and "content" in record:
            updated = dict(record)
            updated["content"] = result.safe_content
            return updated
        return record

    def _replace_argument(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        content_arg: int,
        content_kw: Optional[str],
        operation: MemoryOperation,
        **context: Any,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        args_list = list(args)
        if content_kw and content_kw in kwargs:
            protected = self._protect(
                kwargs[content_kw],
                operation=operation,
                on_threat=self.on_write_threat,
                **context,
            )
            kwargs[content_kw] = protected.safe_content
            return tuple(args_list), kwargs
        if len(args_list) <= content_arg:
            raise TypeError("wrapped memory callable did not receive content argument")
        protected = self._protect(
            args_list[content_arg],
            operation=operation,
            on_threat=self.on_write_threat,
            **context,
        )
        args_list[content_arg] = protected.safe_content
        return tuple(args_list), kwargs

    def _protect(
        self,
        content: Any,
        *,
        operation: MemoryOperation,
        on_threat: str,
        **context: Any,
    ) -> MemoryProtectionResult:
        source_type = context.pop("source_type", self.default_source_type)
        source_id = context.pop("source_id", self.default_source_id)
        text = self._to_text(content)
        metadata = {"operation": operation.value, **context}
        raw_result = self.guard.process(
            text,
            source_type=source_type,
            source_id=source_id,
            custom_metadata=metadata,
        )
        decision = self._decision_value(getattr(raw_result, "decision", "allow"))
        allowed = bool(
            getattr(raw_result, "allowed", decision in {"allow", "allow_sanitized", "sanitize"})
        )
        safe_text = getattr(raw_result, "safe_content", text) if allowed else ""
        protected = MemoryProtectionResult(
            allowed=allowed,
            content=self._restore_content_shape(content, safe_text),
            original_content=content,
            decision=self._normalized_decision(decision),
            operation=operation.value,
            raw_result=raw_result,
            reason=getattr(raw_result, "block_reason", None),
            warnings=list(getattr(raw_result, "warnings", []) or []),
            metadata={"source_type": source_type, "source_id": source_id},
        )
        return self._apply_threat_action(protected, on_threat)

    def _apply_threat_action(
        self,
        result: MemoryProtectionResult,
        on_threat: str,
    ) -> MemoryProtectionResult:
        action = (on_threat or "block").lower()
        if result.allowed:
            return result
        if action in self.PASS_ACTIONS:
            result.content = result.original_content
            return result
        if action in self.DROP_ACTIONS:
            result.content = ""
            return result
        if action in self.BLOCK_ACTIONS:
            raise MemoryBlockedError(result.reason or "Memgar blocked unsafe memory content", result)
        raise ValueError(f"Unsupported threat action: {on_threat}")

    @staticmethod
    def _decision_value(decision: Any) -> str:
        return getattr(decision, "value", str(decision))

    @staticmethod
    def _normalized_decision(decision: str) -> str:
        if decision == GuardDecision.ALLOW_SANITIZED.value:
            return "sanitize"
        return decision

    @staticmethod
    def _extract_content(record: Any) -> Any:
        if isinstance(record, dict) and "content" in record:
            return record["content"]
        return getattr(record, "content", record)

    @staticmethod
    def _to_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        try:
            return json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
        except TypeError:
            return str(content)

    @staticmethod
    def _restore_content_shape(original: Any, safe_text: str) -> Any:
        if isinstance(original, str):
            return safe_text
        if isinstance(original, dict) and "content" in original:
            updated = dict(original)
            updated["content"] = safe_text
            return updated
        return original if safe_text else ""


def guard_agent_memory(**kwargs: Any) -> UniversalMemoryGuard:
    """Create a framework-neutral memory guard."""
    return UniversalMemoryGuard(**kwargs)


def secure_memory_writer(writer: Callable[..., Any], **kwargs: Any) -> Callable[..., Any]:
    """Convenience wrapper for protecting a memory write callable."""
    guard = UniversalMemoryGuard(**kwargs)
    return guard.wrap_writer(writer)
