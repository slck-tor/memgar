"""Framework-neutral memory guard adapter.

UniversalMemoryGuard protects arbitrary agent memory callables without depending
on LangChain, CrewAI, AutoGen, OpenAI Agents, MCP, or a specific vector store.

The default adapter path uses SecureMemoryStore so custom integrations inherit
Memgar's official write, read, retrieval, tool-result, DLP, and audit boundary.
The legacy MemoryGuard path is still available as an explicit escape hatch via
``allow_legacy_guard=True`` for migrations and compatibility tests.
"""

from __future__ import annotations

import inspect
import json
import warnings
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Iterable, Optional

from memgar.memory_guard import GuardDecision, MemoryGuard
from memgar.models import MemoryEntry
from memgar.runtime import EnforcementResult
from memgar.secure_memory_store import (
    SecureMemoryBypassError,
    SecureMemoryStore,
    SecureMemoryStorePolicy,
    SecureMemoryWriteError,
)


class MemoryOperation(str, Enum):
    """Memory operation protected by the universal adapter."""

    WRITE = "write"
    READ = "read"
    RETRIEVAL = "retrieval"
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
    memory-poisoning guard surface: wrap a writer, wrap a reader, guard tool
    output, scan retrieval results, or call guard_write/guard_read directly.
    """

    BLOCK_ACTIONS = {"block", "raise", "human_review"}
    DROP_ACTIONS = {"drop", "quarantine"}
    PASS_ACTIONS = {"warn", "allow", "log"}

    def __init__(
        self,
        guard: Optional[Any] = None,
        *,
        secure_store: Optional[SecureMemoryStore] = None,
        backend: Optional[Any] = None,
        store_policy: Optional[SecureMemoryStorePolicy] = None,
        analyzer: Optional[Any] = None,
        runtime_policy: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        dlp: Optional[Any] = None,
        dlp_policy: Optional[Any] = None,
        auditor: Optional[Any] = None,
        agent_id: str = "default",
        allow_legacy_guard: bool = False,
        on_write_threat: str = "block",
        on_read_threat: str = "drop",
        on_tool_result_threat: str = "block",
        default_source_type: str = "agent_memory",
        default_source_id: Optional[str] = None,
        **guard_kwargs: Any,
    ) -> None:
        self.on_write_threat = on_write_threat
        self.on_read_threat = on_read_threat
        self.on_tool_result_threat = on_tool_result_threat
        self.default_source_type = default_source_type
        self.default_source_id = default_source_id

        uses_legacy_guard = guard is not None or (
            guard_kwargs
            and secure_store is None
            and backend is None
            and analyzer is None
            and runtime_policy is None
            and policy_engine is None
            and dlp is None
            and dlp_policy is None
            and auditor is None
        )
        if uses_legacy_guard and not allow_legacy_guard:
            raise SecureMemoryBypassError(
                "Legacy MemoryGuard usage bypasses the SecureMemoryStore boundary. "
                "Use UniversalMemoryGuard() for secure defaults, pass secure_store=... for a "
                "preconfigured secure boundary, or set allow_legacy_guard=True for an explicit "
                "migration escape hatch."
            )
        if uses_legacy_guard:
            warnings.warn(
                "UniversalMemoryGuard is using a legacy guard without SecureMemoryStore. "
                "Memory writes will not receive SecureMemoryStore audit, DLP, vault, or raw-backend "
                "bypass controls.",
                RuntimeWarning,
                stacklevel=2,
            )
            self.secure_store: Optional[SecureMemoryStore] = None
            self._legacy_guard = guard or MemoryGuard(**guard_kwargs)
            self.guard = self._legacy_guard
            return

        if guard_kwargs:
            raise TypeError(
                "Legacy MemoryGuard kwargs cannot be mixed with SecureMemoryStore settings. "
                "Pass guard=MemoryGuard(...) with allow_legacy_guard=True for legacy behavior or "
                "pass analyzer/runtime policy settings for the secure adapter path."
            )

        self.secure_store = secure_store or SecureMemoryStore(
            backend=backend,
            analyzer=analyzer,
            runtime_policy=runtime_policy,
            policy_engine=policy_engine,
            dlp=dlp,
            dlp_policy=dlp_policy,
            auditor=auditor,
            policy=store_policy,
            agent_id=agent_id,
        )
        self._legacy_guard = None
        self.guard = self.secure_store

    @property
    def is_secure_store_backed(self) -> bool:
        """Whether this adapter is enforcing through SecureMemoryStore."""

        return self.secure_store is not None

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

    def protect_tool_result(
        self,
        tool_name: str,
        result: Any,
        **context: Any,
    ) -> MemoryProtectionResult:
        """Inspect tool/function output before an agent trusts it."""
        context.setdefault("tool_name", tool_name)
        return self._protect(
            result,
            operation=MemoryOperation.TOOL_RESULT,
            on_threat=self.on_tool_result_threat,
            **context,
        )

    def guard_write(self, content: Any, **context: Any) -> Any:
        """Return safe write content or raise MemoryBlockedError."""
        return self.protect_write(content, **context).safe_content

    def guard_read(self, content: Any, **context: Any) -> Any:
        """Return safe read content. Threats are dropped by default."""
        return self.protect_read(content, **context).safe_content

    def guard_tool_result(self, tool_name: str, result: Any, **context: Any) -> Any:
        """Return safe tool/function output or raise MemoryBlockedError."""
        return self.protect_tool_result(tool_name, result, **context).safe_content

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

    def guard_retrieval_results(
        self,
        records: Any,
        *,
        query: str = "",
        top_k: Optional[int] = None,
        **context: Any,
    ) -> Any:
        """Scan retrieval chunks before they enter model context."""
        if self.secure_store is None:
            return self.guard_read_results(records, query=query, **context)

        is_tuple = isinstance(records, tuple)
        is_list = isinstance(records, list)
        chunks = list(records) if is_tuple or is_list else [records]
        checked = self.secure_store.guard_retrieval(
            chunks,
            query=query,
            agent_id=context.get("agent_id"),
            top_k=top_k,
            include_blocked=True,
        )
        guarded: list[Any] = []
        for item in checked:
            result = self._protection_from_enforcement(
                item.enforcement,
                original=item.chunk,
                operation=MemoryOperation.RETRIEVAL,
                metadata={"query": query, "secure_store": True},
            )
            result = self._apply_threat_action(result, self.on_read_threat)
            if not result.allowed and result.safe_content in ("", None):
                continue
            guarded.append(self._replace_record_content(item.chunk, result.safe_content))

        if is_tuple:
            return tuple(guarded)
        if is_list:
            return guarded
        return guarded[0] if guarded else None

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
        if self.secure_store is None:
            return self._protect_legacy(content, operation=operation, on_threat=on_threat, **context)
        if operation == MemoryOperation.WRITE:
            return self._protect_secure_write(content, on_threat=on_threat, **context)
        if operation == MemoryOperation.TOOL_RESULT:
            return self._protect_secure_tool_result(content, on_threat=on_threat, **context)
        return self._protect_secure_read(content, operation=operation, on_threat=on_threat, **context)

    def _protect_secure_write(
        self,
        content: Any,
        *,
        on_threat: str,
        **context: Any,
    ) -> MemoryProtectionResult:
        source_type, source_id, agent_id, tenant_id, principal, metadata = self._extract_context(context)
        text = self._to_text(content)
        raw_result = None
        try:
            raw_result = self.secure_store.write(
                text,
                source_type=source_type,
                source_id=source_id,
                agent_id=agent_id,
                tenant_id=tenant_id,
                principal=principal,
                metadata={"operation": MemoryOperation.WRITE.value, **metadata},
            )
        except SecureMemoryWriteError as exc:
            raw_result = exc.result

        decision = self._decision_value(raw_result.action)
        allowed = raw_result.allowed
        safe_text = raw_result.safe_content if allowed else ""
        protected = MemoryProtectionResult(
            allowed=allowed,
            content=self._restore_content_shape(content, safe_text),
            original_content=content,
            decision=decision,
            operation=MemoryOperation.WRITE.value,
            raw_result=raw_result,
            reason=raw_result.enforcement.reason,
            warnings=self._dlp_warnings(raw_result),
            metadata={
                "source_type": source_type,
                "source_id": source_id,
                "secure_store": True,
                **raw_result.metadata,
            },
        )
        return self._apply_threat_action(protected, on_threat)

    def _protect_secure_read(
        self,
        content: Any,
        *,
        operation: MemoryOperation,
        on_threat: str,
        **context: Any,
    ) -> MemoryProtectionResult:
        source_type, source_id, agent_id, _tenant_id, _principal, metadata = self._extract_context(context)
        entry = MemoryEntry(
            content=self._to_text(content),
            source_type=source_type,
            source_id=source_id,
            metadata={"operation": operation.value, **metadata},
        )
        checked = self.secure_store.enforcer.on_memory_read(
            [entry],
            query=str(metadata.get("query", "")),
            agent_id=agent_id or self.secure_store.agent_id,
        )
        enforcement = checked[0].enforcement
        self._audit_secure_boundary(
            event="memory_read_adapter",
            action=enforcement.action.value,
            allowed=enforcement.allowed,
            boundary="memory_read",
            source_type=source_type,
            source_id=source_id,
            risk_score=enforcement.risk_score,
            was_sanitized=enforcement.was_sanitized,
            reason=enforcement.reason,
        )
        protected = self._protection_from_enforcement(
            enforcement,
            original=content,
            operation=operation,
            metadata={"source_type": source_type, "source_id": source_id, "secure_store": True},
        )
        return self._apply_threat_action(protected, on_threat)

    def _protect_secure_tool_result(
        self,
        content: Any,
        *,
        on_threat: str,
        **context: Any,
    ) -> MemoryProtectionResult:
        tool_name = str(context.pop("tool_name", context.pop("source_id", "tool")))
        agent_id = context.pop("agent_id", None)
        enforcement = self.secure_store.guard_tool_result(
            tool_name,
            content,
            agent_id=agent_id,
            raise_on_block=False,
        )
        protected = self._protection_from_enforcement(
            enforcement,
            original=content,
            operation=MemoryOperation.TOOL_RESULT,
            metadata={"tool_name": tool_name, "secure_store": True, **context},
        )
        return self._apply_threat_action(protected, on_threat)

    def _protect_legacy(
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
        raw_result = self._legacy_guard.process(
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
            metadata={"source_type": source_type, "source_id": source_id, "legacy_guard": True},
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

    def _protection_from_enforcement(
        self,
        enforcement: EnforcementResult,
        *,
        original: Any,
        operation: MemoryOperation,
        metadata: Optional[dict[str, Any]] = None,
    ) -> MemoryProtectionResult:
        decision = self._decision_value(enforcement.action)
        safe_text = enforcement.safe_content if enforcement.allowed else ""
        return MemoryProtectionResult(
            allowed=enforcement.allowed,
            content=self._restore_content_shape(original, safe_text),
            original_content=original,
            decision=decision,
            operation=operation.value,
            raw_result=enforcement,
            reason=enforcement.reason,
            warnings=[],
            metadata=metadata or {},
        )

    def _extract_context(
        self,
        context: dict[str, Any],
    ) -> tuple[str, Optional[str], Optional[str], str, str, dict[str, Any]]:
        source_type = context.pop("source_type", self.default_source_type)
        source_id = context.pop("source_id", self.default_source_id)
        agent_id = context.pop("agent_id", None)
        tenant_id = str(context.pop("tenant_id", ""))
        principal = str(context.pop("principal", ""))
        user_metadata = dict(context.pop("metadata", {}) or {})
        user_metadata.update(context)
        return source_type, source_id, agent_id, tenant_id, principal, user_metadata

    def _audit_secure_boundary(self, **payload: Any) -> None:
        audit = getattr(self.secure_store, "_log_boundary_audit", None)
        if callable(audit):
            audit(**payload)

    @staticmethod
    def _dlp_warnings(raw_result: Any) -> list[str]:
        findings = list(getattr(getattr(raw_result, "dlp", None), "findings", []) or [])
        if not findings:
            return []
        labels = sorted({str(getattr(item, "label", "unknown")) for item in findings})
        return [f"DLP redacted: {', '.join(labels)}"]

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
    def _replace_record_content(record: Any, safe_content: Any) -> Any:
        if isinstance(record, str):
            return safe_content
        if isinstance(record, dict) and "content" in record:
            updated = dict(record)
            updated["content"] = safe_content
            return updated
        return record

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
