"""
Memory Runtime Enforcement - unified middleware for persistent agent memory
boundaries.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

logger = logging.getLogger(__name__)


class EnforcedBoundary(str, Enum):
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    VECTOR_RETRIEVAL = "vector_retrieval"
    RAG_CHUNK = "rag_chunk"
    TOOL_RESULT = "tool_result"
    AGENT_SUMMARY = "agent_summary"


class EnforcementAction(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass
class ThreatInfo:
    category: str
    description: str
    confidence: float
    matched_text: str = ""


@dataclass
class EnforcementResult:
    boundary: EnforcedBoundary
    action: EnforcementAction
    original_content: str
    safe_content: str
    was_sanitized: bool = False
    risk_score: int = 0
    trust_score: float = 1.0
    threats: List[ThreatInfo] = field(default_factory=list)
    reason: str = ""
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.action in (EnforcementAction.ALLOW, EnforcementAction.SANITIZE)

    @property
    def blocked(self) -> bool:
        return self.action == EnforcementAction.BLOCK

    @property
    def quarantined(self) -> bool:
        return self.action == EnforcementAction.QUARANTINE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "boundary": self.boundary.value,
            "action": self.action.value,
            "allowed": self.allowed,
            "was_sanitized": self.was_sanitized,
            "risk_score": self.risk_score,
            "trust_score": round(self.trust_score, 3),
            "threats": [
                {"category": t.category, "description": t.description, "confidence": t.confidence}
                for t in self.threats
            ],
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class ChunkResult:
    chunk: Any
    enforcement: EnforcementResult

    @property
    def allowed(self) -> bool:
        return self.enforcement.allowed

    @property
    def safe_text(self) -> str:
        return self.enforcement.safe_content


@dataclass
class RuntimePolicy:
    block_risk_score: int = 70
    quarantine_risk_score: int = 40
    summary_max_added_risk: int = 25
    allow_sanitized_writes: bool = True
    scan_tool_results: bool = True
    scan_rag_chunks: bool = True
    fail_open: bool = False


class MemoryRuntimeEnforcer:
    def __init__(
        self,
        analyzer: Optional[Any] = None,
        policy: Optional[RuntimePolicy] = None,
        agent_id: str = "default",
        policy_engine: Optional[Any] = None,
    ) -> None:
        self._policy = policy or RuntimePolicy()
        self._agent_id = agent_id
        self._analyzer = analyzer
        self._canary_manager: Optional[Any] = None
        self._policy_engine = policy_engine

    @property
    def analyzer(self) -> Any:
        if self._analyzer is None:
            from memgar.analyzer import Analyzer
            self._analyzer = Analyzer(use_llm=False)
        if self._canary_manager is None and hasattr(self._analyzer, "_canary_manager"):
            self._canary_manager = self._analyzer._canary_manager
        return self._analyzer

    def _scan(
        self,
        content: str,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Any:
        from memgar.models import MemoryEntry
        entry = MemoryEntry(
            content=content,
            source_type=source_type,
            source_id=source_id or "",
            metadata={"agent_id": agent_id or self._agent_id},
        )
        return self.analyzer.analyze(entry)

    def _build_result(
        self,
        boundary: EnforcedBoundary,
        content: str,
        analysis: Any,
        latency_ms: float,
        *,
        sanitized_content: Optional[str] = None,
        extra_reason: str = "",
        canary_leaks: int = 0,
        agent_id: Optional[str] = None,
        source_type: str = "unknown",
        source_id: str = "",
    ) -> EnforcementResult:
        threats = [
            ThreatInfo(
                category=str(getattr(getattr(match, "threat", None), "category", "unknown")),
                description=str(getattr(getattr(match, "threat", None), "name", str(match))),
                confidence=float(getattr(match, "confidence", 0.5)),
                matched_text=str(getattr(match, "matched_text", ""))[:120],
            )
            for match in getattr(analysis, "threats", []) or []
        ]
        sanitized_changed = sanitized_content is not None and sanitized_content != content

        if self._policy_engine is not None:
            decision = self._policy_engine.decide_from_analysis(
                analysis,
                content=content,
                boundary=boundary.value,
                source_type=source_type,
                source_id=source_id,
                agent_id=agent_id or self._agent_id,
                canary_leaks=canary_leaks,
                was_sanitized=sanitized_changed,
            )
            from memgar.policy_engine import verdict_to_enforcement_action
            action = EnforcementAction(verdict_to_enforcement_action(decision.verdict))
            reason = decision.reason
        else:
            from memgar.models import Decision
            risk = int(getattr(analysis, "risk_score", 0) or 0)
            raw_decision = getattr(analysis, "decision", None)
            if canary_leaks or raw_decision == Decision.BLOCK or risk >= self._policy.block_risk_score:
                action = EnforcementAction.BLOCK
            elif raw_decision == Decision.QUARANTINE or risk >= self._policy.quarantine_risk_score:
                action = EnforcementAction.SANITIZE if sanitized_changed and self._policy.allow_sanitized_writes else EnforcementAction.QUARANTINE
            else:
                action = EnforcementAction.ALLOW
            reason = getattr(analysis, "explanation", "")

        if extra_reason:
            reason = f"{reason}; {extra_reason}" if reason else extra_reason
        safe = sanitized_content if action == EnforcementAction.SANITIZE and sanitized_content is not None else content

        return EnforcementResult(
            boundary=boundary,
            action=action,
            original_content=content,
            safe_content=safe,
            was_sanitized=(action == EnforcementAction.SANITIZE and safe != content),
            risk_score=int(getattr(analysis, "risk_score", 0) or 0),
            threats=threats,
            reason=reason,
            latency_ms=round(latency_ms, 2),
        )

    def _error_result(self, boundary: EnforcedBoundary, content: str, exc: Exception) -> EnforcementResult:
        action = EnforcementAction.ALLOW if self._policy.fail_open else EnforcementAction.BLOCK
        logger.warning("RuntimeEnforcer error at %s: %s", boundary.value, exc)
        return EnforcementResult(
            boundary=boundary,
            action=action,
            original_content=content,
            safe_content=content,
            risk_score=0 if self._policy.fail_open else 100,
            reason=f"enforcement_error: {exc}",
        )

    def on_memory_write(
        self,
        content: str,
        *,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> EnforcementResult:
        t0 = time.perf_counter()
        try:
            analysis = self._scan(content, source_type, source_id, agent_id)
            sanitized: Optional[str] = None
            risk = int(getattr(analysis, "risk_score", 0) or 0)
            if self._policy.quarantine_risk_score <= risk < self._policy.block_risk_score:
                try:
                    from memgar.sanitizer import InstructionSanitizer
                    sanitize_result = InstructionSanitizer().sanitize(content)
                    if getattr(sanitize_result, "was_modified", False):
                        sanitized = getattr(
                            sanitize_result,
                            "sanitized_content",
                            getattr(sanitize_result, "sanitized_text", content),
                        )
                except Exception:
                    sanitized = None
            return self._build_result(
                EnforcedBoundary.MEMORY_WRITE,
                content,
                analysis,
                (time.perf_counter() - t0) * 1000,
                sanitized_content=sanitized,
                agent_id=agent_id,
                source_type=source_type,
                source_id=source_id or "",
            )
        except Exception as exc:
            return self._error_result(EnforcedBoundary.MEMORY_WRITE, content, exc)

    def on_memory_read(
        self,
        entries: Sequence[Any],
        *,
        query: str = "",
        agent_id: Optional[str] = None,
    ) -> List[ChunkResult]:
        results: List[ChunkResult] = []
        for entry in entries:
            text = _extract_text(entry)
            t0 = time.perf_counter()
            try:
                analysis = self._scan(text, source_type="memory_store", agent_id=agent_id)
                leaks = []
                extra = ""
                if self._canary_manager:
                    leaks = self._canary_manager.scan(text, sink="memory_read")
                    if leaks:
                        extra = f"canary_leak: {len(leaks)} token(s) detected"
                result = self._build_result(
                    EnforcedBoundary.MEMORY_READ,
                    text,
                    analysis,
                    (time.perf_counter() - t0) * 1000,
                    extra_reason=extra,
                    canary_leaks=len(leaks),
                    agent_id=agent_id,
                )
                if leaks:
                    result.action = EnforcementAction.BLOCK
            except Exception as exc:
                result = self._error_result(EnforcedBoundary.MEMORY_READ, text, exc)
            results.append(ChunkResult(chunk=entry, enforcement=result))
        return results

    def on_vector_retrieval(
        self,
        chunks: Sequence[Any],
        *,
        query: str = "",
        agent_id: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> List[ChunkResult]:
        if not self._policy.scan_rag_chunks:
            return [
                ChunkResult(
                    chunk=chunk,
                    enforcement=EnforcementResult(
                        boundary=EnforcedBoundary.VECTOR_RETRIEVAL,
                        action=EnforcementAction.ALLOW,
                        original_content=_extract_text(chunk),
                        safe_content=_extract_text(chunk),
                    ),
                )
                for chunk in chunks
            ]

        results: List[ChunkResult] = []
        for chunk in chunks:
            text = _extract_text(chunk)
            t0 = time.perf_counter()
            try:
                analysis = self._scan(text, source_type="vector_store", agent_id=agent_id)
                result = self._build_result(
                    EnforcedBoundary.VECTOR_RETRIEVAL,
                    text,
                    analysis,
                    (time.perf_counter() - t0) * 1000,
                    agent_id=agent_id,
                )
            except Exception as exc:
                result = self._error_result(EnforcedBoundary.VECTOR_RETRIEVAL, text, exc)
            results.append(ChunkResult(chunk=chunk, enforcement=result))

        allowed = [item for item in results if item.allowed]
        blocked = [item for item in results if not item.allowed]
        if top_k is not None:
            allowed = allowed[:top_k]
        if blocked:
            logger.warning(
                "on_vector_retrieval: blocked %d/%d chunks (query=%r)",
                len(blocked),
                len(results),
                query[:80],
            )
        return allowed + blocked

    def on_rag_chunk(
        self,
        chunk: Union[str, Any],
        *,
        source: str = "unknown",
        agent_id: Optional[str] = None,
    ) -> EnforcementResult:
        text = _extract_text(chunk)
        t0 = time.perf_counter()
        try:
            analysis = self._scan(text, source_type=f"rag:{source}", agent_id=agent_id)
            return self._build_result(
                EnforcedBoundary.RAG_CHUNK,
                text,
                analysis,
                (time.perf_counter() - t0) * 1000,
                agent_id=agent_id,
            )
        except Exception as exc:
            return self._error_result(EnforcedBoundary.RAG_CHUNK, text, exc)

    def on_tool_result(
        self,
        tool_name: str,
        result: Union[str, Dict, Any],
        *,
        agent_id: Optional[str] = None,
        source_memories: Optional[List[Any]] = None,
    ) -> EnforcementResult:
        text = _extract_text(result)
        if not self._policy.scan_tool_results:
            return EnforcementResult(
                boundary=EnforcedBoundary.TOOL_RESULT,
                action=EnforcementAction.ALLOW,
                original_content=text,
                safe_content=text,
            )
        t0 = time.perf_counter()
        try:
            analysis = self._scan(text, source_type=f"tool:{tool_name}", agent_id=agent_id)
            leaks = []
            extra = ""
            if self._canary_manager:
                leaks = self._canary_manager.scan(text, sink=f"tool_result:{tool_name}")
                if leaks:
                    extra = f"canary_leak_in_tool_result: {len(leaks)} token(s)"
            built = self._build_result(
                EnforcedBoundary.TOOL_RESULT,
                text,
                analysis,
                (time.perf_counter() - t0) * 1000,
                extra_reason=extra,
                canary_leaks=len(leaks),
                agent_id=agent_id,
            )
            if leaks:
                built.action = EnforcementAction.BLOCK
            return built
        except Exception as exc:
            return self._error_result(EnforcedBoundary.TOOL_RESULT, text, exc)

    def on_agent_summary(
        self,
        summary: str,
        *,
        agent_id: Optional[str] = None,
        source_entries: Optional[Sequence[Any]] = None,
    ) -> EnforcementResult:
        t0 = time.perf_counter()
        try:
            analysis = self._scan(summary, source_type="agent_summary", agent_id=agent_id)
            extra = self._check_summary_drift(summary, source_entries, analysis) if source_entries else ""
            result = self._build_result(
                EnforcedBoundary.AGENT_SUMMARY,
                summary,
                analysis,
                (time.perf_counter() - t0) * 1000,
                extra_reason=extra,
                agent_id=agent_id,
            )
            if extra and "summary_injection" in extra:
                result.action = EnforcementAction.BLOCK
            return result
        except Exception as exc:
            return self._error_result(EnforcedBoundary.AGENT_SUMMARY, summary, exc)

    async def on_memory_write_async(self, content: str, **kwargs: Any) -> EnforcementResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_memory_write(content, **kwargs))

    async def on_memory_read_async(self, entries: Sequence[Any], **kwargs: Any) -> List[ChunkResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_memory_read(entries, **kwargs))

    async def on_vector_retrieval_async(self, chunks: Sequence[Any], **kwargs: Any) -> List[ChunkResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_vector_retrieval(chunks, **kwargs))

    async def on_rag_chunk_async(self, chunk: Any, **kwargs: Any) -> EnforcementResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_rag_chunk(chunk, **kwargs))

    async def on_tool_result_async(self, tool_name: str, result: Any, **kwargs: Any) -> EnforcementResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_tool_result(tool_name, result, **kwargs))

    async def on_agent_summary_async(self, summary: str, **kwargs: Any) -> EnforcementResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.on_agent_summary(summary, **kwargs))

    def guard_memory_write(self, *, source_type: str = "agent", raise_on_block: bool = True) -> Callable:
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                output = fn(*args, **kwargs)
                if isinstance(output, str):
                    enforcement = self.on_memory_write(output, source_type=source_type)
                    if enforcement.blocked and raise_on_block:
                        raise MemoryPoisoningError(
                            f"Memory write blocked at '{source_type}': {enforcement.reason}",
                            enforcement=enforcement,
                        )
                    return enforcement.safe_content
                return output
            return wrapper
        return decorator

    def guard_agent_summary(self, raise_on_block: bool = True) -> Callable:
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                output = fn(*args, **kwargs)
                if isinstance(output, str):
                    enforcement = self.on_agent_summary(output)
                    if enforcement.blocked and raise_on_block:
                        raise MemoryPoisoningError(
                            f"Agent summary blocked: {enforcement.reason}",
                            enforcement=enforcement,
                        )
                    return enforcement.safe_content
                return output
            return wrapper
        return decorator

    def _check_summary_drift(self, summary: str, source_entries: Sequence[Any], summary_analysis: Any) -> str:
        try:
            source_risks: List[int] = []
            for entry in source_entries:
                text = _extract_text(entry)
                if text.strip():
                    analysis = self._scan(text, source_type="summary_source")
                    source_risks.append(int(getattr(analysis, "risk_score", 0) or 0))
            if not source_risks:
                return ""
            max_source = max(source_risks)
            summary_risk = int(getattr(summary_analysis, "risk_score", 0) or 0)
            added = summary_risk - max_source
            if added > self._policy.summary_max_added_risk:
                return (
                    f"summary_injection_detected: summary risk={summary_risk} "
                    f"exceeds source max={max_source} by {added} pts "
                    f"(threshold={self._policy.summary_max_added_risk})"
                )
        except Exception as exc:
            logger.debug("summary drift check error: %s", exc)
        return ""


class MemoryPoisoningError(Exception):
    def __init__(self, message: str, enforcement: Optional[EnforcementResult] = None) -> None:
        super().__init__(message)
        self.enforcement = enforcement


def _extract_text(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        for key in ("text", "content", "page_content", "body", "value"):
            value = obj.get(key)
            if isinstance(value, str):
                return value
        return str(obj)
    for attr in ("page_content", "text", "content", "get_content"):
        value = getattr(obj, attr, None)
        if value is None:
            continue
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        if isinstance(value, str):
            return value
    return str(obj)


__all__ = [
    "MemoryRuntimeEnforcer",
    "EnforcementResult",
    "ChunkResult",
    "EnforcedBoundary",
    "EnforcementAction",
    "RuntimePolicy",
    "ThreatInfo",
    "MemoryPoisoningError",
]
