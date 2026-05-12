"""
Memgar LangChain Integration
============================

Memory firewall middleware for LangChain applications.

The wrapper treats memory writes and memory reads as untrusted data flow. Writes
are routed through UniversalMemoryGuard/SecureMemoryStore before persistence;
reads are scanned again before historical memory can re-enter prompt context.
"""

from __future__ import annotations

import copy
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..models import Decision
from ..scanner import MemoryScanner
from .universal import MemoryBlockedError, MemoryProtectionResult, UniversalMemoryGuard

logger = logging.getLogger(__name__)
_DROP = object()
_TEXT_KEYS = ("content", "page_content", "text")
_TEXT_ATTRS = ("content", "page_content", "text")


@dataclass
class ScanResult:
    """Result of memory scan."""

    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    original_content: str = ""
    safe_content: Optional[str] = None
    boundary: str = "memory"


class MemgarMemoryGuard:
    """Security wrapper for LangChain memory classes.

    This class is intentionally compatible with LangChain memory objects such as
    ConversationBufferMemory. It delegates unknown attributes to the wrapped
    memory object while enforcing Memgar on these official boundaries:

    - save_context/asave_context: memory write
    - add_memory: memory write
    - load_memory_variables/aload_memory_variables: memory read

    Direct access to the wrapped raw memory object can still bypass Memgar, so
    applications should pass this wrapper to chains instead of the raw memory.
    """

    def __init__(
        self,
        memory: Any,
        mode: str = "protect",
        on_threat: str = "block",
        on_read_threat: str = "drop",
        callback: Optional[Callable[[ScanResult], None]] = None,
        scan_reads: bool = True,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        agent_id: str = "langchain",
        **guard_kwargs: Any,
    ):
        """
        Initialize memory guard.

        Args:
            memory: LangChain memory instance to wrap.
            mode: Kept for callback-handler compatibility with the older scanner API.
            on_threat: Action for unsafe memory writes: block, warn, log, or allow.
            on_read_threat: Action for unsafe memory reads: drop by default.
            callback: Optional callback function receiving ScanResult.
            scan_reads: Scan load_memory_variables output before it reaches context.
            memory_guard: Optional preconfigured UniversalMemoryGuard.
            secure_store: Optional preconfigured SecureMemoryStore.
            agent_id: Agent identifier for audit events.
            **guard_kwargs: Forwarded to UniversalMemoryGuard.
        """
        self._memory = memory
        self._mode = mode
        self._on_threat = on_threat
        self._on_read_threat = on_read_threat
        self._callback = callback
        self._scan_reads = scan_reads
        self._blocked_count = 0
        self._scanned_count = 0
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            agent_id=agent_id,
            on_write_threat=on_threat,
            on_read_threat=on_read_threat,
            on_tool_result_threat=on_threat,
            default_source_type="langchain_memory",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        """Return the secure memory boundary used by this adapter."""

        return self._memory_guard

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to wrapped memory."""

        return getattr(self._memory, name)

    def _scan_content(self, content: str, *, boundary: str, source_id: str = "") -> ScanResult:
        """Scan content through the secure memory boundary."""

        self._scanned_count += 1
        try:
            if boundary == "read":
                protected = self._memory_guard.protect_read(
                    content,
                    source_type="langchain_memory:read",
                    source_id=source_id,
                )
            else:
                protected = self._memory_guard.protect_write(
                    content,
                    source_type="langchain_memory:write",
                    source_id=source_id,
                )
        except MemoryBlockedError as exc:
            scan_result = self._scan_result_from_protection(content, exc.result, boundary)
            self._handle_threat(scan_result, content)
            return scan_result

        scan_result = self._scan_result_from_protection(content, protected, boundary)
        if not scan_result.allowed:
            self._record_threat(scan_result)
        if self._callback:
            self._callback(scan_result)
        return scan_result

    def _handle_threat(self, scan_result: ScanResult, content: str) -> str:
        """Handle detected threat based on configuration."""

        self._record_threat(scan_result)
        action = self._on_read_threat if scan_result.boundary == "read" else self._on_threat
        if action == "block":
            raise MemgarThreatError(
                f"Memory poisoning attempt blocked: {scan_result.threat_type}",
                scan_result=scan_result,
            )
        if action == "warn":
            logger.warning("Memgar: allowing with warning - %s...", content[:50])
            return content
        logger.info("Memgar: logged threat - %s", scan_result.threat_type)
        return content

    def _record_threat(self, scan_result: ScanResult) -> None:
        self._blocked_count += 1
        logger.warning(
            "Memgar: threat detected at %s - %s (risk: %s)",
            scan_result.boundary,
            scan_result.threat_type,
            scan_result.risk_score,
        )

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]) -> None:
        """Scan and save context to memory."""

        safe_inputs = self._guard_mapping_for_write(inputs, prefix="input")
        safe_outputs = self._guard_mapping_for_write(outputs, prefix="output")
        self._memory.save_context(safe_inputs, safe_outputs)

    async def asave_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]) -> None:
        """Async version of save_context for LangChain async memory classes."""

        safe_inputs = self._guard_mapping_for_write(inputs, prefix="input")
        safe_outputs = self._guard_mapping_for_write(outputs, prefix="output")
        saver = getattr(self._memory, "asave_context", None)
        if saver is None:
            self._memory.save_context(safe_inputs, safe_outputs)
            return
        result = saver(safe_inputs, safe_outputs)
        if inspect.isawaitable(result):
            await result

    def add_memory(self, content: str, **kwargs: Any) -> None:
        """Scan and add a single memory entry."""

        safe_content = self._guard_write_value(content, source_id="add_memory")
        if safe_content is _DROP or safe_content in (None, ""):
            return

        if hasattr(self._memory, "add_memory"):
            self._memory.add_memory(safe_content, **kwargs)
        elif hasattr(self._memory, "chat_memory"):
            from langchain.schema import HumanMessage

            self._memory.chat_memory.add_message(HumanMessage(content=safe_content))

    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Load memory variables and scan them before they enter prompt context."""

        variables = self._memory.load_memory_variables(inputs)
        if not self._scan_reads:
            return variables
        return self._guard_mapping_for_read(variables, prefix="memory")

    async def aload_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Async version of load_memory_variables."""

        loader = getattr(self._memory, "aload_memory_variables", None)
        if loader is None:
            return self.load_memory_variables(inputs)
        variables = loader(inputs)
        if inspect.isawaitable(variables):
            variables = await variables
        if not self._scan_reads:
            return variables
        return self._guard_mapping_for_read(variables, prefix="memory")

    def guard_retrieval_results(
        self,
        records: Any,
        *,
        query: str = "",
        top_k: Optional[int] = None,
        **context: Any,
    ) -> Any:
        """Scan arbitrary LangChain retrieval output before model context."""

        return self._memory_guard.guard_retrieval_results(
            records,
            query=query,
            top_k=top_k,
            source_type="langchain_retrieval",
            **context,
        )

    def clear(self) -> None:
        """Clear memory."""

        self._memory.clear()

    @property
    def stats(self) -> Dict[str, int]:
        """Get scanning statistics."""

        return {
            "scanned": self._scanned_count,
            "blocked": self._blocked_count,
        }

    def _guard_mapping_for_write(self, values: Dict[str, Any], *, prefix: str) -> Dict[str, Any]:
        return {
            key: self._guard_write_value(value, source_id=f"{prefix}.{key}")
            for key, value in values.items()
        }

    def _guard_mapping_for_read(self, values: Dict[str, Any], *, prefix: str) -> Dict[str, Any]:
        safe: Dict[str, Any] = {}
        for key, value in values.items():
            guarded = self._guard_read_value(value, source_id=f"{prefix}.{key}", drop_blocked=False)
            safe[key] = "" if guarded is _DROP else guarded
        return safe

    def _guard_write_value(self, value: Any, *, source_id: str) -> Any:
        if isinstance(value, str):
            return self._scan_content(value, boundary="write", source_id=source_id).safe_content or ""
        if isinstance(value, dict):
            return {k: self._guard_write_value(v, source_id=f"{source_id}.{k}") for k, v in value.items()}
        if isinstance(value, list):
            return [self._guard_write_value(v, source_id=f"{source_id}[]") for v in value]
        if isinstance(value, tuple):
            return tuple(self._guard_write_value(v, source_id=f"{source_id}[]") for v in value)
        return value

    def _guard_read_value(self, value: Any, *, source_id: str, drop_blocked: bool) -> Any:
        if isinstance(value, str):
            result = self._scan_content(value, boundary="read", source_id=source_id)
            if not result.allowed and result.safe_content in (None, ""):
                return _DROP if drop_blocked else ""
            return result.safe_content if result.safe_content is not None else value

        if isinstance(value, dict):
            content_key = next((key for key in _TEXT_KEYS if isinstance(value.get(key), str)), None)
            if content_key:
                guarded_content = self._guard_read_value(
                    value[content_key],
                    source_id=f"{source_id}.{content_key}",
                    drop_blocked=drop_blocked,
                )
                if guarded_content is _DROP:
                    return _DROP
                updated = dict(value)
                updated[content_key] = guarded_content
                return updated
            return {
                key: ("" if (guarded := self._guard_read_value(
                    item,
                    source_id=f"{source_id}.{key}",
                    drop_blocked=False,
                )) is _DROP else guarded)
                for key, item in value.items()
            }

        if isinstance(value, list):
            guarded_items = [
                self._guard_read_value(item, source_id=f"{source_id}[]", drop_blocked=True)
                for item in value
            ]
            return [item for item in guarded_items if item is not _DROP]

        if isinstance(value, tuple):
            guarded_items = [
                self._guard_read_value(item, source_id=f"{source_id}[]", drop_blocked=True)
                for item in value
            ]
            return tuple(item for item in guarded_items if item is not _DROP)

        attr = _text_attr(value)
        if attr:
            text = getattr(value, attr)
            guarded_text = self._guard_read_value(
                text,
                source_id=f"{source_id}.{attr}",
                drop_blocked=drop_blocked,
            )
            if guarded_text is _DROP:
                return _DROP
            return _replace_text_attr(value, attr, guarded_text)

        return value

    @staticmethod
    def _scan_result_from_protection(
        original_content: str,
        protected: MemoryProtectionResult,
        boundary: str,
    ) -> ScanResult:
        return ScanResult(
            allowed=protected.allowed,
            decision=protected.decision,
            risk_score=_risk_score(protected.raw_result),
            threat_type=protected.reason or protected.decision,
            original_content=original_content[:100],
            safe_content=str(protected.safe_content) if protected.safe_content is not None else None,
            boundary=boundary,
        )


class SecureConversationChain:
    """Small wrapper that installs MemgarMemoryGuard on an existing chain."""

    def __init__(self, chain: Any, memory: Optional[Any] = None, **guard_kwargs: Any) -> None:
        self._chain = chain
        raw_memory = memory if memory is not None else getattr(chain, "memory", None)
        self.memory = guard_memory(raw_memory, **guard_kwargs) if raw_memory is not None else None
        if self.memory is not None:
            try:
                setattr(chain, "memory", self.memory)
            except Exception:
                logger.debug("Memgar: unable to attach guarded memory to LangChain chain")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chain, name)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        return self._chain.invoke(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._chain.run(*args, **kwargs)


class MemgarCallbackHandler:
    """LangChain callback handler for Memgar."""

    def __init__(
        self,
        mode: str = "protect",
        on_threat: str = "block",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
    ):
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._scan_inputs = scan_inputs
        self._scan_outputs = scan_outputs
        self._threats: List[ScanResult] = []

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Scan prompts before LLM call."""

        if not self._scan_inputs:
            return

        for prompt in prompts:
            result = self._scanner.scan(prompt)
            if result.decision != Decision.ALLOW:
                scan_result = ScanResult(
                    allowed=False,
                    decision=result.decision.value,
                    risk_score=result.risk_score,
                    threat_type=result.threat_type,
                    original_content=prompt[:100],
                    boundary="llm_input",
                )
                self._threats.append(scan_result)
                if self._on_threat == "block":
                    raise MemgarThreatError(
                        f"Input threat blocked: {result.threat_type}",
                        scan_result=scan_result,
                    )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Scan LLM output."""

        if not self._scan_outputs:
            return

        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    text = gen.text if hasattr(gen, "text") else str(gen)
                    result = self._scanner.scan(text)
                    if result.decision != Decision.ALLOW:
                        logger.warning("Memgar: output threat detected - %s", result.threat_type)

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Scan chain inputs."""

        if not self._scan_inputs:
            return

        for value in inputs.values():
            if isinstance(value, str):
                result = self._scanner.scan(value)
                if result.decision != Decision.ALLOW:
                    logger.warning("Memgar: chain input threat - %s", result.threat_type)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Scan tool inputs."""

        if not self._scan_inputs:
            return

        result = self._scanner.scan(input_str)
        if result.decision != Decision.ALLOW and self._on_threat == "block":
            raise MemgarThreatError(f"Tool input blocked: {result.threat_type}")

    @property
    def detected_threats(self) -> List[ScanResult]:
        """Get list of detected threats."""

        return self._threats.copy()

    def clear_threats(self) -> None:
        """Clear threat history."""

        self._threats.clear()


class MemgarThreatError(Exception):
    """Exception raised when a threat is detected and blocked."""

    def __init__(self, message: str, scan_result: Optional[ScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


def guard_memory(memory: Any, **kwargs: Any) -> MemgarMemoryGuard:
    """Quick wrapper to guard a LangChain memory."""

    return MemgarMemoryGuard(memory, **kwargs)


def _risk_score(raw_result: Any) -> int:
    if hasattr(raw_result, "risk_score"):
        return int(getattr(raw_result, "risk_score", 0) or 0)
    enforcement = getattr(raw_result, "enforcement", raw_result)
    return int(getattr(enforcement, "risk_score", 0) or 0)


def _text_attr(value: Any) -> Optional[str]:
    for attr in _TEXT_ATTRS:
        if isinstance(getattr(value, attr, None), str):
            return attr
    return None


def _replace_text_attr(value: Any, attr: str, safe_text: str) -> Any:
    if hasattr(value, "model_copy"):
        try:
            return value.model_copy(update={attr: safe_text})
        except Exception:
            pass
    if hasattr(value, "copy"):
        try:
            return value.copy(update={attr: safe_text})
        except TypeError:
            pass
        except Exception:
            pass
    try:
        cloned = copy.copy(value)
        setattr(cloned, attr, safe_text)
        return cloned
    except Exception:
        logger.debug("Memgar: unable to clone LangChain object for sanitized memory read")
    return safe_text
