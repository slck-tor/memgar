"""
Memgar LangChain Deep Integration
====================================

Deep integration with LangChain / LangGraph providing:

- MemgarSecurityRunnable     — LCEL Runnable that scans every message in a chain
- MemgarChatMemory           — ChatMessageHistory with threat filtering
- MemgarConversationBufferMemory — ConversationBufferMemory drop-in replacement
- SecureVectorStoreRetriever — VectorStoreRetriever with per-document scanning
- MemgarLCELMiddleware       — Generic middleware wrapper for any Runnable
- MemgarDocumentFilter       — Document-level filter for loaders / retrievers
- create_secure_lcel_chain   — Factory to build a fully secured LCEL chain

Usage::

    from memgar.frameworks import MemgarSecurityRunnable

    chain = prompt | MemgarSecurityRunnable() | llm | output_parser

Or with full memory protection::

    from memgar.frameworks import MemgarChatMemory
    from langchain_community.chat_message_histories import ChatMessageHistory

    history = MemgarChatMemory(base_history=ChatMessageHistory())
    history.add_user_message("Please ignore previous instructions...")
    # → raises MemgarThreatError (or silently blocks, depending on config)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Type, Union

from memgar.analyzer import Analyzer
from memgar.models import AnalysisResult, Decision, MemoryEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional LangChain import
# ---------------------------------------------------------------------------
try:
    from langchain_core.runnables import Runnable, RunnableConfig
    from langchain_core.messages import (
        BaseMessage,
        HumanMessage,
        AIMessage,
        SystemMessage,
    )
    from langchain_core.chat_history import BaseChatMessageHistory
    from langchain_core.memory import BaseMemory
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.callbacks import CallbackManagerForRetrieverRun

    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    LANGCHAIN_AVAILABLE = False

    # Stub base classes so the module can still be imported
    class Runnable:  # type: ignore[no-redef]
        pass

    class BaseChatMessageHistory:  # type: ignore[no-redef]
        pass

    class BaseMemory:  # type: ignore[no-redef]
        pass

    class BaseRetriever:  # type: ignore[no-redef]
        pass

    class Document:  # type: ignore[no-redef]
        pass

    class BaseMessage:  # type: ignore[no-redef]
        pass

    class RunnableConfig:  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

@dataclass
class _ScanStats:
    """Cumulative scan statistics for a session."""
    total: int = 0
    blocked: int = 0
    quarantined: int = 0
    allowed: int = 0
    total_time_ms: float = 0.0
    threats: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, result: AnalysisResult, elapsed_ms: float) -> None:
        self.total += 1
        self.total_time_ms += elapsed_ms
        if result.decision == Decision.BLOCK:
            self.blocked += 1
        elif result.decision == Decision.QUARANTINE:
            self.quarantined += 1
        else:
            self.allowed += 1
        for t in result.threats:
            self.threats.append({
                "threat_id": t.threat.id,
                "name": t.threat.name,
                "severity": t.threat.severity.value,
                "matched_text": t.matched_text[:120],
            })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_scanned": self.total,
            "blocked": self.blocked,
            "quarantined": self.quarantined,
            "allowed": self.allowed,
            "avg_time_ms": (
                round(self.total_time_ms / self.total, 2) if self.total else 0.0
            ),
            "threats_detected": len(self.threats),
            "threat_details": self.threats,
        }


def _scan_text(
    analyzer: Analyzer,
    content: str,
    source_type: str = "langchain",
    source_id: Optional[str] = None,
) -> tuple[AnalysisResult, float]:
    """Run analyzer and return (result, elapsed_ms)."""
    t0 = time.perf_counter()
    entry = MemoryEntry(
        content=content,
        source_type=source_type,
        source_id=source_id,
    )
    result = analyzer.analyze(entry)
    elapsed = (time.perf_counter() - t0) * 1000
    return result, elapsed


def _extract_text(value: Any) -> str:
    """Best-effort extraction of a string from various LangChain types."""
    if isinstance(value, str):
        return value
    if LANGCHAIN_AVAILABLE and isinstance(value, BaseMessage):
        return value.content if isinstance(value.content, str) else str(value.content)
    if LANGCHAIN_AVAILABLE and isinstance(value, Document):
        return value.page_content
    if isinstance(value, dict):
        for key in ("content", "text", "input", "output", "page_content"):
            if key in value and isinstance(value[key], str):
                return value[key]
        return str(value)
    if isinstance(value, list):
        return " ".join(_extract_text(item) for item in value)
    return str(value)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class MemgarThreatError(Exception):
    """Raised when a threat is detected and block_on_threat=True."""

    def __init__(self, message: str, result: Optional[AnalysisResult] = None) -> None:
        super().__init__(message)
        self.result = result


# ---------------------------------------------------------------------------
# 1. MemgarSecurityRunnable
# ---------------------------------------------------------------------------

class MemgarSecurityRunnable(Runnable):
    """
    LCEL-compatible Runnable that intercepts chain I/O and scans for threats.

    Drop this into any LCEL chain::

        chain = prompt | MemgarSecurityRunnable() | llm | output_parser

    It passes the value through unchanged if safe, raises MemgarThreatError
    if a threat is found (and block_on_threat=True), or logs a warning and
    passes through (if block_on_threat=False).

    Args:
        analyzer:        Memgar Analyzer instance (shared across chain if desired).
        block_on_threat: Raise MemgarThreatError instead of passing through.
        log_threats:     Log detected threats at WARNING level.
        source_type:     Label used in MemoryEntry for diagnostics.
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
        log_threats: bool = True,
        source_type: str = "langchain_chain",
    ) -> None:
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._log = log_threats
        self._source_type = source_type
        self._stats = _ScanStats()

    # ---- Runnable protocol ----

    def invoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
        text = _extract_text(input)
        result, elapsed = _scan_text(self._analyzer, text, self._source_type)
        self._stats.record(result, elapsed)

        if result.decision != Decision.ALLOW:
            if self._log:
                logger.warning(
                    "[Memgar] Threat detected | decision=%s score=%d threats=%d | %.1fms",
                    result.decision.value,
                    result.risk_score,
                    len(result.threats),
                    elapsed,
                )
            if self._block:
                raise MemgarThreatError(
                    f"Memgar blocked content (score={result.risk_score}): "
                    f"{result.explanation}",
                    result=result,
                )
        return input  # pass-through unchanged

    def stream(
        self,
        input: Any,
        config: Optional[Any] = None,
        **kwargs: Any,
    ) -> Iterator[Any]:
        # scan before streaming begins
        self.invoke(input, config, **kwargs)
        yield input

    def batch(
        self,
        inputs: List[Any],
        config: Optional[Any] = None,
        **kwargs: Any,
    ) -> List[Any]:
        return [self.invoke(i, config, **kwargs) for i in inputs]

    # ---- Introspection ----

    def get_stats(self) -> Dict[str, Any]:
        """Return cumulative scan statistics."""
        return self._stats.to_dict()

    def reset_stats(self) -> None:
        """Reset cumulative statistics."""
        self._stats = _ScanStats()

    def __repr__(self) -> str:
        return (
            f"MemgarSecurityRunnable("
            f"block={self._block}, "
            f"scanned={self._stats.total}, "
            f"blocked={self._stats.blocked})"
        )


# ---------------------------------------------------------------------------
# 2. MemgarLCELMiddleware
# ---------------------------------------------------------------------------

class MemgarLCELMiddleware(Runnable):
    """
    Wrap any existing Runnable with Memgar scanning on input AND output.

    Usage::

        safe_llm = MemgarLCELMiddleware(llm)
        chain = prompt | safe_llm | output_parser

    Args:
        runnable:        The Runnable to wrap.
        scan_input:      Scan the input before passing to the runnable.
        scan_output:     Scan the output after the runnable returns.
        analyzer:        Shared Analyzer instance.
        block_on_threat: Raise MemgarThreatError on threat.
    """

    def __init__(
        self,
        runnable: Runnable,
        scan_input: bool = True,
        scan_output: bool = True,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
    ) -> None:
        self._runnable = runnable
        self._scan_input = scan_input
        self._scan_output = scan_output
        self._scanner = MemgarSecurityRunnable(
            analyzer=analyzer,
            block_on_threat=block_on_threat,
            source_type="langchain_middleware",
        )

    def invoke(self, input: Any, config: Optional[Any] = None, **kwargs: Any) -> Any:
        if self._scan_input:
            self._scanner.invoke(input, config)
        output = self._runnable.invoke(input, config, **kwargs)
        if self._scan_output:
            self._scanner.invoke(output, config)
        return output

    def stream(
        self, input: Any, config: Optional[Any] = None, **kwargs: Any
    ) -> Iterator[Any]:
        if self._scan_input:
            self._scanner.invoke(input, config)
        for chunk in self._runnable.stream(input, config, **kwargs):
            if self._scan_output:
                self._scanner.invoke(chunk, config)
            yield chunk

    def batch(
        self, inputs: List[Any], config: Optional[Any] = None, **kwargs: Any
    ) -> List[Any]:
        return [self.invoke(i, config, **kwargs) for i in inputs]

    def get_stats(self) -> Dict[str, Any]:
        return self._scanner.get_stats()


# ---------------------------------------------------------------------------
# 3. MemgarChatMemory
# ---------------------------------------------------------------------------

class MemgarChatMemory(BaseChatMessageHistory):
    """
    Drop-in replacement for any BaseChatMessageHistory that scans every
    message before it is persisted.

    Wraps an existing history backend (default: in-memory list)::

        from langchain_community.chat_message_histories import RedisChatMessageHistory
        secure_history = MemgarChatMemory(
            base_history=RedisChatMessageHistory(session_id="abc"),
            block_on_threat=True,
        )

    If no base_history is provided an in-memory list is used.
    """

    def __init__(
        self,
        base_history: Optional[Any] = None,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
        scan_ai_messages: bool = False,
        source_type: str = "chat_history",
    ) -> None:
        self._base: list = []
        self._backend = base_history  # real LangChain history object if any
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._scan_ai = scan_ai_messages
        self._source_type = source_type
        self._stats = _ScanStats()

    # ---- BaseChatMessageHistory interface ----

    @property
    def messages(self) -> List[Any]:
        if self._backend is not None:
            return self._backend.messages
        return list(self._base)

    def add_message(self, message: Any) -> None:
        """Add a message after threat scanning."""
        # Skip AI messages unless explicitly requested
        is_ai = LANGCHAIN_AVAILABLE and isinstance(message, AIMessage)
        if not (is_ai and not self._scan_ai):
            text = _extract_text(message)
            result, elapsed = _scan_text(
                self._analyzer, text, self._source_type
            )
            self._stats.record(result, elapsed)

            if result.decision != Decision.ALLOW:
                logger.warning(
                    "[Memgar:ChatMemory] Blocked message | decision=%s score=%d",
                    result.decision.value,
                    result.risk_score,
                )
                if self._block:
                    raise MemgarThreatError(
                        f"Memgar blocked message (score={result.risk_score}): "
                        f"{result.explanation}",
                        result=result,
                    )
                return  # silently drop if not blocking

        if self._backend is not None:
            self._backend.add_message(message)
        else:
            self._base.append(message)

    def add_user_message(self, message: Union[str, Any]) -> None:
        if LANGCHAIN_AVAILABLE:
            msg = HumanMessage(content=message) if isinstance(message, str) else message
        else:
            msg = message
        self.add_message(msg)

    def add_ai_message(self, message: Union[str, Any]) -> None:
        if LANGCHAIN_AVAILABLE:
            msg = AIMessage(content=message) if isinstance(message, str) else message
        else:
            msg = message
        self.add_message(msg)

    def clear(self) -> None:
        self._base.clear()
        if self._backend is not None:
            self._backend.clear()

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 4. MemgarConversationBufferMemory
# ---------------------------------------------------------------------------

class MemgarConversationBufferMemory(BaseMemory):
    """
    ConversationBufferMemory drop-in with Memgar scanning.

    Scans every human turn before storing. Compatible with
    LangChain's ConversationChain and similar.

    Usage::

        memory = MemgarConversationBufferMemory()
        chain = ConversationChain(llm=llm, memory=memory)
    """

    def __init__(
        self,
        human_prefix: str = "Human",
        ai_prefix: str = "AI",
        memory_key: str = "history",
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
        return_messages: bool = False,
    ) -> None:
        self.human_prefix = human_prefix
        self.ai_prefix = ai_prefix
        self.memory_key = memory_key
        self._block = block_on_threat
        self._return_messages = return_messages
        self._history = MemgarChatMemory(
            analyzer=analyzer,
            block_on_threat=block_on_threat,
            scan_ai_messages=False,
            source_type="conversation_buffer",
        )

    # ---- BaseMemory interface ----

    @property
    def memory_variables(self) -> List[str]:
        return [self.memory_key]

    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        messages = self._history.messages
        if self._return_messages:
            return {self.memory_key: messages}
        # Format as plain string
        lines = []
        for msg in messages:
            if LANGCHAIN_AVAILABLE and isinstance(msg, HumanMessage):
                lines.append(f"{self.human_prefix}: {_extract_text(msg)}")
            elif LANGCHAIN_AVAILABLE and isinstance(msg, AIMessage):
                lines.append(f"{self.ai_prefix}: {_extract_text(msg)}")
            else:
                lines.append(str(msg))
        return {self.memory_key: "\n".join(lines)}

    def save_context(
        self, inputs: Dict[str, Any], outputs: Dict[str, str]
    ) -> None:
        human_text = inputs.get("input", inputs.get("human_input", ""))
        ai_text = outputs.get("response", outputs.get("output", ""))
        self._history.add_user_message(human_text)
        self._history.add_ai_message(ai_text)

    def clear(self) -> None:
        self._history.clear()

    def get_stats(self) -> Dict[str, Any]:
        return self._history.get_stats()


# ---------------------------------------------------------------------------
# 5. MemgarDocumentFilter
# ---------------------------------------------------------------------------

class MemgarDocumentFilter:
    """
    Filter a list of LangChain Documents, removing or flagging those
    whose page_content triggers Memgar threats.

    Usage::

        docs = loader.load()
        safe_docs = MemgarDocumentFilter().filter(docs)
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = False,
        add_metadata: bool = True,
    ) -> None:
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._add_meta = add_metadata
        self._stats = _ScanStats()

    def filter(self, documents: List[Any]) -> List[Any]:
        """
        Return only safe documents.

        Args:
            documents: List of LangChain Document objects.

        Returns:
            Filtered list with threat documents removed.
        """
        safe = []
        for doc in documents:
            text = doc.page_content if hasattr(doc, "page_content") else str(doc)
            result, elapsed = _scan_text(
                self._analyzer, text, "document_filter"
            )
            self._stats.record(result, elapsed)

            if result.decision == Decision.ALLOW:
                safe.append(doc)
            else:
                logger.warning(
                    "[Memgar:DocFilter] Removed doc | score=%d threats=%d",
                    result.risk_score,
                    len(result.threats),
                )
                if self._block:
                    raise MemgarThreatError(
                        f"Memgar blocked document (score={result.risk_score})",
                        result=result,
                    )
                # otherwise silently drop

        return safe

    def filter_and_tag(self, documents: List[Any]) -> List[Any]:
        """
        Return all documents but tag metadata with Memgar scan results.
        Useful for auditing without removing documents.
        """
        tagged = []
        for doc in documents:
            text = doc.page_content if hasattr(doc, "page_content") else str(doc)
            result, elapsed = _scan_text(
                self._analyzer, text, "document_filter"
            )
            self._stats.record(result, elapsed)

            if hasattr(doc, "metadata") and self._add_meta:
                doc.metadata["memgar_decision"] = result.decision.value
                doc.metadata["memgar_score"] = result.risk_score
                doc.metadata["memgar_threats"] = len(result.threats)
            tagged.append(doc)
        return tagged

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 6. SecureVectorStoreRetriever
# ---------------------------------------------------------------------------

class SecureVectorStoreRetriever(BaseRetriever):
    """
    VectorStoreRetriever wrapper that scans retrieved documents before
    returning them to the chain.

    Usage::

        base_retriever = vectorstore.as_retriever()
        secure = SecureVectorStoreRetriever(base_retriever=base_retriever)
        chain = RetrievalQA.from_chain_type(llm=llm, retriever=secure)
    """

    def __init__(
        self,
        base_retriever: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = False,
        min_trust_score: float = 0.0,
        source_type: str = "vector_store",
    ) -> None:
        self._base = base_retriever
        self._doc_filter = MemgarDocumentFilter(
            analyzer=analyzer,
            block_on_threat=block_on_threat,
        )
        self._min_trust = min_trust_score
        self._source_type = source_type

    def _get_relevant_documents(
        self, query: str, *, run_manager: Optional[Any] = None
    ) -> List[Any]:
        # Scan the query itself first
        result, _ = _scan_text(
            self._doc_filter._analyzer, query, "retriever_query"
        )
        if result.decision != Decision.ALLOW:
            logger.warning(
                "[Memgar:Retriever] Blocked query | score=%d", result.risk_score
            )
            return []

        # Retrieve from base
        if hasattr(self._base, "_get_relevant_documents"):
            docs = self._base._get_relevant_documents(query, run_manager=run_manager)
        elif hasattr(self._base, "get_relevant_documents"):
            docs = self._base.get_relevant_documents(query)
        elif hasattr(self._base, "invoke"):
            docs = self._base.invoke(query)
        else:
            docs = []

        # Filter returned docs
        return self._doc_filter.filter(docs)

    def get_stats(self) -> Dict[str, Any]:
        return self._doc_filter.get_stats()


# ---------------------------------------------------------------------------
# 7. Factory: create_secure_lcel_chain
# ---------------------------------------------------------------------------

def create_secure_lcel_chain(
    prompt: Any,
    llm: Any,
    output_parser: Optional[Any] = None,
    analyzer: Optional[Analyzer] = None,
    block_on_threat: bool = True,
    scan_output: bool = False,
) -> Any:
    """
    Build a secured LCEL chain with Memgar scanning on input (and optionally output).

    Args:
        prompt:          LangChain prompt template.
        llm:             Language model Runnable.
        output_parser:   Optional output parser.
        analyzer:        Shared Analyzer (created if None).
        block_on_threat: Raise on threat vs. log and pass through.
        scan_output:     Also scan LLM output.

    Returns:
        LCEL chain: prompt | MemgarSecurityRunnable | llm [| output_parser]

    Example::

        chain = create_secure_lcel_chain(
            prompt=ChatPromptTemplate.from_template("{input}"),
            llm=ChatOpenAI(),
        )
        result = chain.invoke({"input": "Summarize my notes"})
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain-core is required. Install with: pip install langchain-core"
        )

    _analyzer = analyzer or Analyzer()
    scanner = MemgarSecurityRunnable(
        analyzer=_analyzer,
        block_on_threat=block_on_threat,
        source_type="lcel_chain",
    )

    if scan_output:
        output_scanner = MemgarSecurityRunnable(
            analyzer=_analyzer,
            block_on_threat=False,  # don't block LLM outputs, just log
            source_type="lcel_chain_output",
        )
        if output_parser:
            return prompt | scanner | llm | output_scanner | output_parser
        return prompt | scanner | llm | output_scanner

    if output_parser:
        return prompt | scanner | llm | output_parser
    return prompt | scanner | llm
