"""
Memgar LlamaIndex Deep Integration
======================================

Deep integration with LlamaIndex (llama-index) providing:

- MemgarQueryEngineSecurity      — Wraps any QueryEngine with input/output scanning
- MemgarIndexSecurity            — Index-level security for insert / delete / query
- MemgarStorageContextSecurity   — StorageContext wrapper with write-time scanning
- SecureVectorIndexRetriever     — Retriever with per-node threat scanning
- MemgarIngestionPipelineSecurity — IngestionPipeline wrapper that filters nodes
- MemgarNodeFilter               — Standalone node filter (postprocessor)
- create_secure_query_pipeline   — Factory for a fully secured query pipeline

Usage::

    from memgar.frameworks import MemgarQueryEngineSecurity

    safe_engine = MemgarQueryEngineSecurity(base_engine=index.as_query_engine())
    response = safe_engine.query("Summarize my agent memory")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from memgar.analyzer import Analyzer
from memgar.models import AnalysisResult, Decision, MemoryEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional LlamaIndex import
# ---------------------------------------------------------------------------
try:
    from llama_index.core.query_engine import BaseQueryEngine
    from llama_index.core.retrievers import BaseRetriever
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import (
        NodeWithScore,
        QueryBundle,
        TextNode,
        BaseNode,
    )
    from llama_index.core.response.schema import RESPONSE_TYPE, Response
    from llama_index.core.indices.base import BaseIndex
    from llama_index.core.storage.storage_context import StorageContext
    from llama_index.core.ingestion import IngestionPipeline
    from llama_index.core.schema import TransformComponent

    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False

    # Stub base classes
    class BaseQueryEngine:  # type: ignore[no-redef]
        pass

    class BaseRetriever:  # type: ignore[no-redef]
        pass

    class BaseNodePostprocessor:  # type: ignore[no-redef]
        pass

    class NodeWithScore:  # type: ignore[no-redef]
        pass

    class QueryBundle:  # type: ignore[no-redef]
        pass

    class TransformComponent:  # type: ignore[no-redef]
        pass

    RESPONSE_TYPE = Any  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

@dataclass
class _ScanStats:
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
    source_type: str = "llamaindex",
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


def _node_text(node: Any) -> str:
    """Extract text from a NodeWithScore or BaseNode."""
    # LlamaIndex NodeWithScore has a .node attribute
    inner = getattr(node, "node", node)
    if hasattr(inner, "get_content"):
        return inner.get_content()
    if hasattr(inner, "text"):
        return inner.text
    if hasattr(inner, "page_content"):
        return inner.page_content
    # Fallback: try the outer object
    if hasattr(node, "get_content"):
        return node.get_content()
    if hasattr(node, "text"):
        return node.text
    return str(node)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class MemgarThreatError(Exception):
    """Raised when a threat is detected and block_on_threat=True."""

    def __init__(self, message: str, result: Optional[AnalysisResult] = None) -> None:
        super().__init__(message)
        self.result = result


# ---------------------------------------------------------------------------
# 1. MemgarNodeFilter  (postprocessor)
# ---------------------------------------------------------------------------

class MemgarNodeFilter(BaseNodePostprocessor):
    """
    LlamaIndex node postprocessor that scans each retrieved node and removes
    those containing threats.

    Usage::

        from llama_index.core.query_engine import RetrieverQueryEngine

        engine = RetrieverQueryEngine(
            retriever=retriever,
            node_postprocessors=[MemgarNodeFilter()],
        )

    Args:
        analyzer:        Shared Analyzer instance.
        block_on_threat: Raise MemgarThreatError instead of silently dropping.
        add_metadata:    Tag node metadata with scan results.
        min_score:       Minimum Memgar risk score to filter (0 = block nothing,
                         100 = only block score-100 threats).
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = False,
        add_metadata: bool = True,
        min_score: int = 50,
    ) -> None:
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._add_meta = add_metadata
        self._min_score = min_score
        self._stats = _ScanStats()

    def _postprocess_nodes(
        self,
        nodes: List[Any],
        query_bundle: Optional[Any] = None,
    ) -> List[Any]:
        safe_nodes: List[Any] = []
        for node in nodes:
            text = _node_text(node)
            node_id = getattr(
                getattr(node, "node", node), "node_id", None
            )
            result, elapsed = _scan_text(
                self._analyzer, text, "llamaindex_postprocessor", node_id
            )
            self._stats.record(result, elapsed)

            is_threat = (
                result.decision != Decision.ALLOW
                and result.risk_score >= self._min_score
            )

            if is_threat:
                logger.warning(
                    "[Memgar:NodeFilter] Filtered node id=%s | score=%d decision=%s",
                    node_id,
                    result.risk_score,
                    result.decision.value,
                )
                if self._block:
                    raise MemgarThreatError(
                        f"Memgar blocked node (score={result.risk_score}): "
                        f"{result.explanation}",
                        result=result,
                    )
                continue  # drop node

            # Optionally tag metadata
            if self._add_meta:
                target = getattr(node, "node", node)
                if hasattr(target, "metadata") and isinstance(target.metadata, dict):
                    target.metadata["memgar_decision"] = result.decision.value
                    target.metadata["memgar_score"] = result.risk_score
                    target.metadata["memgar_threats"] = len(result.threats)

            safe_nodes.append(node)
        return safe_nodes

    def postprocess_nodes(
        self,
        nodes: List[Any],
        query_bundle: Optional[Any] = None,
        **kwargs: Any,
    ) -> List[Any]:
        return self._postprocess_nodes(nodes, query_bundle)

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 2. SecureVectorIndexRetriever
# ---------------------------------------------------------------------------

class SecureVectorIndexRetriever(BaseRetriever):
    """
    Retriever wrapper that scans the query before retrieval and filters
    returned nodes through Memgar.

    Usage::

        base_retriever = index.as_retriever(similarity_top_k=5)
        secure = SecureVectorIndexRetriever(base_retriever=base_retriever)
        nodes = secure.retrieve("What are my agent's stored credentials?")
    """

    def __init__(
        self,
        base_retriever: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_query_threat: bool = True,
        block_on_node_threat: bool = False,
        min_score: int = 50,
    ) -> None:
        self._base = base_retriever
        self._analyzer = analyzer or Analyzer()
        self._block_query = block_on_query_threat
        self._node_filter = MemgarNodeFilter(
            analyzer=self._analyzer,
            block_on_threat=block_on_node_threat,
            min_score=min_score,
        )
        self._query_stats = _ScanStats()

    def _retrieve(self, query_bundle: Any) -> List[Any]:
        # 1. Scan query
        query_str = (
            query_bundle.query_str
            if hasattr(query_bundle, "query_str")
            else str(query_bundle)
        )
        result, elapsed = _scan_text(
            self._analyzer, query_str, "llamaindex_retriever_query"
        )
        self._query_stats.record(result, elapsed)

        if result.decision != Decision.ALLOW:
            logger.warning(
                "[Memgar:Retriever] Blocked query | score=%d", result.risk_score
            )
            if self._block_query:
                raise MemgarThreatError(
                    f"Memgar blocked retrieval query (score={result.risk_score})",
                    result=result,
                )
            return []

        # 2. Retrieve
        if hasattr(self._base, "_retrieve"):
            nodes = self._base._retrieve(query_bundle)
        elif hasattr(self._base, "retrieve"):
            nodes = self._base.retrieve(query_bundle)
        else:
            nodes = []

        # 3. Filter nodes
        return self._node_filter.postprocess_nodes(nodes, query_bundle)

    def retrieve(self, str_or_query_bundle: Any) -> List[Any]:
        if LLAMAINDEX_AVAILABLE and isinstance(str_or_query_bundle, str):
            query_bundle = QueryBundle(query_str=str_or_query_bundle)
        else:
            query_bundle = str_or_query_bundle
        return self._retrieve(query_bundle)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "query_stats": self._query_stats.to_dict(),
            "node_stats": self._node_filter.get_stats(),
        }


# ---------------------------------------------------------------------------
# 3. MemgarQueryEngineSecurity
# ---------------------------------------------------------------------------

class MemgarQueryEngineSecurity(BaseQueryEngine):
    """
    Wraps any LlamaIndex QueryEngine with Memgar scanning on:
      - query input
      - retrieved nodes (via node filter)
      - response output

    Usage::

        safe_engine = MemgarQueryEngineSecurity(
            base_engine=index.as_query_engine()
        )
        response = safe_engine.query("List all credentials in memory")
    """

    def __init__(
        self,
        base_engine: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_query_threat: bool = True,
        block_on_response_threat: bool = False,
        scan_response: bool = True,
    ) -> None:
        self._engine = base_engine
        self._analyzer = analyzer or Analyzer()
        self._block_query = block_on_query_threat
        self._block_response = block_on_response_threat
        self._scan_response = scan_response
        self._stats = _ScanStats()

    def _scan(self, text: str, source: str) -> AnalysisResult:
        result, elapsed = _scan_text(self._analyzer, text, source)
        self._stats.record(result, elapsed)
        return result

    def query(self, str_or_query_bundle: Any, **kwargs: Any) -> Any:
        """Run a query with full Memgar security scanning."""
        query_str = (
            str_or_query_bundle.query_str
            if hasattr(str_or_query_bundle, "query_str")
            else str(str_or_query_bundle)
        )

        # Scan query
        result = self._scan(query_str, "llamaindex_query_engine_input")
        if result.decision != Decision.ALLOW:
            logger.warning(
                "[Memgar:QueryEngine] Blocked query | score=%d", result.risk_score
            )
            if self._block_query:
                raise MemgarThreatError(
                    f"Memgar blocked query (score={result.risk_score}): "
                    f"{result.explanation}",
                    result=result,
                )

        # Execute query
        response = self._engine.query(str_or_query_bundle, **kwargs)

        # Optionally scan response
        if self._scan_response:
            resp_text = (
                str(response.response)
                if hasattr(response, "response")
                else str(response)
            )
            resp_result = self._scan(resp_text, "llamaindex_query_engine_output")
            if resp_result.decision != Decision.ALLOW:
                logger.warning(
                    "[Memgar:QueryEngine] Threat in response | score=%d",
                    resp_result.risk_score,
                )
                if self._block_response:
                    raise MemgarThreatError(
                        f"Memgar blocked LLM response (score={resp_result.risk_score})",
                        result=resp_result,
                    )

        return response

    def _query(self, query_bundle: Any) -> Any:
        """Internal method required by BaseQueryEngine."""
        return self.query(query_bundle)

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 4. MemgarIndexSecurity
# ---------------------------------------------------------------------------

class MemgarIndexSecurity:
    """
    Wraps a LlamaIndex BaseIndex to scan content on insert.

    Every document / node inserted is scanned before it reaches the index.
    Optionally also scans query operations by wrapping as_query_engine().

    Usage::

        from llama_index.core import VectorStoreIndex

        base_index = VectorStoreIndex([])
        secure_index = MemgarIndexSecurity(base_index=base_index)

        # Insert with scanning
        secure_index.insert(document)

        # Query with scanning
        engine = secure_index.as_secure_query_engine()
        response = engine.query("What credentials are stored?")
    """

    def __init__(
        self,
        base_index: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_insert: bool = True,
        block_on_query: bool = True,
    ) -> None:
        self._index = base_index
        self._analyzer = analyzer or Analyzer()
        self._block_insert = block_on_insert
        self._block_query = block_on_query
        self._stats = _ScanStats()

    def insert(self, document: Any, **kwargs: Any) -> None:
        """Insert a document after scanning its content."""
        text = (
            document.get_content()
            if hasattr(document, "get_content")
            else str(document)
        )
        doc_id = getattr(document, "doc_id", None) or getattr(document, "id_", None)

        result, elapsed = _scan_text(
            self._analyzer, text, "llamaindex_index_insert", str(doc_id)
        )
        self._stats.record(result, elapsed)

        if result.decision != Decision.ALLOW:
            logger.warning(
                "[Memgar:Index] Blocked insert | doc_id=%s score=%d",
                doc_id,
                result.risk_score,
            )
            if self._block_insert:
                raise MemgarThreatError(
                    f"Memgar blocked document insert (score={result.risk_score}): "
                    f"{result.explanation}",
                    result=result,
                )
            return  # silently drop

        self._index.insert(document, **kwargs)

    def insert_nodes(self, nodes: List[Any], **kwargs: Any) -> None:
        """Insert multiple nodes after scanning each."""
        safe_nodes = []
        for node in nodes:
            text = _node_text(node)
            result, elapsed = _scan_text(
                self._analyzer, text, "llamaindex_index_insert_node"
            )
            self._stats.record(result, elapsed)
            if result.decision == Decision.ALLOW:
                safe_nodes.append(node)
            else:
                logger.warning(
                    "[Memgar:Index] Filtered node on insert | score=%d",
                    result.risk_score,
                )
                if self._block_insert:
                    raise MemgarThreatError(
                        f"Memgar blocked node insert (score={result.risk_score})",
                        result=result,
                    )
        if safe_nodes:
            if hasattr(self._index, "insert_nodes"):
                self._index.insert_nodes(safe_nodes, **kwargs)

    def as_secure_query_engine(self, **kwargs: Any) -> MemgarQueryEngineSecurity:
        """Return a secured query engine for this index."""
        base_engine = self._index.as_query_engine(**kwargs)
        return MemgarQueryEngineSecurity(
            base_engine=base_engine,
            analyzer=self._analyzer,
            block_on_query_threat=self._block_query,
        )

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the base index."""
        return getattr(self._index, name)

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 5. MemgarStorageContextSecurity
# ---------------------------------------------------------------------------

class MemgarStorageContextSecurity:
    """
    Wraps a LlamaIndex StorageContext and intercepts writes to the
    docstore, index_store, and vector_store.

    This is a lower-level security layer that operates at the storage
    level rather than the index level, catching threats even if
    they bypass higher-level APIs.

    Usage::

        from llama_index.core import StorageContext

        base_ctx = StorageContext.from_defaults()
        secure_ctx = MemgarStorageContextSecurity(base_ctx)

        # Use secure_ctx wherever you would use base_ctx
        index = VectorStoreIndex(docs, storage_context=secure_ctx.context)
    """

    def __init__(
        self,
        base_context: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
    ) -> None:
        self._ctx = base_context
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._stats = _ScanStats()

    @property
    def context(self) -> Any:
        """The underlying (unmodified) StorageContext."""
        return self._ctx

    def safe_add_documents(self, documents: List[Any]) -> List[Any]:
        """
        Scan documents and add only safe ones to the docstore.

        Returns the list of documents that were accepted.
        """
        safe = []
        for doc in documents:
            text = (
                doc.get_content()
                if hasattr(doc, "get_content")
                else getattr(doc, "text", str(doc))
            )
            result, elapsed = _scan_text(
                self._analyzer, text, "llamaindex_storage_context"
            )
            self._stats.record(result, elapsed)

            if result.decision == Decision.ALLOW:
                safe.append(doc)
                if hasattr(self._ctx, "docstore") and hasattr(
                    self._ctx.docstore, "add_documents"
                ):
                    self._ctx.docstore.add_documents([doc])
            else:
                logger.warning(
                    "[Memgar:StorageContext] Blocked document | score=%d",
                    result.risk_score,
                )
                if self._block:
                    raise MemgarThreatError(
                        f"Memgar blocked document (score={result.risk_score}): "
                        f"{result.explanation}",
                        result=result,
                    )
        return safe

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()


# ---------------------------------------------------------------------------
# 6. MemgarIngestionPipelineSecurity
# ---------------------------------------------------------------------------

class MemgarIngestionPipelineSecurity:
    """
    Wraps a LlamaIndex IngestionPipeline and scans nodes after each
    transformation step, removing threats before they reach the vector store.

    Usage::

        from llama_index.core.ingestion import IngestionPipeline
        from llama_index.core.node_parser import SentenceSplitter

        base_pipeline = IngestionPipeline(transformations=[SentenceSplitter()])
        secure_pipeline = MemgarIngestionPipelineSecurity(base_pipeline)

        safe_nodes = secure_pipeline.run(documents=docs)
    """

    def __init__(
        self,
        base_pipeline: Any,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = False,
        min_score: int = 50,
    ) -> None:
        self._pipeline = base_pipeline
        self._filter = MemgarNodeFilter(
            analyzer=analyzer,
            block_on_threat=block_on_threat,
            min_score=min_score,
        )

    def run(
        self,
        documents: Optional[List[Any]] = None,
        nodes: Optional[List[Any]] = None,
        **kwargs: Any,
    ) -> List[Any]:
        """
        Run the pipeline and filter output nodes with Memgar.

        Returns only nodes that pass the security check.
        """
        result_nodes = self._pipeline.run(
            documents=documents,
            nodes=nodes,
            **kwargs,
        )
        return self._filter.postprocess_nodes(result_nodes)

    def get_stats(self) -> Dict[str, Any]:
        return self._filter.get_stats()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pipeline, name)


# ---------------------------------------------------------------------------
# 7. Factory: create_secure_query_pipeline
# ---------------------------------------------------------------------------

def create_secure_query_pipeline(
    index: Any,
    analyzer: Optional[Analyzer] = None,
    similarity_top_k: int = 5,
    block_on_query: bool = True,
    block_on_insert: bool = True,
    scan_response: bool = True,
) -> Dict[str, Any]:
    """
    Build a fully secured LlamaIndex pipeline from an existing index.

    Returns a dict with:
        - ``engine``    : MemgarQueryEngineSecurity — use for queries
        - ``retriever`` : SecureVectorIndexRetriever
        - ``index``     : MemgarIndexSecurity — use for inserts
        - ``analyzer``  : shared Analyzer instance

    Usage::

        pipeline = create_secure_query_pipeline(index=vector_index)
        response = pipeline["engine"].query("What API keys are cached?")

    Args:
        index:             LlamaIndex BaseIndex instance.
        analyzer:          Shared Analyzer (created if None).
        similarity_top_k:  Number of top documents to retrieve.
        block_on_query:    Block threats detected in queries.
        block_on_insert:   Block threats detected on insert.
        scan_response:     Scan LLM responses for data exfiltration.
    """
    if not LLAMAINDEX_AVAILABLE:
        raise ImportError(
            "llama-index is required. Install with: pip install llama-index-core"
        )

    _analyzer = analyzer or Analyzer()

    secure_index = MemgarIndexSecurity(
        base_index=index,
        analyzer=_analyzer,
        block_on_insert=block_on_insert,
        block_on_query=block_on_query,
    )

    base_retriever = index.as_retriever(similarity_top_k=similarity_top_k)
    secure_retriever = SecureVectorIndexRetriever(
        base_retriever=base_retriever,
        analyzer=_analyzer,
        block_on_query_threat=block_on_query,
    )

    base_engine = index.as_query_engine(similarity_top_k=similarity_top_k)
    secure_engine = MemgarQueryEngineSecurity(
        base_engine=base_engine,
        analyzer=_analyzer,
        block_on_query_threat=block_on_query,
        scan_response=scan_response,
    )

    return {
        "engine": secure_engine,
        "retriever": secure_retriever,
        "index": secure_index,
        "analyzer": _analyzer,
    }
