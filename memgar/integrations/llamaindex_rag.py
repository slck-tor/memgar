"""
Memgar LlamaIndex RAG Integration
=================================

Trust-aware retrieval integration for LlamaIndex.

MemgarRetriever first applies trust-aware ranking, then routes returned node
content through UniversalMemoryGuard/SecureMemoryStore before those chunks can
enter model context. This matches the LangChain retrieval firewall and closes the
retrieval-side memory poisoning loop for LlamaIndex users.

Provides:
- MemgarRetriever: Trust-aware and runtime-scanned retriever for LlamaIndex
- MemgarNodePostprocessor: Trust-based and runtime-scanned node filtering
- Query engine helpers

Example:
    from llama_index.core import VectorStoreIndex
    from memgar.integrations.llamaindex_rag import MemgarRetriever

    # Create index
    index = VectorStoreIndex.from_documents(documents)

    # Wrap with Memgar
    retriever = MemgarRetriever(
        base_retriever=index.as_retriever(),
        min_trust_score=0.3,
    )

    # Use in query engine
    query_engine = index.as_query_engine(retriever=retriever)
"""

import logging
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Import base classes (handle if LlamaIndex not installed)
try:
    from llama_index.core.callbacks import CallbackManager
    from llama_index.core.postprocessor import BaseNodePostprocessor
    from llama_index.core.retrievers import BaseRetriever
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False
    BaseRetriever = object
    BaseNodePostprocessor = object
    NodeWithScore = Any
    QueryBundle = Any
    TextNode = Any
    CallbackManager = Any

from ..retriever import (
    RetrievalMetadata,
    RetrievedDocument,
    TrustAwareRetriever,
)
from .universal import UniversalMemoryGuard


class MemgarRetriever(BaseRetriever if LLAMAINDEX_AVAILABLE else object):
    """
    Trust-aware and runtime-scanned LlamaIndex retriever.

    Drop-in replacement that adds trust-weighted ranking, temporal decay,
    anomaly detection, and a SecureMemoryStore-backed retrieval firewall.
    """

    def __init__(
        self,
        base_retriever: Any,
        min_trust_score: float = 0.3,
        trust_weight_factor: float = 0.3,
        enable_temporal_decay: bool = True,
        decay_half_life_days: float = 30.0,
        enable_anomaly_detection: bool = True,
        filter_flagged: bool = True,
        filter_high_risk: bool = True,
        high_risk_threshold: int = 70,
        similarity_top_k: int = 5,
        return_metadata: bool = False,
        metadata_store: Optional[Dict[str, RetrievalMetadata]] = None,
        on_anomaly: Optional[Callable] = None,
        callback_manager: Optional[CallbackManager] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        analyzer: Optional[Any] = None,
        runtime_policy: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        dlp: Optional[Any] = None,
        dlp_policy: Optional[Any] = None,
        auditor: Optional[Any] = None,
        agent_id: str = "llamaindex",
        scan_retrieval_outputs: bool = True,
        on_retrieval_threat: str = "drop",
        allow_legacy_guard: bool = False,
        guard: Optional[Any] = None,
    ):
        """
        Initialize Memgar retriever for LlamaIndex.
        """
        if LLAMAINDEX_AVAILABLE:
            super().__init__(callback_manager=callback_manager)

        self.base_retriever = base_retriever
        self.return_metadata = return_metadata
        self.on_anomaly = on_anomaly
        self.similarity_top_k = similarity_top_k
        self.agent_id = agent_id
        self.scan_retrieval_outputs = scan_retrieval_outputs
        self.memory_guard = memory_guard or UniversalMemoryGuard(
            guard=guard,
            secure_store=secure_store,
            analyzer=analyzer,
            runtime_policy=runtime_policy,
            policy_engine=policy_engine,
            dlp=dlp,
            dlp_policy=dlp_policy,
            auditor=auditor,
            agent_id=agent_id,
            allow_legacy_guard=allow_legacy_guard,
            on_read_threat=on_retrieval_threat,
            default_source_type="llamaindex_retrieval",
        )

        self.trust_retriever = TrustAwareRetriever(
            retrieve_fn=self._base_retrieve,
            min_trust_score=min_trust_score,
            trust_weight_factor=trust_weight_factor,
            enable_temporal_decay=enable_temporal_decay,
            decay_half_life_days=decay_half_life_days,
            enable_anomaly_detection=enable_anomaly_detection,
            filter_flagged=filter_flagged,
            filter_high_risk=filter_high_risk,
            high_risk_threshold=high_risk_threshold,
            top_k=similarity_top_k,
        )

        if metadata_store:
            for doc_id, metadata in metadata_store.items():
                self.trust_retriever.set_metadata(doc_id, metadata)

    def _base_retrieve(
        self,
        query: str,
        k: int = 10,
        **kwargs
    ) -> List[Dict]:
        """Call base retriever and convert to dict format."""
        query_bundle = QueryBundle(query_str=query) if LLAMAINDEX_AVAILABLE else query

        if hasattr(self.base_retriever, 'retrieve'):
            nodes = self.base_retriever.retrieve(query_bundle)
        elif hasattr(self.base_retriever, '_retrieve'):
            nodes = self.base_retriever._retrieve(query_bundle)
        else:
            nodes = []

        results = []
        for node_with_score in nodes[:k]:
            if hasattr(node_with_score, 'node'):
                node = node_with_score.node
                score = node_with_score.score or 0.5
            else:
                node = node_with_score
                score = 0.5

            content = _node_content(node)
            node_id = _node_id(node, content)

            results.append({
                "content": content,
                "doc_id": node_id,
                "score": score,
                "metadata": _node_metadata(node),
                "_node": node,
            })

        return results

    def _retrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        """Retrieve nodes with trust-aware ranking and runtime firewalling."""
        query = query_bundle.query_str if hasattr(query_bundle, 'query_str') else str(query_bundle)

        result = self.trust_retriever.retrieve(query, top_k=self.similarity_top_k)

        if result.anomalies_detected > 0 and self.on_anomaly:
            self.on_anomaly(result.anomaly_details)

        documents = self._guard_retrieved_documents(result.documents, query=query)
        nodes_with_scores = []

        for doc in documents:
            node = self._node_from_retrieved(doc)

            if self.return_metadata and hasattr(node, 'metadata'):
                node.metadata["memgar"] = {
                    "similarity_score": doc.similarity_score,
                    "trust_adjusted_score": doc.trust_adjusted_score,
                    "final_score": doc.final_score,
                    "trust_weight": doc.trust_weight,
                    "temporal_decay": doc.temporal_decay,
                    "is_trusted": doc.is_trusted,
                    "is_anomalous": doc.is_anomalous,
                }

            nodes_with_scores.append(_make_node_with_score(
                node=node,
                score=doc.final_score,
            ))

        return nodes_with_scores

    def retrieve(self, str_or_query_bundle: Any) -> List[NodeWithScore]:
        """Public retrieve method."""
        if isinstance(str_or_query_bundle, str):
            query_bundle = QueryBundle(query_str=str_or_query_bundle) if LLAMAINDEX_AVAILABLE else str_or_query_bundle
        else:
            query_bundle = str_or_query_bundle
        return self._retrieve(query_bundle)

    def set_node_metadata(
        self,
        node_id: str,
        trust_score: float = 0.5,
        source_type: str = "unknown",
        created_at: Optional[datetime] = None,
        risk_score: int = 0,
        flagged: bool = False,
        **extra
    ) -> None:
        """Set metadata for a node."""
        import hashlib
        metadata = RetrievalMetadata(
            doc_id=node_id,
            content_hash=hashlib.sha256(node_id.encode()).hexdigest(),
            trust_score=trust_score,
            source_type=source_type,
            created_at=created_at or datetime.now(timezone.utc),
            risk_score=risk_score,
            flagged=flagged,
            custom_data=extra,
        )
        self.trust_retriever.set_metadata(node_id, metadata)

    def get_statistics(self) -> Dict:
        """Get retrieval statistics."""
        stats = self.trust_retriever.get_statistics()
        stats["runtime_firewall_enabled"] = self.scan_retrieval_outputs
        return stats

    def _guard_retrieved_documents(
        self,
        documents: List[RetrievedDocument],
        *,
        query: str,
    ) -> List[RetrievedDocument]:
        if not self.scan_retrieval_outputs or not documents:
            return documents

        records = []
        for index, doc in enumerate(documents):
            metadata = {
                "doc_id": doc.doc_id,
                "similarity_score": doc.similarity_score,
                "trust_adjusted_score": doc.trust_adjusted_score,
                "final_score": doc.final_score,
                "is_trusted": doc.is_trusted,
                "is_anomalous": doc.is_anomalous,
            }
            if doc.metadata:
                metadata["memgar"] = doc.metadata.to_dict()
            records.append({
                "content": doc.content,
                "metadata": metadata,
                "doc_id": doc.doc_id,
                "_memgar_index": index,
            })

        safe_records = self.memory_guard.guard_retrieval_results(
            records,
            query=query,
            top_k=len(records),
            source_type="llamaindex_retrieval",
            agent_id=self.agent_id,
        )

        safe_documents: List[RetrievedDocument] = []
        for record in safe_records:
            if not isinstance(record, dict):
                continue
            index = record.get("_memgar_index")
            if index is None or index >= len(documents):
                continue
            doc = documents[index]
            safe_content = _record_content(record, fallback=doc.content)
            if safe_content != doc.content:
                doc = replace(doc, content=safe_content)
            safe_documents.append(doc)
        return safe_documents

    def _node_from_retrieved(self, doc: RetrievedDocument) -> Any:
        metadata = {
            "trust_score": doc.trust_weight,
            "is_trusted": doc.is_trusted,
            "final_score": doc.final_score,
        }
        if doc.metadata and doc.metadata.custom_data:
            original = doc.metadata.custom_data.get("_node")
            if original is not None:
                original_content = _node_content(original)
                if original_content == doc.content:
                    return original
                metadata.update(_node_metadata(original))
        return _make_text_node(doc.content, doc.doc_id, metadata)


class MemgarNodePostprocessor(BaseNodePostprocessor if LLAMAINDEX_AVAILABLE else object):
    """
    Trust-based and runtime-scanned node postprocessor for LlamaIndex.

    Use when you want to keep your existing retriever but add trust-based
    filtering and SecureMemoryStore-backed runtime scanning as a postprocessing
    step before nodes enter model context.
    """

    def __init__(
        self,
        min_trust_score: float = 0.3,
        filter_anomalous: bool = True,
        filter_flagged: bool = True,
        metadata_key: str = "trust_score",
        enable_reranking: bool = True,
        trust_weight: float = 0.3,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        analyzer: Optional[Any] = None,
        runtime_policy: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        dlp: Optional[Any] = None,
        dlp_policy: Optional[Any] = None,
        auditor: Optional[Any] = None,
        agent_id: str = "llamaindex",
        scan_retrieval_outputs: bool = True,
        on_retrieval_threat: str = "drop",
        allow_legacy_guard: bool = False,
        guard: Optional[Any] = None,
    ):
        """Initialize postprocessor."""
        if LLAMAINDEX_AVAILABLE:
            super().__init__()

        self.min_trust_score = min_trust_score
        self.filter_anomalous = filter_anomalous
        self.filter_flagged = filter_flagged
        self.metadata_key = metadata_key
        self.enable_reranking = enable_reranking
        self.trust_weight = trust_weight
        self.agent_id = agent_id
        self.scan_retrieval_outputs = scan_retrieval_outputs
        self.memory_guard = memory_guard or UniversalMemoryGuard(
            guard=guard,
            secure_store=secure_store,
            analyzer=analyzer,
            runtime_policy=runtime_policy,
            policy_engine=policy_engine,
            dlp=dlp,
            dlp_policy=dlp_policy,
            auditor=auditor,
            agent_id=agent_id,
            allow_legacy_guard=allow_legacy_guard,
            on_read_threat=on_retrieval_threat,
            default_source_type="llamaindex_postprocessor",
        )

    def _postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        """Postprocess nodes with trust filtering and runtime firewalling."""
        filtered_nodes = []

        for node_with_score in nodes:
            node = node_with_score.node
            score = node_with_score.score or 0.5

            metadata = _node_metadata(node)
            trust_score = metadata.get(self.metadata_key, 0.5)

            if trust_score < self.min_trust_score:
                continue
            if self.filter_flagged and metadata.get("flagged", False):
                continue
            if self.filter_anomalous and metadata.get("is_anomalous", False):
                continue

            if self.enable_reranking:
                adjusted_score = score * (
                    1 - self.trust_weight +
                    self.trust_weight * trust_score
                )
            else:
                adjusted_score = score

            filtered_nodes.append(_make_node_with_score(
                node=node,
                score=adjusted_score,
            ))

        if self.enable_reranking:
            filtered_nodes.sort(key=lambda x: x.score or 0, reverse=True)

        query = query_bundle.query_str if hasattr(query_bundle, 'query_str') else str(query_bundle or "")
        return self._guard_nodes(filtered_nodes, query=query)

    def _guard_nodes(self, nodes: List[NodeWithScore], *, query: str) -> List[NodeWithScore]:
        if not self.scan_retrieval_outputs or not nodes:
            return nodes

        records = []
        for index, node_with_score in enumerate(nodes):
            node = node_with_score.node
            content = _node_content(node)
            records.append({
                "content": content,
                "metadata": _node_metadata(node),
                "doc_id": _node_id(node, content),
                "_memgar_index": index,
            })

        safe_records = self.memory_guard.guard_retrieval_results(
            records,
            query=query,
            top_k=len(records),
            source_type="llamaindex_postprocessor",
            agent_id=self.agent_id,
        )

        safe_nodes: List[NodeWithScore] = []
        for record in safe_records:
            if not isinstance(record, dict):
                continue
            index = record.get("_memgar_index")
            if index is None or index >= len(nodes):
                continue
            original = nodes[index]
            original_node = original.node
            original_content = _node_content(original_node)
            safe_content = _record_content(record, fallback=original_content)
            if safe_content == original_content:
                safe_node = original_node
            else:
                safe_node = _make_text_node(
                    safe_content,
                    _node_id(original_node, original_content),
                    _node_metadata(original_node),
                )
            safe_nodes.append(_make_node_with_score(node=safe_node, score=original.score or 0.5))
        return safe_nodes

    def postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        """Public postprocess method."""
        return self._postprocess_nodes(nodes, query_bundle)


# =============================================================================
# QUERY ENGINE HELPERS
# =============================================================================

def create_secure_query_engine(
    index: Any,
    min_trust_score: float = 0.3,
    similarity_top_k: int = 5,
    response_mode: str = "compact",
    on_anomaly: Optional[Callable] = None,
    **guard_kwargs: Any,
) -> Any:
    """Create a trust-aware query engine."""
    base_retriever = index.as_retriever(similarity_top_k=similarity_top_k * 2)
    secure_retriever = MemgarRetriever(
        base_retriever=base_retriever,
        min_trust_score=min_trust_score,
        similarity_top_k=similarity_top_k,
        on_anomaly=on_anomaly,
        **guard_kwargs,
    )

    query_engine = index.as_query_engine(
        retriever=secure_retriever,
        response_mode=response_mode,
    )

    return query_engine


def create_secure_chat_engine(
    index: Any,
    min_trust_score: float = 0.3,
    similarity_top_k: int = 5,
    chat_mode: str = "condense_plus_context",
    on_anomaly: Optional[Callable] = None,
    **guard_kwargs: Any,
) -> Any:
    """Create a trust-aware chat engine."""
    base_retriever = index.as_retriever(similarity_top_k=similarity_top_k * 2)
    secure_retriever = MemgarRetriever(
        base_retriever=base_retriever,
        min_trust_score=min_trust_score,
        similarity_top_k=similarity_top_k,
        on_anomaly=on_anomaly,
        **guard_kwargs,
    )

    chat_engine = index.as_chat_engine(
        retriever=secure_retriever,
        chat_mode=chat_mode,
    )

    return chat_engine


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_llamaindex_available() -> bool:
    """Check if LlamaIndex is available."""
    return LLAMAINDEX_AVAILABLE


def extract_trust_from_metadata(
    nodes: List[Any],
    trust_key: str = "trust_score",
    default_trust: float = 0.5,
) -> Dict[str, float]:
    """Extract trust scores from node metadata."""
    trust_map = {}

    for node in nodes:
        if hasattr(node, 'node'):
            actual_node = node.node
        else:
            actual_node = node

        node_id = actual_node.node_id if hasattr(actual_node, 'node_id') else str(hash(str(actual_node)))
        metadata = actual_node.metadata if hasattr(actual_node, 'metadata') else {}

        trust_map[node_id] = metadata.get(trust_key, default_trust)

    return trust_map


def _node_content(node: Any) -> str:
    if hasattr(node, 'get_content'):
        try:
            return str(node.get_content())
        except Exception:
            pass
    for attr in ('text', 'content', 'page_content'):
        value = getattr(node, attr, None)
        if isinstance(value, str):
            return value
    return str(node)


def _node_id(node: Any, content: str) -> str:
    value = getattr(node, 'node_id', None) or getattr(node, 'id_', None) or getattr(node, 'id', None)
    if value:
        return str(value)
    return str(hash(content))


def _node_metadata(node: Any) -> Dict[str, Any]:
    metadata = getattr(node, 'metadata', None)
    if isinstance(metadata, dict):
        return dict(metadata)
    return {}


def _record_content(record: Dict[str, Any], *, fallback: str) -> str:
    for key in ('content', 'text', 'page_content'):
        value = record.get(key)
        if isinstance(value, str):
            return value
    return fallback


def _make_text_node(content: str, node_id: str, metadata: Dict[str, Any]) -> Any:
    try:
        return TextNode(text=content, id_=node_id, metadata=metadata)
    except Exception:
        return _FallbackTextNode(content, node_id, metadata)


def _make_node_with_score(node: Any, score: float) -> Any:
    try:
        return NodeWithScore(node=node, score=score)
    except Exception:
        return _FallbackNodeWithScore(node=node, score=score)


class _FallbackTextNode:
    def __init__(self, text: str, node_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.text = text
        self.node_id = node_id
        self.metadata = metadata or {}

    def get_content(self) -> str:
        return self.text


class _FallbackNodeWithScore:
    def __init__(self, node: Any, score: float) -> None:
        self.node = node
        self.score = score
