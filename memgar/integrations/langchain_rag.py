"""
Memgar LangChain RAG Integration
================================

Trust-aware retrieval integration for LangChain.

MemgarRetriever first applies trust-aware ranking, then routes the final
LangChain Document outputs through UniversalMemoryGuard/SecureMemoryStore before
those chunks can enter model context. This closes the retrieval-side memory
poisoning loop where an already-poisoned vector store result is reintroduced into
the prompt.
"""

from __future__ import annotations

import copy
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from langchain_core.callbacks import CallbackManagerForRetrieverRun
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.vectorstores import VectorStore

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseRetriever = object
    Document = dict
    CallbackManagerForRetrieverRun = Any
    VectorStore = object

from ..retriever import RetrievalMetadata, TrustAwareRetriever
from .universal import UniversalMemoryGuard


class MemgarRetriever(BaseRetriever if LANGCHAIN_AVAILABLE else object):
    """Trust-aware and runtime-scanned LangChain retriever.

    The adapter wraps any LangChain-compatible retriever. It keeps the existing
    provenance/trust ranking layer and adds a second runtime retrieval firewall
    over returned Document.page_content values.
    """

    base_retriever: Any = None
    trust_retriever: Any = None
    return_metadata: bool = False
    on_anomaly: Any = None
    memory_guard: Any = None
    scan_retrieval_outputs: bool = True
    agent_id: str = "langchain"

    class Config:
        arbitrary_types_allowed = True

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
        top_k: int = 5,
        return_metadata: bool = False,
        metadata_store: Optional[Dict[str, RetrievalMetadata]] = None,
        on_anomaly: Optional[Callable] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        analyzer: Optional[Any] = None,
        runtime_policy: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        dlp: Optional[Any] = None,
        dlp_policy: Optional[Any] = None,
        auditor: Optional[Any] = None,
        agent_id: str = "langchain",
        scan_retrieval_outputs: bool = True,
        on_retrieval_threat: str = "drop",
        allow_legacy_guard: bool = False,
        guard: Optional[Any] = None,
        **kwargs: Any,
    ):
        if LANGCHAIN_AVAILABLE:
            super().__init__(**kwargs)

        self.base_retriever = base_retriever
        self.return_metadata = return_metadata
        self.on_anomaly = on_anomaly
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
            default_source_type="langchain_retrieval",
        )

        self.trust_retriever = TrustAwareRetriever(
            base_retriever=base_retriever,
            min_trust_score=min_trust_score,
            trust_weight_factor=trust_weight_factor,
            enable_temporal_decay=enable_temporal_decay,
            decay_half_life_days=decay_half_life_days,
            enable_anomaly_detection=enable_anomaly_detection,
            filter_flagged=filter_flagged,
            filter_high_risk=filter_high_risk,
            high_risk_threshold=high_risk_threshold,
            top_k=top_k,
        )

        if metadata_store:
            for doc_id, metadata in metadata_store.items():
                self.trust_retriever.set_metadata(doc_id, metadata)

    def _get_relevant_documents(
        self,
        query: str,
        *,
        run_manager: Optional[CallbackManagerForRetrieverRun] = None,
        **kwargs: Any,
    ) -> List[Document]:
        """Get relevant documents with trust ranking and retrieval firewalling."""

        result = self.trust_retriever.retrieve(query, **kwargs)
        if result.anomalies_detected > 0 and self.on_anomaly:
            self.on_anomaly(result.anomaly_details)

        documents = [self._document_from_retrieved(doc) for doc in result.documents]
        return self._guard_documents(documents, query=query)

    def get_relevant_documents(self, query: str, **kwargs: Any) -> List[Document]:
        """Get relevant documents for older LangChain versions."""

        return self._get_relevant_documents(query, **kwargs)

    def invoke(self, input: str, **kwargs: Any) -> List[Document]:
        """Invoke retriever using the LangChain standard interface."""

        return self._get_relevant_documents(input, **kwargs)

    def set_document_metadata(
        self,
        doc_id: str,
        trust_score: float = 0.5,
        source_type: str = "unknown",
        created_at: Optional[datetime] = None,
        risk_score: int = 0,
        flagged: bool = False,
        **extra: Any,
    ) -> None:
        """Set metadata for a document after adding it to a vector store."""

        metadata = RetrievalMetadata(
            doc_id=doc_id,
            content_hash=hashlib.sha256(doc_id.encode()).hexdigest(),
            trust_score=trust_score,
            source_type=source_type,
            created_at=created_at or datetime.now(timezone.utc),
            risk_score=risk_score,
            flagged=flagged,
            custom_data=extra,
        )
        self.trust_retriever.set_metadata(doc_id, metadata)

    def set_metadata_from_provenance(self, doc_id: str, provenance: Any) -> None:
        """Set metadata from a Layer 2 provenance object."""

        metadata = RetrievalMetadata(
            doc_id=doc_id,
            content_hash=provenance.content_hash,
            trust_score=provenance.trust_score / 100,
            source_type=(
                provenance.source.source_type.value
                if hasattr(provenance.source, "source_type")
                else "unknown"
            ),
            source_verified=provenance.source.verified
            if hasattr(provenance.source, "verified")
            else False,
            created_at=datetime.fromisoformat(provenance.created_at)
            if isinstance(provenance.created_at, str)
            else provenance.created_at,
            was_sanitized=provenance.was_sanitized,
            risk_score=provenance.risk_score,
            flagged=provenance.flagged_for_review,
            reviewed=provenance.reviewed_by is not None,
        )
        self.trust_retriever.set_metadata(doc_id, metadata)

    def get_retrieval_stats(self) -> Dict[str, Any]:
        """Get retrieval statistics."""

        stats = self.trust_retriever.get_statistics()
        stats["runtime_firewall_enabled"] = self.scan_retrieval_outputs
        return stats

    def get_anomaly_report(self) -> List[Dict[str, Any]]:
        """Get detected retrieval anomalies."""

        if self.trust_retriever.anomaly_detector:
            return [
                {
                    "type": anomaly.anomaly_type,
                    "doc_id": anomaly.doc_id,
                    "severity": anomaly.severity,
                    "description": anomaly.description,
                    "timestamp": anomaly.timestamp.isoformat(),
                }
                for anomaly in self.trust_retriever.anomaly_detector.get_all_anomalies()
            ]
        return []

    def _document_from_retrieved(self, doc: Any) -> Document:
        metadata = {
            "doc_id": doc.doc_id,
            "similarity_score": doc.similarity_score,
            "trust_adjusted_score": doc.trust_adjusted_score,
            "final_score": doc.final_score,
            "is_trusted": doc.is_trusted,
        }
        if self.return_metadata and doc.metadata:
            metadata["memgar"] = doc.metadata.to_dict()
        if doc.metadata and doc.metadata.custom_data:
            metadata.update(doc.metadata.custom_data)
        return _make_document(doc.content, metadata)

    def _guard_documents(self, documents: List[Document], *, query: str) -> List[Document]:
        if not self.scan_retrieval_outputs or not documents:
            return documents

        records = []
        for index, doc in enumerate(documents):
            metadata = _document_metadata(doc)
            records.append(
                {
                    "content": _document_content(doc),
                    "metadata": metadata,
                    "doc_id": metadata.get("doc_id", str(index)),
                    "_memgar_index": index,
                }
            )

        safe_records = self.memory_guard.guard_retrieval_results(
            records,
            query=query,
            top_k=len(records),
            source_type="langchain_retrieval",
            agent_id=self.agent_id,
        )
        safe_documents: List[Document] = []
        for record in safe_records:
            index = record.get("_memgar_index")
            if index is None or index >= len(documents):
                continue
            safe_documents.append(_replace_document_content(documents[index], record.get("content", "")))
        return safe_documents


class MemgarVectorStoreRetriever(MemgarRetriever):
    """Trust-aware retriever that wraps a LangChain VectorStore directly."""

    vector_store: Any = None

    def __init__(
        self,
        vector_store: Any,
        search_type: str = "similarity",
        search_kwargs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        base_retriever = vector_store.as_retriever(
            search_type=search_type,
            search_kwargs=search_kwargs or {"k": 10},
        )
        super().__init__(base_retriever=base_retriever, **kwargs)
        self.vector_store = vector_store


def create_secure_rag_chain(
    llm: Any,
    retriever: Any,
    min_trust_score: float = 0.3,
    chain_type: str = "stuff",
    return_source_documents: bool = True,
    on_anomaly: Optional[Callable] = None,
    **guard_kwargs: Any,
) -> Any:
    """Create a trust-aware and runtime-scanned RAG chain."""

    try:
        from langchain.chains import RetrievalQA
    except ImportError as exc:
        raise ImportError("langchain is required for RAG chains") from exc

    secure_retriever = MemgarRetriever(
        base_retriever=retriever,
        min_trust_score=min_trust_score,
        on_anomaly=on_anomaly,
        **guard_kwargs,
    )
    return RetrievalQA.from_chain_type(
        llm=llm,
        chain_type=chain_type,
        retriever=secure_retriever,
        return_source_documents=return_source_documents,
    )


def create_secure_conversational_chain(
    llm: Any,
    retriever: Any,
    memory: Any,
    min_trust_score: float = 0.3,
    on_anomaly: Optional[Callable] = None,
    **guard_kwargs: Any,
) -> Any:
    """Create a conversational RAG chain with secured retriever and memory."""

    try:
        from langchain.chains import ConversationalRetrievalChain
    except ImportError as exc:
        raise ImportError("langchain is required for conversational chains") from exc

    from .langchain import MemgarMemoryGuard

    shared_guard = guard_kwargs.get("memory_guard")
    memory_guard_kwargs = {
        key: value for key, value in guard_kwargs.items() if key != "memory_guard"
    }
    secure_retriever = MemgarRetriever(
        base_retriever=retriever,
        min_trust_score=min_trust_score,
        on_anomaly=on_anomaly,
        **guard_kwargs,
    )
    secure_memory = (
        memory
        if isinstance(memory, MemgarMemoryGuard)
        else MemgarMemoryGuard(memory, memory_guard=shared_guard, **memory_guard_kwargs)
    )
    return ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=secure_retriever,
        memory=secure_memory,
        return_source_documents=True,
    )


class TrustAwareDocumentLoader:
    """Document loader that assigns trust metadata during ingestion."""

    def __init__(
        self,
        default_trust: float = 0.5,
        source_trust_map: Optional[Dict[str, float]] = None,
        verified_domains: Optional[List[str]] = None,
    ):
        self.default_trust = default_trust
        self.source_trust_map = source_trust_map or {
            "system": 1.0,
            "verified": 0.95,
            "internal": 0.85,
            "authenticated": 0.7,
            "partner": 0.6,
            "external": 0.4,
            "unknown": 0.3,
        }
        self.verified_domains = set(verified_domains or [])

    def _generate_doc_id(self, content: str) -> str:
        return f"doc_{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _get_trust_score(
        self,
        source_type: str,
        domain: Optional[str] = None,
        verified: bool = False,
    ) -> float:
        if verified:
            return 0.95
        if domain and domain in self.verified_domains:
            return 0.9
        return self.source_trust_map.get(source_type, self.default_trust)

    def load_documents(
        self,
        documents: List[Any],
        source_type: str = "unknown",
        source_domain: Optional[str] = None,
        verified: bool = False,
        risk_score: int = 0,
        tags: Optional[List[str]] = None,
    ) -> List[Document]:
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain required for document loading")

        trust_score = self._get_trust_score(source_type, source_domain, verified)
        now = datetime.now(timezone.utc)
        processed_docs = []
        for doc in documents:
            if isinstance(doc, Document):
                content = doc.page_content
                existing_metadata = doc.metadata.copy()
            elif isinstance(doc, dict):
                content = doc.get("content", doc.get("text", doc.get("page_content", "")))
                existing_metadata = dict(doc.get("metadata", {}) or {})
            else:
                content = str(doc)
                existing_metadata = {}

            doc_id = existing_metadata.get("doc_id") or self._generate_doc_id(content)
            metadata = {
                **existing_metadata,
                "doc_id": doc_id,
                "trust_score": trust_score,
                "source_type": source_type,
                "source_domain": source_domain,
                "source_verified": verified,
                "created_at": now.isoformat(),
                "risk_score": risk_score,
                "tags": tags or [],
            }
            processed_docs.append(_make_document(content, metadata))
        return processed_docs


def check_langchain_available() -> bool:
    """Check if LangChain is available."""

    return LANGCHAIN_AVAILABLE


def sync_metadata_to_retriever(retriever: MemgarRetriever, documents: List[Document]) -> int:
    """Sync document metadata to a MemgarRetriever."""

    count = 0
    for doc in documents:
        metadata = _document_metadata(doc)
        if "doc_id" not in metadata:
            continue
        created_at = metadata.get("created_at")
        retriever.set_document_metadata(
            doc_id=metadata["doc_id"],
            trust_score=metadata.get("trust_score", 0.5),
            source_type=metadata.get("source_type", "unknown"),
            created_at=datetime.fromisoformat(created_at) if created_at else None,
            risk_score=metadata.get("risk_score", 0),
            flagged=metadata.get("flagged", False),
        )
        count += 1
    return count


def _make_document(content: str, metadata: Dict[str, Any]) -> Document:
    return Document(page_content=content, metadata=metadata)


def _document_content(doc: Any) -> str:
    if isinstance(doc, dict):
        return str(doc.get("page_content", doc.get("content", doc.get("text", ""))))
    return str(getattr(doc, "page_content", getattr(doc, "content", getattr(doc, "text", ""))))


def _document_metadata(doc: Any) -> Dict[str, Any]:
    if isinstance(doc, dict):
        return dict(doc.get("metadata", {}) or {})
    return dict(getattr(doc, "metadata", {}) or {})


def _replace_document_content(doc: Document, safe_content: str) -> Document:
    if isinstance(doc, dict):
        updated = dict(doc)
        if "page_content" in updated:
            updated["page_content"] = safe_content
        elif "content" in updated:
            updated["content"] = safe_content
        else:
            updated["page_content"] = safe_content
        return updated
    if hasattr(doc, "model_copy"):
        try:
            return doc.model_copy(update={"page_content": safe_content})
        except Exception:
            pass
    if hasattr(doc, "copy"):
        try:
            return doc.copy(update={"page_content": safe_content})
        except TypeError:
            pass
        except Exception:
            pass
    try:
        cloned = copy.copy(doc)
        setattr(cloned, "page_content", safe_content)
        return cloned
    except Exception:
        logger.debug("Memgar: unable to clone LangChain Document for sanitized retrieval")
    return _make_document(safe_content, _document_metadata(doc))
