"""
Memgar LangChain RAG Integration
================================

Trust-aware retrieval integration for LangChain.

Provides:
- MemgarRetriever: Drop-in replacement for any LangChain retriever
- MemgarVectorStore: Trust-aware vector store wrapper
- Trust-aware RAG chain helpers

Example:
    from langchain_openai import OpenAIEmbeddings
    from langchain_community.vectorstores import FAISS
    from memgar.integrations.langchain_rag import MemgarRetriever
    
    # Wrap your existing retriever
    base_retriever = vector_store.as_retriever()
    secure_retriever = MemgarRetriever(base_retriever)
    
    # Use in RAG chain
    chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=secure_retriever,
    )
"""

import logging
from typing import List, Dict, Optional, Any, Callable, Sequence
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Import base classes (handle if LangChain not installed)
try:
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.documents import Document
    from langchain_core.callbacks import CallbackManagerForRetrieverRun
    from langchain_core.vectorstores import VectorStore
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseRetriever = object
    Document = dict
    CallbackManagerForRetrieverRun = Any
    VectorStore = object

from ..retriever import (
    TrustAwareRetriever,
    RetrievalMetadata,
    RetrievalResult,
    RetrievedDocument,
    TemporalDecay,
    DecayFunction,
    RetrievalAnomalyDetector,
)


class MemgarRetriever(BaseRetriever if LANGCHAIN_AVAILABLE else object):
    """
    Trust-aware LangChain retriever.
    
    Drop-in replacement that adds:
    - Trust-weighted ranking
    - Temporal decay
    - Anomaly detection
    - Untrusted content filtering
    
    Example:
        from langchain_community.vectorstores import Chroma
        from memgar.integrations.langchain_rag import MemgarRetriever
        
        # Create base retriever
        vector_store = Chroma.from_documents(docs, embeddings)
        base_retriever = vector_store.as_retriever(search_kwargs={"k": 10})
        
        # Wrap with Memgar
        secure_retriever = MemgarRetriever(
            base_retriever=base_retriever,
            min_trust_score=0.3,
            enable_temporal_decay=True,
        )
        
        # Use normally
        docs = secure_retriever.invoke("What is our refund policy?")
    """
    
    # Pydantic fields for LangChain
    base_retriever: Any = None
    trust_retriever: Any = None
    return_metadata: bool = False
    
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
        **kwargs
    ):
        """
        Initialize Memgar retriever.
        
        Args:
            base_retriever: LangChain retriever to wrap
            min_trust_score: Minimum trust score (0-1)
            trust_weight_factor: How much trust affects ranking
            enable_temporal_decay: Enable time-based decay
            decay_half_life_days: Half-life for decay
            enable_anomaly_detection: Detect suspicious patterns
            filter_flagged: Filter flagged documents
            filter_high_risk: Filter high-risk documents
            high_risk_threshold: Risk score threshold
            top_k: Number of documents to return
            return_metadata: Include Memgar metadata in doc.metadata
            metadata_store: Pre-populated metadata store
            on_anomaly: Callback for anomaly detection
        """
        if LANGCHAIN_AVAILABLE:
            super().__init__(**kwargs)
        
        self.base_retriever = base_retriever
        self.return_metadata = return_metadata
        self.on_anomaly = on_anomaly
        
        # Create trust-aware retriever
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
        
        # Load metadata if provided
        if metadata_store:
            for doc_id, metadata in metadata_store.items():
                self.trust_retriever.set_metadata(doc_id, metadata)
    
    def _get_relevant_documents(
        self,
        query: str,
        *,
        run_manager: Optional[CallbackManagerForRetrieverRun] = None,
    ) -> List[Document]:
        """
        Get relevant documents with trust-aware ranking.
        
        This is the main retrieval method called by LangChain.
        """
        # Get trust-aware results
        result = self.trust_retriever.retrieve(query)
        
        # Handle anomalies
        if result.anomalies_detected > 0 and self.on_anomaly:
            self.on_anomaly(result.anomaly_details)
        
        # Convert to LangChain Documents
        documents = []
        for doc in result.documents:
            # Build metadata
            metadata = {
                "doc_id": doc.doc_id,
                "similarity_score": doc.similarity_score,
                "trust_adjusted_score": doc.trust_adjusted_score,
                "final_score": doc.final_score,
                "is_trusted": doc.is_trusted,
            }
            
            if self.return_metadata and doc.metadata:
                metadata["memgar"] = doc.metadata.to_dict()
            
            # Preserve original metadata if present
            if doc.metadata and doc.metadata.custom_data:
                metadata.update(doc.metadata.custom_data)
            
            documents.append(Document(
                page_content=doc.content,
                metadata=metadata,
            ))
        
        return documents
    
    # Alias for older LangChain versions
    def get_relevant_documents(
        self,
        query: str,
        **kwargs
    ) -> List[Document]:
        """Get relevant documents (legacy method)."""
        return self._get_relevant_documents(query, **kwargs)
    
    def invoke(
        self,
        input: str,
        **kwargs
    ) -> List[Document]:
        """Invoke retriever (LangChain standard interface)."""
        return self._get_relevant_documents(input, **kwargs)
    
    def set_document_metadata(
        self,
        doc_id: str,
        trust_score: float = 0.5,
        source_type: str = "unknown",
        created_at: Optional[datetime] = None,
        risk_score: int = 0,
        flagged: bool = False,
        **extra
    ) -> None:
        """
        Set metadata for a document.
        
        Call this when adding documents to your vector store.
        """
        import hashlib
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
    
    def set_metadata_from_provenance(
        self,
        doc_id: str,
        provenance: Any,  # MemoryProvenance from Layer 2
    ) -> None:
        """Set metadata from Layer 2 provenance object."""
        metadata = RetrievalMetadata(
            doc_id=doc_id,
            content_hash=provenance.content_hash,
            trust_score=provenance.trust_score / 100,  # Convert 0-100 to 0-1
            source_type=provenance.source.source_type.value if hasattr(provenance.source, 'source_type') else "unknown",
            source_verified=provenance.source.verified if hasattr(provenance.source, 'verified') else False,
            created_at=datetime.fromisoformat(provenance.created_at) if isinstance(provenance.created_at, str) else provenance.created_at,
            was_sanitized=provenance.was_sanitized,
            risk_score=provenance.risk_score,
            flagged=provenance.flagged_for_review,
            reviewed=provenance.reviewed_by is not None,
        )
        self.trust_retriever.set_metadata(doc_id, metadata)
    
    def get_retrieval_stats(self) -> Dict:
        """Get retrieval statistics."""
        return self.trust_retriever.get_statistics()
    
    def get_anomaly_report(self) -> List[Dict]:
        """Get detected anomalies."""
        if self.trust_retriever.anomaly_detector:
            return [
                {
                    "type": a.anomaly_type,
                    "doc_id": a.doc_id,
                    "severity": a.severity,
                    "description": a.description,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in self.trust_retriever.anomaly_detector.get_all_anomalies()
            ]
        return []


class MemgarVectorStoreRetriever(MemgarRetriever):
    """
    Trust-aware retriever that wraps a VectorStore directly.
    
    Example:
        from langchain_community.vectorstores import FAISS
        
        vector_store = FAISS.from_documents(docs, embeddings)
        retriever = MemgarVectorStoreRetriever(
            vector_store=vector_store,
            search_type="similarity",
            search_kwargs={"k": 10}
        )
    """
    
    def __init__(
        self,
        vector_store: Any,
        search_type: str = "similarity",
        search_kwargs: Optional[Dict] = None,
        **kwargs
    ):
        """
        Initialize with vector store.
        
        Args:
            vector_store: LangChain VectorStore
            search_type: "similarity" or "mmr"
            search_kwargs: Search parameters
        """
        # Create base retriever from vector store
        base_retriever = vector_store.as_retriever(
            search_type=search_type,
            search_kwargs=search_kwargs or {"k": 10}
        )
        
        super().__init__(base_retriever=base_retriever, **kwargs)
        self.vector_store = vector_store


# =============================================================================
# RAG CHAIN HELPERS
# =============================================================================

def create_secure_rag_chain(
    llm: Any,
    retriever: Any,
    min_trust_score: float = 0.3,
    chain_type: str = "stuff",
    return_source_documents: bool = True,
    on_anomaly: Optional[Callable] = None,
) -> Any:
    """
    Create a trust-aware RAG chain.
    
    Example:
        from langchain_openai import ChatOpenAI
        
        llm = ChatOpenAI(model="gpt-4")
        chain = create_secure_rag_chain(
            llm=llm,
            retriever=vector_store.as_retriever(),
            min_trust_score=0.4,
        )
        
        result = chain.invoke({"query": "What is our policy?"})
    """
    try:
        from langchain.chains import RetrievalQA
    except ImportError:
        raise ImportError("langchain is required for RAG chains")
    
    # Wrap retriever with Memgar
    secure_retriever = MemgarRetriever(
        base_retriever=retriever,
        min_trust_score=min_trust_score,
        on_anomaly=on_anomaly,
    )
    
    # Create chain
    chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type=chain_type,
        retriever=secure_retriever,
        return_source_documents=return_source_documents,
    )
    
    return chain


def create_secure_conversational_chain(
    llm: Any,
    retriever: Any,
    memory: Any,
    min_trust_score: float = 0.3,
    on_anomaly: Optional[Callable] = None,
) -> Any:
    """
    Create a trust-aware conversational RAG chain.
    
    Example:
        from langchain.memory import ConversationBufferMemory
        
        memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        chain = create_secure_conversational_chain(
            llm=llm,
            retriever=retriever,
            memory=memory,
        )
    """
    try:
        from langchain.chains import ConversationalRetrievalChain
    except ImportError:
        raise ImportError("langchain is required for conversational chains")
    
    # Wrap retriever
    secure_retriever = MemgarRetriever(
        base_retriever=retriever,
        min_trust_score=min_trust_score,
        on_anomaly=on_anomaly,
    )
    
    chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=secure_retriever,
        memory=memory,
        return_source_documents=True,
    )
    
    return chain


# =============================================================================
# DOCUMENT INGESTION WITH TRUST
# =============================================================================

class TrustAwareDocumentLoader:
    """
    Document loader that assigns trust metadata during ingestion.
    
    Example:
        loader = TrustAwareDocumentLoader(
            default_trust=0.5,
            source_trust_map={
                "internal": 0.9,
                "partner": 0.7,
                "external": 0.4,
            }
        )
        
        # Load with trust metadata
        docs = loader.load_documents(
            raw_docs,
            source_type="internal"
        )
        
        # Add to vector store
        vector_store.add_documents(docs)
        
        # Register metadata with retriever
        for doc in docs:
            retriever.set_document_metadata(
                doc_id=doc.metadata["doc_id"],
                trust_score=doc.metadata["trust_score"],
                source_type=doc.metadata["source_type"],
            )
    """
    
    def __init__(
        self,
        default_trust: float = 0.5,
        source_trust_map: Optional[Dict[str, float]] = None,
        verified_domains: Optional[List[str]] = None,
    ):
        """
        Initialize loader.
        
        Args:
            default_trust: Default trust for unknown sources
            source_trust_map: Map of source_type to trust score
            verified_domains: List of verified domains
        """
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
        """Generate document ID from content."""
        import hashlib
        return f"doc_{hashlib.sha256(content.encode()).hexdigest()[:16]}"
    
    def _get_trust_score(
        self,
        source_type: str,
        domain: Optional[str] = None,
        verified: bool = False,
    ) -> float:
        """Get trust score for source."""
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
        """
        Load documents with trust metadata.
        
        Args:
            documents: List of documents (strings, dicts, or Document objects)
            source_type: Type of source
            source_domain: Domain if applicable
            verified: Whether source is verified
            risk_score: Pre-computed risk score
            tags: Optional tags
            
        Returns:
            List of Documents with trust metadata
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain required for document loading")
        
        trust_score = self._get_trust_score(source_type, source_domain, verified)
        now = datetime.now(timezone.utc)
        
        processed_docs = []
        for doc in documents:
            # Extract content
            if isinstance(doc, Document):
                content = doc.page_content
                existing_metadata = doc.metadata.copy()
            elif isinstance(doc, dict):
                content = doc.get("content", doc.get("text", doc.get("page_content", "")))
                existing_metadata = doc.get("metadata", {})
            else:
                content = str(doc)
                existing_metadata = {}
            
            # Generate doc_id
            doc_id = existing_metadata.get("doc_id") or self._generate_doc_id(content)
            
            # Build metadata
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
            
            processed_docs.append(Document(
                page_content=content,
                metadata=metadata,
            ))
        
        return processed_docs


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_langchain_available() -> bool:
    """Check if LangChain is available."""
    return LANGCHAIN_AVAILABLE


def sync_metadata_to_retriever(
    retriever: MemgarRetriever,
    documents: List[Document],
) -> int:
    """
    Sync document metadata to retriever.
    
    Call this after adding documents to vector store.
    
    Returns:
        Number of documents synced
    """
    count = 0
    for doc in documents:
        metadata = doc.metadata
        if "doc_id" in metadata:
            retriever.set_document_metadata(
                doc_id=metadata["doc_id"],
                trust_score=metadata.get("trust_score", 0.5),
                source_type=metadata.get("source_type", "unknown"),
                created_at=datetime.fromisoformat(metadata["created_at"]) if "created_at" in metadata else None,
                risk_score=metadata.get("risk_score", 0),
                flagged=metadata.get("flagged", False),
            )
            count += 1
    return count
