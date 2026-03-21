# memgar/integrations/__init__.py

"""
Memgar Framework Integrations
"""

# Agent Framework Integrations
from .langchain import MemgarMemoryGuard, MemgarCallbackHandler
from .crewai import MemgarCrewGuard, secure_crew, secure_agent
from .autogen import MemgarAutoGenGuard
from .openai_assistants import MemgarAssistantGuard
from .mcp import MemgarMCPGuard

# RAG Integrations (Layer 3)
try:
    from .langchain_rag import (
        MemgarRetriever as LangChainMemgarRetriever,
        MemgarVectorStoreRetriever,
        TrustAwareDocumentLoader,
        create_secure_rag_chain,
    )
    LANGCHAIN_RAG_AVAILABLE = True
except ImportError:
    LANGCHAIN_RAG_AVAILABLE = False

try:
    from .llamaindex_rag import (
        MemgarRetriever as LlamaIndexMemgarRetriever,
        MemgarNodePostprocessor,
        create_secure_query_engine,
    )
    LLAMAINDEX_RAG_AVAILABLE = True
except ImportError:
    LLAMAINDEX_RAG_AVAILABLE = False

__all__ = [
    # Agent Frameworks
    "MemgarMemoryGuard",
    "MemgarCallbackHandler",
    "MemgarCrewGuard",
    "MemgarAutoGenGuard",
    "MemgarAssistantGuard",
    "MemgarMCPGuard",
    
    # RAG
    "LangChainMemgarRetriever",
    "LlamaIndexMemgarRetriever",
    "TrustAwareDocumentLoader",
    "create_secure_rag_chain",
    "create_secure_query_engine",
]
