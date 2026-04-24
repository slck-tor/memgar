"""
Memgar Framework Deep Integrations
====================================

Deep integration modules for LangChain and LlamaIndex.
These modules provide drop-in security middleware that intercepts
memory operations at the framework level.

Available integrations:
    - LangChain: MemgarSecurityRunnable, MemgarChatMemory,
                 MemgarConversationBufferMemory, SecureVectorStoreRetriever,
                 MemgarLCELMiddleware
    - LlamaIndex: MemgarQueryEngineSecurity, MemgarIndexSecurity,
                  MemgarStorageContextSecurity, SecureVectorIndexRetriever,
                  MemgarIngestionPipelineSecurity
"""

from __future__ import annotations

__version__ = '1.0.0'

# LangChain deep integration
try:
    from memgar.frameworks.langchain_deep import (
        MemgarSecurityRunnable,
        MemgarChatMemory,
        MemgarConversationBufferMemory,
        SecureVectorStoreRetriever,
        MemgarLCELMiddleware,
        MemgarDocumentFilter,
        create_secure_lcel_chain,
        LANGCHAIN_AVAILABLE,
    )
    _LANGCHAIN_DEEP = True
except ImportError:
    _LANGCHAIN_DEEP = False

# LlamaIndex deep integration
try:
    from memgar.frameworks.llamaindex_deep import (
        MemgarQueryEngineSecurity,
        MemgarIndexSecurity,
        MemgarStorageContextSecurity,
        SecureVectorIndexRetriever,
        MemgarIngestionPipelineSecurity,
        MemgarNodeFilter,
        create_secure_query_pipeline,
        LLAMAINDEX_AVAILABLE,
    )
    _LLAMAINDEX_DEEP = True
except ImportError:
    _LLAMAINDEX_DEEP = False


def get_available_integrations() -> dict[str, bool]:
    """Return which deep integrations are available."""
    return {
        "langchain_deep": _LANGCHAIN_DEEP,
        "llamaindex_deep": _LLAMAINDEX_DEEP,
    }


# Framework availability detection (added for compatibility)
LANGCHAIN_AVAILABLE = _LANGCHAIN_DEEP
LLAMAINDEX_AVAILABLE = _LLAMAINDEX_DEEP
CREWAI_AVAILABLE = False
AUTOGEN_AVAILABLE = False

try:
    import crewai
    CREWAI_AVAILABLE = True
except ImportError:
    pass

try:
    import autogen
    AUTOGEN_AVAILABLE = True
except ImportError:
    pass


def get_available_frameworks():
    """Return list of available framework integrations"""
    available = []
    if LANGCHAIN_AVAILABLE:
        available.append('langchain')
    if LLAMAINDEX_AVAILABLE:
        available.append('llamaindex')
    if CREWAI_AVAILABLE:
        available.append('crewai')
    if AUTOGEN_AVAILABLE:
        available.append('autogen')
    return available


def check_framework(name):
    """Check if a framework is available"""
    frameworks = {
        'langchain': LANGCHAIN_AVAILABLE,
        'llamaindex': LLAMAINDEX_AVAILABLE,
        'crewai': CREWAI_AVAILABLE,
        'autogen': AUTOGEN_AVAILABLE,
    }
    return frameworks.get(name.lower(), False)


__all__ = [
    # LangChain
    "MemgarSecurityRunnable",
    "MemgarChatMemory",
    "MemgarConversationBufferMemory",
    "SecureVectorStoreRetriever",
    "MemgarLCELMiddleware",
    "MemgarDocumentFilter",
    "create_secure_lcel_chain",
    # LlamaIndex
    "MemgarQueryEngineSecurity",
    "MemgarIndexSecurity",
    "MemgarStorageContextSecurity",
    "SecureVectorIndexRetriever",
    "MemgarIngestionPipelineSecurity",
    "MemgarNodeFilter",
    "create_secure_query_pipeline",
    # Utils
    "get_available_integrations",
    "get_available_frameworks",
    "check_framework",
]
