"""
Memgar Framework Integrations
=============================

Agent framework and RAG integrations for Memgar.

Agent Frameworks:
    - Universal: UniversalMemoryGuard for any memory read/write callable
    - LangChain: MemgarMemoryGuard, MemgarCallbackHandler
    - CrewAI: MemgarCrewGuard, secure_crew, secure_agent
    - AutoGen: MemgarAutoGenGuard
    - OpenAI Assistants: MemgarAssistantGuard
    - OpenAI Agents SDK: MemgarOpenAIAgentsGuard
    - MCP: MemgarMCPGuard, MCP Server

RAG Frameworks:
    - LangChain RAG: MemgarRetriever, create_secure_rag_chain
    - LlamaIndex: MemgarRetriever, create_secure_query_engine

Usage:
    from memgar.integrations import UniversalMemoryGuard

    guard = UniversalMemoryGuard()
    safe_save = guard.wrap_writer(memory.save)
"""

# =============================================================================
# AGENT FRAMEWORK INTEGRATIONS
# =============================================================================

# Universal framework-neutral integration, always available.
from .universal import (
    MemoryBlockedError,
    MemoryOperation,
    MemoryProtectionResult,
    UniversalMemoryGuard,
    guard_agent_memory,
    secure_memory_writer,
)

UNIVERSAL_AVAILABLE = True

# LangChain Agent Integration
LANGCHAIN_AGENT_AVAILABLE = False
MemgarMemoryGuard = None
MemgarCallbackHandler = None
SecureConversationChain = None

try:
    from .langchain import (
        MemgarMemoryGuard,
        MemgarCallbackHandler,
        SecureConversationChain,
    )
    LANGCHAIN_AGENT_AVAILABLE = True
except ImportError:
    pass

# CrewAI Integration
CREWAI_AVAILABLE = False
MemgarCrewGuard = None
secure_crew = None
secure_agent = None

try:
    from .crewai import (
        MemgarCrewGuard,
        secure_crew,
        secure_agent,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    pass

# AutoGen Integration
AUTOGEN_AVAILABLE = False
MemgarAutoGenGuard = None

try:
    from .autogen import (
        MemgarAutoGenGuard,
    )
    AUTOGEN_AVAILABLE = True
except ImportError:
    pass

# OpenAI Assistants Integration
OPENAI_ASSISTANTS_AVAILABLE = False
MemgarAssistantGuard = None

try:
    from .openai_assistants import (
        MemgarAssistantGuard,
    )
    OPENAI_ASSISTANTS_AVAILABLE = True
except ImportError:
    pass

# OpenAI Agents SDK Integration
OPENAI_AGENTS_AVAILABLE = False
MemgarOpenAIAgentsGuard = None
guard_openai_agents = None

try:
    from .openai_agents import (
        MemgarOpenAIAgentsGuard,
        guard_openai_agents,
    )
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    pass

# MCP Integration
MCP_AVAILABLE = False
MemgarMCPGuard = None

try:
    from .mcp import (
        MemgarMCPGuard,
    )
    MCP_AVAILABLE = True
except ImportError:
    pass

# Mem0 (memory-management framework)
MEM0_AVAILABLE = False
MemgarMem0Guard = None
try:
    from .mem0 import MemgarMem0Guard, MEM0_AVAILABLE  # noqa: F811
except ImportError:
    pass

# Letta / MemGPT (memory-centric agent framework)
LETTA_AVAILABLE = False
MemgarLettaGuard = None
try:
    from .letta import MemgarLettaGuard, LETTA_AVAILABLE  # noqa: F811
except ImportError:
    pass

# Vector DB native adapters
PINECONE_AVAILABLE = False
MemgarPineconeIndex = None
try:
    from .pinecone import MemgarPineconeIndex, PINECONE_AVAILABLE  # noqa: F811
except ImportError:
    pass

CHROMA_AVAILABLE = False
MemgarChromaCollection = None
try:
    from .chroma import MemgarChromaCollection, CHROMA_AVAILABLE  # noqa: F811
except ImportError:
    pass

QDRANT_AVAILABLE = False
MemgarQdrantClient = None
try:
    from .qdrant import MemgarQdrantClient, QDRANT_AVAILABLE  # noqa: F811
except ImportError:
    pass

WEAVIATE_AVAILABLE = False
MemgarWeaviateCollection = None
try:
    from .weaviate import MemgarWeaviateCollection, WEAVIATE_AVAILABLE  # noqa: F811
except ImportError:
    pass

# Shared vector base — always available (no third-party deps)
from ._vector_base import (
    VectorStoreSecurityShell,
    WritePolicy,
    WriteScanRecord,
    VectorWriteBlocked,
)

# =============================================================================
# RAG FRAMEWORKS (Layer 3)
# =============================================================================

# LangChain RAG Integration
LANGCHAIN_RAG_AVAILABLE = False
LangChainMemgarRetriever = None
MemgarVectorStoreRetriever = None
TrustAwareDocumentLoader = None
create_secure_rag_chain = None
create_secure_conversational_chain = None
sync_metadata_to_retriever = None

try:
    from .langchain_rag import (
        MemgarRetriever as LangChainMemgarRetriever,
        MemgarVectorStoreRetriever,
        TrustAwareDocumentLoader,
        create_secure_rag_chain,
        create_secure_conversational_chain,
        sync_metadata_to_retriever,
    )
    LANGCHAIN_RAG_AVAILABLE = True
except ImportError:
    pass

# LlamaIndex Integration
LLAMAINDEX_AVAILABLE = False
LlamaIndexMemgarRetriever = None
MemgarNodePostprocessor = None
create_secure_query_engine = None
create_secure_chat_engine = None

try:
    from .llamaindex_rag import (
        MemgarRetriever as LlamaIndexMemgarRetriever,
        MemgarNodePostprocessor,
        create_secure_query_engine,
        create_secure_chat_engine,
    )
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    pass


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_available_integrations() -> dict:
    """Get status of all available integrations."""
    return {
        # Agent frameworks
        "universal": UNIVERSAL_AVAILABLE,
        "langchain_agent": LANGCHAIN_AGENT_AVAILABLE,
        "crewai": CREWAI_AVAILABLE,
        "autogen": AUTOGEN_AVAILABLE,
        "openai_assistants": OPENAI_ASSISTANTS_AVAILABLE,
        "openai_agents": OPENAI_AGENTS_AVAILABLE,
        "mcp": MCP_AVAILABLE,

        # Memory frameworks
        "mem0": MEM0_AVAILABLE,
        "letta": LETTA_AVAILABLE,

        # RAG frameworks
        "langchain_rag": LANGCHAIN_RAG_AVAILABLE,
        "llamaindex": LLAMAINDEX_AVAILABLE,

        # Vector databases
        "pinecone": PINECONE_AVAILABLE,
        "chroma": CHROMA_AVAILABLE,
        "qdrant": QDRANT_AVAILABLE,
        "weaviate": WEAVIATE_AVAILABLE,
    }


def list_integrations() -> None:
    """Print available integrations."""
    status = get_available_integrations()

    print("Memgar Integrations Status:")
    print("-" * 40)

    print("\nAgent Frameworks:")
    print("  Universal:         available")
    print(f"  LangChain Agent:    {'available' if status['langchain_agent'] else 'missing (pip install langchain)'}")
    print(f"  CrewAI:             {'available' if status['crewai'] else 'missing (pip install crewai)'}")
    print(f"  AutoGen:            {'available' if status['autogen'] else 'missing (pip install pyautogen)'}")
    print(f"  OpenAI Assistants:  {'available' if status['openai_assistants'] else 'missing (pip install openai)'}")
    print(f"  OpenAI Agents SDK:  {'available' if status['openai_agents'] else 'missing'}")
    print(f"  MCP:                {'available' if status['mcp'] else 'missing'}")

    print("\nRAG Frameworks:")
    print(f"  LangChain RAG:      {'available' if status['langchain_rag'] else 'missing (pip install langchain)'}")
    print(f"  LlamaIndex:         {'available' if status['llamaindex'] else 'missing (pip install llama-index)'}")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Status functions
    "get_available_integrations",
    "list_integrations",

    # Availability flags
    "UNIVERSAL_AVAILABLE",
    "LANGCHAIN_AGENT_AVAILABLE",
    "CREWAI_AVAILABLE",
    "AUTOGEN_AVAILABLE",
    "OPENAI_ASSISTANTS_AVAILABLE",
    "OPENAI_AGENTS_AVAILABLE",
    "MCP_AVAILABLE",
    "LANGCHAIN_RAG_AVAILABLE",
    "LLAMAINDEX_AVAILABLE",

    # Universal adapter
    "UniversalMemoryGuard",
    "MemoryProtectionResult",
    "MemoryBlockedError",
    "MemoryOperation",
    "guard_agent_memory",
    "secure_memory_writer",

    # LangChain Agent
    "MemgarMemoryGuard",
    "MemgarCallbackHandler",
    "SecureConversationChain",

    # CrewAI
    "MemgarCrewGuard",
    "secure_crew",
    "secure_agent",

    # AutoGen
    "MemgarAutoGenGuard",

    # OpenAI Assistants
    "MemgarAssistantGuard",

    # OpenAI Agents SDK
    "MemgarOpenAIAgentsGuard",
    "guard_openai_agents",

    # MCP
    "MemgarMCPGuard",

    # LangChain RAG
    "LangChainMemgarRetriever",
    "MemgarVectorStoreRetriever",
    "TrustAwareDocumentLoader",
    "create_secure_rag_chain",
    "create_secure_conversational_chain",
    "sync_metadata_to_retriever",

    # LlamaIndex
    "LlamaIndexMemgarRetriever",
    "MemgarNodePostprocessor",
    "create_secure_query_engine",
    "create_secure_chat_engine",
]
