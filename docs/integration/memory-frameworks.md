# Memory framework integrations

Drop-in security wrappers for the memory layers most agents are built on.
Each integration scans every **write** through memgar's `Analyzer` and
decorates every **read** with risk metadata, while keeping the underlying
library's public API surface intact — so existing code is a one-line upgrade.

## Coverage

| Layer | Library | Wrapper class | Status |
|---|---|---|---|
| Memory management | [Mem0](https://github.com/mem0ai/mem0) | `MemgarMem0Guard` | ✓ |
| Memory-centric agents | [Letta](https://docs.letta.com) (formerly MemGPT) | `MemgarLettaGuard` | ✓ |
| Vector DB | [Pinecone](https://docs.pinecone.io) | `MemgarPineconeIndex` | ✓ |
| Vector DB | [Chroma](https://docs.trychroma.com) | `MemgarChromaCollection` | ✓ |
| Vector DB | [Qdrant](https://qdrant.tech) | `MemgarQdrantClient` | ✓ |
| Vector DB | [Weaviate](https://weaviate.io) | `MemgarWeaviateCollection` | ✓ |

All six share the same `VectorStoreSecurityShell` underneath, so policy
semantics (BLOCK / SANITIZE / AUDIT_ONLY) and metadata fields
(`memgar_risk_score`, `memgar_decision`, `memgar_threat_ids`) are identical
across vendors.

## Write policies

```python
from memgar.integrations import WritePolicy

WritePolicy.BLOCK        # raises VectorWriteBlocked on poisoned content
WritePolicy.SANITIZE     # replaces content with "[blocked by memgar] (risk=..., ids=...)"
WritePolicy.AUDIT_ONLY   # writes through; attaches risk metadata for downstream filtering
```

`BLOCK` is the default — fail-closed. Pick `AUDIT_ONLY` when you want to
study attacks without disrupting agent behavior; pick `SANITIZE` when you
need to preserve schema cardinality but blank the content.

## Mem0

```python
from mem0 import Memory
from memgar.integrations import MemgarMem0Guard

memory = MemgarMem0Guard(Memory(), write_policy="block")

# Scanned write — raises VectorWriteBlocked on poison
memory.add("User prefers dark mode", user_id="alice")

# Scored read — every result gets risk metadata
hits = memory.search("dark mode", user_id="alice")
for h in hits:
    risk = h["metadata"]["memgar_risk_score"]
    if risk >= 40:
        continue  # skip suspicious memories
```

Wrapped methods: `add`, `update`, `search`, `get`, `get_all`, `delete`,
`history`. Both string and `List[Dict]` message formats are supported.

## Letta (MemGPT)

```python
from letta_client import Letta
from memgar.integrations import MemgarLettaGuard

client = MemgarLettaGuard(
    Letta(token="..."),
    guard_core_memory=True,  # also scan core memory block updates
)

# Archival memory write — scanned
client.insert_archival_memory(agent_id="...", memory="...")

# Archival memory read — decorated
results = client.query_archival_memory(agent_id="...", query="...")

# Core memory block — highest-leverage poisoning target,
# guarded by default
client.update_memory_block(
    agent_id="...", block_label="persona", value="..."
)
```

Core memory blocks are always in-context, so a poisoned block keeps
influencing the agent on every reply — the wrapper guards them by default
(disable with `guard_core_memory=False` if you trust the source).

## Pinecone

```python
from pinecone import Pinecone
from memgar.integrations import MemgarPineconeIndex

pc = Pinecone(api_key="...")
index = MemgarPineconeIndex(pc.Index("agent-memory"), text_key="text")

# Scanned upsert — vectors with poisoned metadata.text raise
index.upsert(vectors=[
    {"id": "d1", "values": embed("..."), "metadata": {"text": "..."}}
])

# Scored query — match.metadata.memgar_risk_score is populated
result = index.query(vector=embed("..."), top_k=5, include_metadata=True)
trusted = [m for m in result["matches"]
           if m["metadata"].get("memgar_risk_score", 100) < 40]
```

`text_key` is the metadata key holding the text (defaults to `"text"`,
matching LangChain / LlamaIndex defaults).

## Chroma

```python
import chromadb
from memgar.integrations import MemgarChromaCollection

raw = chromadb.Client().get_or_create_collection("agent-memory")
collection = MemgarChromaCollection(raw)

# Scanned add — entire batch fails if any document is BLOCK-poisoned
collection.add(
    documents=["...", "..."],
    ids=["d1", "d2"],
    metadatas=[{"source": "user"}, {"source": "user"}],
)

# Scored query — metadatas[0][i].memgar_risk_score for each match
results = collection.query(query_texts=["..."], n_results=5)
```

## Qdrant

```python
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from memgar.integrations import MemgarQdrantClient

client = MemgarQdrantClient(QdrantClient(":memory:"))

client.upsert(
    collection_name="memory",
    points=[PointStruct(id=1, vector=embed("..."), payload={"text": "..."})],
)

# Both classic search and v1.10+ query_points are wrapped
hits = client.search(collection_name="memory", query_vector=embed("..."), limit=5)
for hit in hits:
    print(hit.payload["memgar_risk_score"], hit.payload["text"])
```

`text_key` is the payload key (defaults to `"text"`).

## Weaviate

```python
import weaviate
from memgar.integrations import MemgarWeaviateCollection

client = weaviate.connect_to_local()
collection = MemgarWeaviateCollection(
    client.collections.get("AgentMemory"),
    text_property="content",
)

# Scanned write — every insert / insert_many / replace / update path
collection.data.insert({"content": "...", "source": "user"})

# Scored query — near_text, near_vector, hybrid, bm25, fetch_objects
response = collection.query.near_text(query="...", limit=5)
for obj in response.objects:
    print(obj.properties["memgar_risk_score"])
```

Supports v4 client. `text_property` picks the schema property holding the
document body (falls back to `"text"` if `"content"` is absent).

## Common patterns

### Custom analyzer

By default each wrapper builds an `Analyzer(use_llm=False)` (fast, Layer
1 + Layer 1.5 only). Pass your own analyzer to enable Layer 2 LLM or
Layer 4 behavioral baseline:

```python
from memgar import Analyzer

analyzer = Analyzer(use_llm=True, behavioral_baseline=True)
guard = MemgarMem0Guard(memory, analyzer=analyzer)
```

### Audit hook

Capture every BLOCK event for SIEM forwarding:

```python
def on_block(record):
    siem.emit("memory.write.blocked", {
        "risk": record.risk_score,
        "decision": record.decision,
        "threat_ids": record.threat_ids,
        "content_preview": record.content[:200],
    })

guard = MemgarMem0Guard(memory)
guard.shell.on_block = on_block
```

### Trust-aware filtering at read time

```python
hits = memory.search("...", user_id="alice", limit=20)
trusted = [
    h for h in hits
    if h["metadata"].get("memgar_risk_score", 100) < 40
]
```

For multi-modal trust scoring (per-source weights, temporal decay) wrap the
underlying retriever with `TrustAwareRetriever` first, then with the
memgar integration.

## What gets scanned, what doesn't

| Operation | Scanned | Notes |
|---|---|---|
| Mem0 `add` / `update` | ✓ | Body, system/user/assistant messages alike |
| Mem0 `search` | ✓ | Each result's text decorated |
| Letta `insert_archival_memory` | ✓ | – |
| Letta `query_archival_memory` | ✓ | – |
| Letta `update_memory_block` | ✓ (configurable) | Off via `guard_core_memory=False` |
| Pinecone `upsert` | ✓ | Reads `metadata[text_key]` |
| Pinecone `query` | ✓ | Forces `include_metadata=True` |
| Chroma `add` / `upsert` | ✓ | Reads parallel `documents` array |
| Chroma `query` | ✓ | Patches `metadatas[q_idx][i]` |
| Qdrant `upsert` | ✓ | Reads `payload[text_key]` |
| Qdrant `search` / `query_points` | ✓ | – |
| Weaviate `data.insert` etc. | ✓ | Reads `properties[text_property]` |
| Weaviate `query.*` (all 5 paths) | ✓ | – |

What's NOT scanned: raw vector values, vendor-specific configuration calls,
collection management (`create_collection`, `delete`), batch deletes. The
threat model is "poisoned content reaches memory and gets retrieved later"
— operations that don't transit content are out of scope.

## See also

- [Memory poisoning kill chain](../threats/kill-chain.md) — TTP framework
- [Threat catalog](../threats/catalog.md) — every pattern, full text
- [Memory forensics](../operations/forensics.md) — operator CLI commands
