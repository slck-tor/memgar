# Basic usage

## Single analyze

```python
from memgar import Analyzer, MemoryEntry, Decision

a = Analyzer(use_llm=False)

result = a.analyze(MemoryEntry(content="Schedule the team meeting for Friday"))

assert result.decision == Decision.ALLOW
print(result.risk_score)      # 0.0
print(result.layers_used)     # ['pattern_matching']
```

## Batch analyze

```python
results = [a.analyze(MemoryEntry(content=c)) for c in candidates]
blocked = [r for r in results if r.is_blocked]
```

## Async / threadpool

```python
import asyncio

async def scan(c):
    return await a.analyze_async(MemoryEntry(content=c))

results = await asyncio.gather(*(scan(c) for c in candidates))
```

`analyze_async` runs the synchronous analyzer in a thread pool so it composes
cleanly with FastAPI / aiohttp servers without blocking the loop.

## RAG retrieval guard (Layer 3 standalone)

The trust-aware retriever wraps your existing retriever; it does not need a
full Analyzer pipeline if you only want source-weighted ranking.

```python
from memgar.retriever import TrustAwareRetriever

retriever = TrustAwareRetriever(
    base_retriever=my_chroma_retriever,
    trust_map={"corporate-wiki": 0.95, "discord-paste": 0.1},
)

chunks = retriever.retrieve("How do I cancel my subscription?")
# Returns trust-weighted, deduped, and re-ranked chunks
```

## Analyzer result fields

```python
result = a.analyze(entry)
result.decision         # Decision.ALLOW / QUARANTINE / BLOCK
result.risk_score       # 0-100
result.is_attack        # decision != ALLOW
result.is_blocked       # decision == BLOCK
result.layers_used      # list[str], e.g. ['pattern_matching', 'transformer_ml']
result.explanation      # human-readable reason
result.threats          # list of matched ThreatMatch objects
result.category         # primary ThreatCategory
result.threat_type      # primary threat name
result.analysis_time_ms # latency
```

## Custom patterns

```python
from memgar import Analyzer
from memgar.models import Threat, ThreatCategory, Severity

custom = Threat(
    id="MYCO-001",
    name="My company-specific exfil token",
    description="Our internal API tokens leaking via memory",
    category=ThreatCategory.CREDENTIAL,
    severity=Severity.CRITICAL,
    patterns=[r"\bMYCO[a-z0-9]{32}\b"],
    keywords=["MYCO_"],
    examples=["MYCOa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"],
)

a = Analyzer(use_llm=False, custom_patterns=[custom])
```

## SIEM event subscription

```python
from memgar.siem import SIEMEventEmitter

emitter = SIEMEventEmitter(
    handlers=[my_splunk_writer, my_kafka_writer],
)
a = Analyzer(siem_emitter=emitter)
# Every block / quarantine emits an OCSF-compatible event
```
