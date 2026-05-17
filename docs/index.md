---
hide:
  - navigation
---

# Memgar

**Memory poisoning defense for AI agents.**

Memgar inspects, sanitizes, quarantines, and blocks unsafe memory before it can
influence an agent. Run it as a Python runtime guard, a FastAPI gateway in front
of model providers, or an integrity vault with signed snapshots, hash baselines,
diff, and rollback.

Every memory write, retrieval chunk, tool result, and gateway request gets a
security decision before it reaches the model or long-term memory.

<div class="grid cards" markdown>

-   :material-shield-check: __Detect__

    ---

    4-layer pipeline (pattern, semantic, ML transformer, behavioral baseline)
    with **770+ threat patterns** spanning prompt injection, exfiltration,
    manipulation, credential theft, and persona hijack.

-   :material-database-lock: __Memory-context aware__

    ---

    Memgar's distinct value vs Lakera / NeMo / Rebuff: it knows about
    `[Memory note]`, `AI memory:`, `User previously said:` and other
    **memory-injection envelopes** that look like ordinary context.

-   :material-speedometer: __Production-grade__

    ---

    `<5 ms` Layer 1, `~7 ms` ONNX inference, `<25 ms` P95 end-to-end.
    Health visibility, fail-close mode, Prometheus + SIEM, Ed25519 signed
    threat feed.

-   :material-source-branch: __Open source__

    ---

    MIT licensed. Auditable corpus, reproducible calibration gates, no
    runtime dependency on any external account.

</div>

## At a glance

```python
from memgar import Analyzer, MemoryEntry

a = Analyzer(use_llm=False)
a.register_source_trust("untrusted-wiki", 0.1)

result = a.analyze(MemoryEntry(content="..."))
print(result.decision, result.risk_score, result.explanation)
```

## What memgar protects

- Memory writes from chats, tools, documents, summaries, and external sources.
- RAG and vector retrieval chunks before they are inserted into context.
- Tool and function outputs before an agent trusts them.
- Gateway requests and responses, including tool/function arguments.
- Memory integrity through snapshots, hashes, provenance metadata, Ed25519
  signatures, diff, and rollback.

## Decision model

| Verdict | Meaning |
| --- | --- |
| `allow` | Safe content can be used as-is. |
| `sanitize` | A safe rewrite is available and should be used instead of the original. |
| `quarantine` | Store for audit or review, but do not use in context. |
| `human_review` | A human should approve before the memory affects an agent. |
| `block` | Reject the content before it reaches memory or the model. |

## Next steps

- [5-minute quickstart](quickstart.md) — install + first analyze
- [Architecture overview](architecture/overview.md) — the 4-layer pipeline
- [Threat categories](architecture/threats.md) — what memgar catches
- [Calibration & gates](development/calibration.md) — measure FP/FN on your corpus

## Why "memgar"?

Memory + guard. Built for the case nobody else is solving cleanly: long-lived
agent memory that an attacker can poison once and exploit indefinitely.
