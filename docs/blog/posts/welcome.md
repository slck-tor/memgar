---
date: 2026-05-17
authors:
  - memgar
categories:
  - Releases
  - Community
slug: welcome-to-memgar
---

# Welcome to memgar.com

The memgar documentation portal is live at memgar.com. Memgar is an
open-source library for memory-poisoning defense in AI agents —
the attack class where adversarial content lands in an agent's RAG
store, conversation history, or preference cache, and influences every
future turn.

<!-- more -->

## What's here

- [Quickstart](../../quickstart.md) — install + first analyze in 5 minutes
- [Architecture](../../architecture/overview.md) — the 4-layer pipeline
- [Threat catalog](../../threats/catalog.md) — every one of the 770+
  patterns memgar ships with
- [Deployment checklist](../../resources/deployment-checklist.md) —
  11 things to verify before turning memgar on in production
- [Memory poisoning 101](../../threats/memory-poisoning-101.md) — primer
  on the attack class and why it differs from classical prompt injection

## Highlights since v0.5

The road to v1.0 hardened memgar in five areas:

1. **Health visibility** — every subsystem (SemanticGuard,
   TransformerDetector, FeedLoader) now reports a structured
   `{status, reason, fix_hint}`. No more silent zero-scoring layers.

2. **Three new pattern families** surfaced by the Lakera Gandalf
   in-the-wild prompt-injection corpus:

    - `INJ-001` — broad override (`Ignore all previous TEXT`,
      `Forget all RESTRICTION`, typo-tolerant `Ignoren`)
    - `INJ-002` — system / initial-prompt leak probe
    - `INJ-003` — roleplay / DAN / Developer-Mode persona hijack

3. **Memory-context augmentation** — 8 envelopes per attack seed
   (`[Memory note]`, `AI memory:`, `User previously said:`, …).
   This is memgar's distinct angle vs prompt-injection-only tools.

4. **Corpus tier architecture** — Gold (95) + Mined (49) +
   Augmented (320) = 464 samples across the two-tier CI gate.
   Every auxiliary row is auditable via its `note` field.

5. **fail-close mode** — `Analyzer(fail_close=True)` or
   `MEMGAR_FAIL_CLOSE=true` escalates `ALLOW → QUARANTINE` when any ML
   layer or the threat feed is degraded.

## What's next

See the [roadmap](../../about/roadmap.md). Highlights:

- JS/TS SDK
- LlamaIndex / AutoGen / CrewAI integrations
- Production-trained transformer model (opt-in via `memgar.download_model()`)
- Public benchmark vs Lakera / NeMo / Rebuff

## Getting involved

- :material-github: [Source on GitHub](https://github.com/slcxtor/memgar)
- :material-discord: [Community Discord](https://discord.gg/memgar)
- :material-bug: [Reporting a vulnerability](../../security.md)
- :material-email: hello@memgar.com

Thanks for being here.
