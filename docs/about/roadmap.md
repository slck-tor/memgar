# Roadmap

Public, public-issue-driven. Open a GitHub issue if you want to push
something up the list.

## Now (v1.0 — shipped)

- [x] 4-layer pipeline (pattern · semantic · ML · trust · behavioral)
- [x] 770+ threat patterns including memory-context envelopes
- [x] Health visibility per subsystem
- [x] fail-close mode
- [x] Ed25519 signed threat feed
- [x] Prometheus + OCSF SIEM + OpenTelemetry
- [x] Two-tier CI gate (strict gold + expanded regression)
- [x] Corpus tier architecture
- [x] 8 public corpora ingested (7 default + WildJailbreak opt-in)
- [x] LangChain integration
- [x] Documentation portal at memgar.com

## Next (v1.1 — Q3 2026)

- [ ] **JavaScript / TypeScript SDK** — Node and browser bindings
- [ ] **LlamaIndex integration** (`memgar-llamaindex`)
- [ ] **AutoGen / CrewAI integration** packages
- [ ] **Hosted gateway** (memgar-gateway) — optional SaaS for non-Python
      stacks, runs the same engine via REST/gRPC
- [ ] **Production-trained transformer model** distributed via signed
      release, opt-in via `memgar.download_model()`
- [ ] **Public benchmark** — memgar vs Lakera Guard / NeMo Guardrails /
      Rebuff on PINT and our 464-sample corpus, results page on this site
- [ ] **Threat intel marketplace** — community-contributed pattern packs
      with signature verification

## Later (v1.2+ — Q4 2026 / 2027)

- [ ] **Active learning loop** — production traffic → hard negative
      mining → automatic retraining → canary deploy with quality gate
- [ ] **Dashboard UI** — web dashboard for memgar operators (Grafana-
      driven or standalone Next.js)
- [ ] **VS Code extension** — inline detection during agent development
- [ ] **Multi-language model support** — explicit per-language pattern
      sets (DE, ES, FR, JA, ZH) and recall guarantees
- [ ] **Federated threat intel** — secure cross-org pattern sharing
- [ ] **Cloudflare Workers / Edge runtime** support
- [ ] **SOC 2 / GDPR documentation pack** for enterprise deployment

## Research

Open questions we'd love help on:

- **Provenance-preserving memory writes** — can we annotate every chunk
  in a vector store with its origin signature without breaking retrieval?
- **Behavioural baseline transfer** — can baseline from one agent
  bootstrap a similar one without exposing PII?
- **Adversarial robustness of memory-context wrappers** — what new
  envelopes do attackers find next?
- **Cross-modal poisoning** — image / audio / video tools feeding into
  agent memory.

## Cut from this version

These were considered for v1.0 and explicitly postponed:

- Pre-shipped transformer model artifact (intentional — the default
  training data overfits; see [training docs](../development/training.md))
- Closed-source pattern packs
- Auto-learned source trust
- Telemetry phoning home

## How to influence

1. Open a GitHub issue describing your use case.
2. Vote with :+1: on existing issues.
3. PR a working prototype — we'll review and merge if it fits.
4. Join the [Discord](https://discord.gg/memgar) for synchronous discussion.
