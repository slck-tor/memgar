# Mission

**Memgar exists to make memory poisoning detectable and stoppable for any
team running an AI agent in production.**

## The problem

AI agents are moving from stateless request-response to stateful systems
with long-lived memory: RAG vector stores, conversation histories, user
preference caches, fine-tuned LoRAs, knowledge graphs. Each of those
stores is a write surface. Every write surface is an attack surface.

An attacker who poisons an agent's memory once — by submitting a doc to
the RAG corpus, planting a sentence in a public wiki the agent crawls,
or sending a malicious PDF attachment — can influence every future turn
of that agent indefinitely. The attacker doesn't have to be present at
inference time.

Existing tools (Lakera Guard, NeMo Guardrails, Rebuff, Garak) focus on
the input boundary: inspect the user's prompt before it reaches the LLM.
None of them inspect what's already in the memory store. None of them
detect memory-injection wrappers (`[Memory note] …`, `AI memory: …`,
`User previously said: …`).

That's the gap memgar fills.

## What we build

- **An open-source library** that anyone can audit, fork, and self-host.
  MIT licensed, no vendor lock-in.
- **A pattern library** with 770+ threat detectors covering prompt
  injection, exfiltration, manipulation, credential leaks, persona
  hijack, vulnerability exploitation, and more — with explicit
  attention to memory-injection wrappers.
- **A four-layer defense pipeline**: regex patterns, semantic
  embeddings, fine-tuned ONNX transformer, per-agent behavioral
  baseline. Defense in depth; each layer reports its own health.
- **A signed threat-intelligence feed** so new attack patterns reach
  every deployed instance within hours of being published.
- **Production observability**: Prometheus metrics, OCSF SIEM events,
  OpenTelemetry tracing, PSI-based drift detection, structured per-
  subsystem health.
- **A reproducible calibration corpus** so the false-positive / false-
  negative trade-off is measurable, not aspirational. Two CI gates:
  strict gold + expanded regression.

## What we won't build

- **Auto-learned source trust.** Trust is an operator decision; auto-
  learning trust from behavior would itself be an attack surface.
- **Closed-source detection.** Every pattern, calibration sample, and
  metric lives in the public repo. No "secret sauce" to fail closed
  around.
- **A SaaS that you can't escape.** Memgar is library-first. A hosted
  gateway exists, but the local-only mode is always the canonical one.
- **Marketing claims without numbers.** Every quality claim ties to a
  calibration report you can re-run.

## How we measure success

- **Catch rate** on real-world memory-poisoning corpora (currently
  79.8% recall on a 464-sample multilingual gold + auxiliary set).
- **FPR** on tricky-but-benign queries (currently 9.1% on the curated
  gold; 36% on the harder expanded set, surfacing real pattern
  precision issues we then fix).
- **Latency** at P95 (currently `<25 ms` end-to-end including
  transformer inference).
- **Adoption** — open issues, downloads, integrations.
- **Operator feedback** — what's missing from `health_check()`, where
  patterns over-flag, what threat vectors we miss.

## Get involved

- :material-github: [Source on GitHub](https://github.com/slcxtor/memgar)
- :material-discord: [Community Discord](https://discord.gg/memgar)
- :material-twitter: [@memgar_security](https://x.com/memgar_security)
- :material-email: hello@memgar.com (general) · security@memgar.com (vulns)

We welcome PRs from anyone who hits a real memory-poisoning incident in
their agent and wants to harden the public defense.
