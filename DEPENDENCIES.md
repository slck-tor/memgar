# Dependency Reference

## Core (always required)

| Package | Version | Purpose |
|---------|---------|---------|
| `click` | ≥8.0.0 | CLI framework (`memgar analyze`, `memgar scan`, etc.) |
| `rich` | ≥13.0.0 | Terminal output, tables, progress bars |

No ML or network dependencies in the base install. `pip install memgar` works in air-gapped environments.

---

## Optional Extras

Install extras with: `pip install "memgar[extra1,extra2]"`

### `semantic` — SemanticGuard Layer 1.5

| Package | Purpose |
|---------|---------|
| `sentence-transformers ≥2.2.0` | `all-MiniLM-L6-v2` embeddings for cluster-based similarity |
| `numpy ≥1.21.0` | Centroid math, cosine similarity |

Without this extra, `SemanticGuard` is disabled silently and Layer 1.5 is skipped.

### `llm` — LLM Semantic Analysis (Layer 2)

| Package | Purpose |
|---------|---------|
| `anthropic ≥0.18.0` | Claude API for semantic analysis |
| `openai ≥1.0.0` | OpenAI API alternative |

Requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` environment variable. Used when `Analyzer(use_llm=True)`.

### `langchain` — LangChain Integration

| Package | Purpose |
|---------|---------|
| `langchain ≥0.1.0` | `MemgarSecurityRunnable`, `MemgarChatMemory` |
| `langchain-core ≥0.1.0` | `Runnable` base class |
| `langchain-community ≥0.0.10` | Vector store retriever wrappers |

### `llamaindex` — LlamaIndex Integration

| Package | Purpose |
|---------|---------|
| `llama-index-core ≥0.10.0` | `MemgarQueryEngineSecurity`, node filters |

### `feed` — Threat Intelligence Feed

| Package | Purpose |
|---------|---------|
| `cryptography ≥41.0.0` | Ed25519 signature verification for feed bundles |

> **Note:** The `cryptography` package uses a Rust/pyo3 backend. On some systems the `_cffi_backend` may be missing, causing a `PanicException` at import time. Memgar catches this with `except BaseException` guards. If feed signature verification fails, patterns from the local `patterns.py` are still used.

### `observability` — Prometheus Metrics

| Package | Purpose |
|---------|---------|
| `prometheus_client ≥0.17.0` | 5 metrics exposed on `/metrics` endpoint |

### `tracing` — OpenTelemetry

| Package | Purpose |
|---------|---------|
| `opentelemetry-api ≥1.20.0` | Tracing API |
| `opentelemetry-sdk ≥1.20.0` | Span export |

### `server` — FastAPI REST Endpoint

| Package | Purpose |
|---------|---------|
| `fastapi ≥0.100.0` | REST API (`POST /analyze`, `GET /health`) |
| `uvicorn[standard] ≥0.23.0` | ASGI server |

### `watch` — File Watcher

| Package | Purpose |
|---------|---------|
| `watchdog ≥3.0.0` | `memgar watch ./memories/` filesystem events |

### `adversarial` — Red-Team Loop

| Package | Purpose |
|---------|---------|
| `anthropic ≥0.18.0` | Optional Claude API for semantic attack variants |

Offline mutations (homoglyph, leetspeak, base64, passive rewrite) work without this.

### `dev` — Development & Testing

| Package | Purpose |
|---------|---------|
| `pytest ≥7.0.0` | Test runner |
| `pytest-cov ≥4.0.0` | Coverage reports |
| `pytest-asyncio ≥0.21.0` | Async test support |
| `black ≥23.0.0` | Code formatter |
| `ruff ≥0.1.0` | Linter |
| `mypy ≥1.0.0` | Static type checker |

---

## Installation Profiles

```bash
# Minimal — pattern matching, CLI, no ML deps (air-gap friendly)
pip install memgar

# Standard production
pip install "memgar[semantic,feed,observability]"

# LangChain agent
pip install "memgar[langchain,semantic]"

# LlamaIndex RAG pipeline
pip install "memgar[llamaindex,semantic]"

# REST microservice
pip install "memgar[server,semantic,observability]"

# Full development environment
pip install "memgar[all]"
```

---

## Python Version Support

| Python | Status |
|--------|--------|
| 3.9 | Supported |
| 3.10 | Supported |
| 3.11 | Supported (recommended) |
| 3.12 | Supported |
| 3.13 | Supported |
| <3.9 | Not supported (uses `dict` type hints, `from __future__ import annotations`) |

---

## Dependency Tree (minimal install)

```
memgar
├── click ≥8.0.0
│   └── (no transitive deps)
└── rich ≥13.0.0
    ├── markdown-it-py
    ├── pygments
    └── typing-extensions (Python <3.11)
```

Standard production (`memgar[semantic,feed,observability]`) adds ~450MB for sentence-transformers model weights.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'sentence_transformers'`
Install the semantic extra: `pip install "memgar[semantic]"`

### `pyo3_runtime.PanicException` on feed signature verification
The system `cryptography` package has a broken Rust backend. Memgar catches this and falls back to local patterns automatically. To use the feed, try: `pip install --upgrade cryptography` or use a virtualenv with a clean install.

### `ModuleNotFoundError: No module named 'prometheus_client'`
Install: `pip install "memgar[observability]"` or `pip install prometheus_client`

### `ImportError: No module named 'anthropic'`
Install: `pip install "memgar[llm]"` — required for `Analyzer(use_llm=True)`

### Slow startup (~3.5s on first run)
Memgar compiles 736 regex patterns on first use, then pickles the result. Subsequent starts use the cache (~3ms). Pre-warm by importing at server startup: `from memgar.patterns import PATTERNS`.
