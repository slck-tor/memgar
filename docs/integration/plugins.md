# Codex and Claude Code Plugins

Memgar ships a repo-local plugin package in `plugins/memgar`.

The package contains:

- `.codex-plugin/plugin.json` for Codex plugin metadata.
- `.claude-plugin/plugin.json` for Claude Code plugin metadata.
- `skills/memgar/SKILL.md` with memory poisoning guardrail instructions.
- `commands/status.md` and `commands/scan.md` for Claude Code slash-command workflows.
- `scripts/memgar-health.mjs` and `scripts/memgar-scan.mjs` for local checks.
- `bin/memgar-health` and `bin/memgar-scan` for plugin PATH usage where supported.

## Claude Code

```text
/plugin marketplace add slcxtor/memgar
/plugin install memgar@memgar-plugins
```

For local testing:

```bash
claude --plugin-dir ./plugins/memgar
```

## Codex

The Codex marketplace file is `.agents/plugins/marketplace.json`. It points to `./plugins/memgar` with `AVAILABLE` install policy and `ON_INSTALL` authentication policy.

## Required runtime

Install Memgar and start the gateway when gateway protection is expected:

```bash
pip install "memgar[gateway,agents]"
uvicorn gateway:app --host 127.0.0.1 --port 8080
```

For direct text scanning, the plugin uses:

```bash
memgar analyze "memory text" --json
```

## Security contract

The plugin is an operator and agent workflow package. It does not make raw memory writes safe by itself. Protected applications must still route memory writes, retrieval chunks, tool results, and gateway traffic through `SecureMemoryStore`, `MemoryRuntimeEnforcer`, or Memgar Gateway.
