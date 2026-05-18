---
description: Check Memgar Gateway health and active policy.
---

Run a Memgar Gateway health check and summarize whether memory protection is active.

Preferred command:

```bash
memgar-health
```

Fallback from a repo checkout:

```bash
node plugins/memgar/scripts/memgar-health.mjs
```

Report the gateway URL, health status, upstream allowlist status, input scanning, output scanning, and tool argument firewall status. If the command fails, clearly say that Memgar Gateway protection is not confirmed.
