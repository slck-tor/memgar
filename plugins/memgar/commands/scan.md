---
description: Scan memory text with Memgar before storing or using it.
argument-hint: "<memory text>"
---

Scan the provided text with Memgar before it is written to memory or inserted into agent context.

Preferred command:

```bash
memgar-scan "$ARGUMENTS"
```

Fallback from a repo checkout:

```bash
node plugins/memgar/scripts/memgar-scan.mjs "$ARGUMENTS"
```

If the verdict is `block`, `quarantine`, or `human_review`, do not store the memory or use it in prompt context. If the verdict is `sanitize`, use only the sanitized content when it is available.
