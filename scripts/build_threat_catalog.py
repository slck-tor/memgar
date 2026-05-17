#!/usr/bin/env python3
"""Render docs/threats/catalog.md from memgar/patterns.py.

Walks every Threat in PATTERNS and writes a browsable catalog page with:
  - count badge per category
  - per-pattern card: ID, name, description, examples, MITRE ATT&CK
  - links back to memgar/patterns.py on GitHub

Re-run whenever patterns.py changes:
    python scripts/build_threat_catalog.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import os
os.environ.setdefault("MEMGAR_FEED_ENABLED", "false")
os.environ.setdefault("MEMGAR_OBSERVABILITY_ENABLED", "false")

from memgar.patterns import PATTERNS  # noqa: E402

OUT = REPO_ROOT / "docs" / "threats" / "catalog.md"
REPO_URL = "https://github.com/slcxtor/memgar/blob/main/memgar/patterns.py"


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")


def main() -> int:
    by_cat: dict[str, list] = defaultdict(list)
    for t in PATTERNS:
        cat = t.category.value if hasattr(t.category, "value") else str(t.category)
        by_cat[cat].append(t)

    lines = [
        "---",
        "hide:",
        "  - toc",
        "title: Threat catalog",
        "description: Browsable index of every threat pattern memgar detects.",
        "---",
        "",
        "# Threat catalog",
        "",
        f"Memgar ships **{len(PATTERNS)} threat patterns** across "
        f"{len(by_cat)} categories. Each pattern is a `Threat` dataclass in "
        f"[`memgar/patterns.py`]({REPO_URL}) carrying detection regexes,"
        " keywords, MITRE ATT&CK mapping, and example payloads.",
        "",
        "Patterns are loaded once at import time, cached as a pickle at "
        "`~/.cache/memgar/patterns_v1.pkl`, and re-validated against the file"
        " hash so changes are picked up automatically.",
        "",
        "## Categories",
        "",
        "<div class=\"grid cards\" markdown>",
        "",
    ]

    cat_order = sorted(by_cat, key=lambda c: -len(by_cat[c]))
    for cat in cat_order:
        cnt = len(by_cat[cat])
        anchor = f"#category-{_slug(cat)}"
        lines.append(f"-   __{cat.upper()}__\n\n    ---\n\n    "
                     f"**{cnt}** pattern{'s' if cnt != 1 else ''}\n\n    "
                     f"[:octicons-arrow-right-24: View]({anchor})")
        lines.append("")

    lines += [
        "</div>",
        "",
        "---",
        "",
    ]

    for cat in cat_order:
        cat_lower = cat.lower()
        lines.append(f"## Category: {cat}")
        lines.append("")
        lines.append(f"<a id=\"category-{_slug(cat_lower)}\"></a>")
        lines.append("")
        lines.append(f"{len(by_cat[cat])} pattern{'s' if len(by_cat[cat]) != 1 else ''} "
                     "in this category.")
        lines.append("")
        for t in by_cat[cat]:
            sev = t.severity.name if hasattr(t.severity, "name") else str(t.severity)
            mitre = getattr(t, "mitre_attack", None) or "—"
            tid = getattr(t, "id", "?")
            name = getattr(t, "name", "?")
            desc = (getattr(t, "description", "") or "").strip()

            lines.append(f"### `{tid}` — {name}")
            lines.append("")
            lines.append(f"!!! abstract \"\"")
            lines.append(f"    {desc}")
            lines.append("")
            lines.append(f"**Severity** `{sev}` · **MITRE ATT&CK** `{mitre}`")
            lines.append("")

            examples = getattr(t, "examples", None) or []
            if examples:
                lines.append("Examples:")
                lines.append("")
                lines.append("```text")
                for ex in examples[:3]:
                    lines.append(str(ex).strip())
                lines.append("```")
                lines.append("")

            keywords = getattr(t, "keywords", None) or []
            if keywords:
                lines.append("Keywords: " + ", ".join(f"`{k}`" for k in keywords[:8]))
                lines.append("")
            lines.append("")
        lines.append("---")
        lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(PATTERNS)} patterns across {len(by_cat)} categories → {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
