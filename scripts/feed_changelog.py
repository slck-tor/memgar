"""Generate weekly threat-feed release notes + update CHANGELOG-FEED.md.

Compares the current `memgar/patterns.py` against the last published feed
bundle (`feeds/memgar-feed.json.gz`), computes pattern-level deltas (added /
removed / modified), and emits a release-notes markdown block. Also
prepends a new section to CHANGELOG-FEED.md so the repo carries a public
audit trail of every feed release.

Usage:
    python scripts/feed_changelog.py \
        --new-version 1.2.3 \
        --notes "Added 12 cross-tenant patterns" \
        --output /tmp/release_notes.md
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


CHANGELOG = Path("CHANGELOG-FEED.md")
FEED_BUNDLE = Path("feeds/memgar-feed.json.gz")
PATTERNS_FILE = Path("memgar/patterns.py")


def _load_patterns_from_file(path: Path) -> Dict[str, dict]:
    spec = importlib.util.spec_from_file_location("_patterns_module", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return {
        p.id: {
            "name": p.name,
            "category": p.category.value if hasattr(p.category, "value") else str(p.category),
            "severity": p.severity.value if hasattr(p.severity, "value") else str(p.severity),
        }
        for p in mod.PATTERNS
    }


def _load_previous_bundle() -> Dict[str, dict]:
    if not FEED_BUNDLE.exists():
        return {}
    with gzip.open(FEED_BUNDLE, "rt", encoding="utf-8") as fh:
        bundle = json.load(fh)
    return {p["id"]: p for p in bundle.get("patterns", [])}


def _diff(prev: Dict[str, dict], current: Dict[str, dict]) -> Dict[str, list]:
    prev_ids: Set[str] = set(prev)
    curr_ids: Set[str] = set(current)
    return {
        "added": sorted(curr_ids - prev_ids),
        "removed": sorted(prev_ids - curr_ids),
        "modified": sorted([
            pid for pid in (prev_ids & curr_ids)
            if prev[pid].get("name") != current[pid].get("name")
            or prev[pid].get("severity") != current[pid].get("severity")
        ]),
    }


def _category_breakdown(ids: List[str], patterns: Dict[str, dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for pid in ids:
        cat = patterns.get(pid, {}).get("category", "unknown")
        out[cat] = out.get(cat, 0) + 1
    return out


def _format_notes(version: str, summary: str, diff: Dict[str, list], current: Dict[str, dict]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"## [{version}] — {today}",
        "",
    ]
    if summary:
        lines.append(summary.strip())
        lines.append("")

    lines.append(f"**Pattern total:** {len(current)}")
    lines.append(
        f"**Delta since last release:** "
        f"+{len(diff['added'])} added · "
        f"-{len(diff['removed'])} removed · "
        f"~{len(diff['modified'])} modified"
    )
    lines.append("")

    if diff["added"]:
        breakdown = _category_breakdown(diff["added"], current)
        lines.append("### Added")
        for cat, count in sorted(breakdown.items(), key=lambda x: -x[1]):
            lines.append(f"- `{cat}`: {count}")
        # Inline a few example IDs (cap at 10 for noise control)
        sample = ", ".join(f"`{i}`" for i in diff["added"][:10])
        if sample:
            lines.append(f"  - sample IDs: {sample}{' …' if len(diff['added']) > 10 else ''}")
        lines.append("")

    if diff["removed"]:
        lines.append("### Removed")
        lines.append("- " + ", ".join(f"`{i}`" for i in diff["removed"][:20]))
        if len(diff["removed"]) > 20:
            lines.append(f"  - and {len(diff['removed']) - 20} more")
        lines.append("")

    if diff["modified"]:
        lines.append("### Modified")
        lines.append("- " + ", ".join(f"`{i}`" for i in diff["modified"][:20]))
        if len(diff["modified"]) > 20:
            lines.append(f"  - and {len(diff['modified']) - 20} more")
        lines.append("")

    lines.append("### Verify")
    lines.append("```bash")
    lines.append(f"memgar feed sync                  # downloads + verifies v{version}")
    lines.append("memgar feed verify                # re-check signature locally")
    lines.append("memgar feed status                # show installed version")
    lines.append("```")
    return "\n".join(lines)


def _prepend_changelog(notes: str) -> None:
    existing = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else ""
    header = "# Threat Feed Changelog\n\n"
    if existing.startswith(header):
        body = existing[len(header):]
    else:
        body = existing
    CHANGELOG.write_text(header + notes + "\n\n" + body, encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--new-version", required=True)
    p.add_argument("--notes", default="")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--skip-changelog", action="store_true",
                   help="Print notes only, don't modify CHANGELOG-FEED.md")
    args = p.parse_args()

    prev = _load_previous_bundle()
    current = _load_patterns_from_file(PATTERNS_FILE)
    diff = _diff(prev, current)

    notes = _format_notes(args.new_version, args.notes, diff, current)
    args.output.write_text(notes, encoding="utf-8")
    if not args.skip_changelog:
        _prepend_changelog(notes)

    print(f"Wrote release notes → {args.output}")
    print(f"Delta: +{len(diff['added'])} / -{len(diff['removed'])} / ~{len(diff['modified'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
