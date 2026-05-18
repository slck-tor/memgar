"""Compute the next feed-bundle SemVer from CHANGELOG-FEED.md.

Reads the latest version from CHANGELOG-FEED.md, bumps it per the requested
component, and emits the result for shell consumption.

Usage:
    python scripts/feed_version.py --bump patch
    python scripts/feed_version.py --bump minor --output-env
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


CHANGELOG = Path("CHANGELOG-FEED.md")
HEADING_RE = re.compile(r"^## \[?(\d+)\.(\d+)\.(\d+)\]?")


def current_version() -> tuple[int, int, int]:
    if not CHANGELOG.exists():
        return (1, 0, 0)
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = HEADING_RE.match(line.strip())
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (1, 0, 0)


def bump(version: tuple[int, int, int], part: str) -> tuple[int, int, int]:
    major, minor, patch = version
    if part == "major":
        return (major + 1, 0, 0)
    if part == "minor":
        return (major, minor + 1, 0)
    if part == "patch":
        return (major, minor, patch + 1)
    raise ValueError(f"Unknown bump type: {part}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bump", choices=["patch", "minor", "major"], default="patch")
    p.add_argument("--output-env", action="store_true",
                   help="Emit GitHub Actions step output (key=value)")
    args = p.parse_args()

    current = current_version()
    nxt = bump(current, args.bump)
    nxt_str = f"{nxt[0]}.{nxt[1]}.{nxt[2]}"

    if args.output_env:
        print(f"next_version={nxt_str}")
        print(f"previous_version={current[0]}.{current[1]}.{current[2]}")
    else:
        print(nxt_str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
