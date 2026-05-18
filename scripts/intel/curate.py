"""Interactive curator for `proposed_patterns/*.jsonl`.

Walks each JSONL file, shows one candidate at a time, prompts the
curator with a/r/s/q:

  a — accept; append to `proposed_patterns/accepted.jsonl`
  r — reject; append to `proposed_patterns/rejected.jsonl`
  s — skip (decide later, leaves it in the source JSONL)
  q — quit

The "accepted" file is the human-blessed feed for the next pattern-
release. Adding entries to `memgar/patterns.py` is still a manual
step — the curator typically:
  1. Reviews a batch of accepted candidates
  2. Drafts regex / keywords / examples for each
  3. Adds them to patterns.py
  4. Re-runs the feed-publish workflow

Batch mode (`--auto-accept-source <name>`) and stats-only mode are
also available; see `--help`.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import CandidateSource

logger = logging.getLogger("memgar.intel.curate")


PROPOSED_DIR = Path("proposed_patterns")
ACCEPTED = PROPOSED_DIR / "accepted.jsonl"
REJECTED = PROPOSED_DIR / "rejected.jsonl"


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _display(c: dict, idx: int, total: int) -> None:
    print()
    print(f"───── Candidate {idx}/{total} ─────")
    print(f"Source:       {c.get('source')}")
    print(f"Source ID:    {c.get('source_id')}")
    print(f"Source URL:   {c.get('source_url')}")
    print(f"Proposed ID:  {c.get('proposed_id')}")
    print(f"Name:         {c.get('name')}")
    print(f"Severity:     {c.get('severity_guess')}   Category: {c.get('category_guess')}")
    print(f"MITRE:        {c.get('mitre_attack')}")
    desc = c.get("description", "")
    print(f"Description:  {desc}")
    if c.get("sample_text"):
        print(f"Sample:")
        for line in c["sample_text"].splitlines():
            print(f"  │ {line}")
    print(f"Fingerprint:  {c.get('fingerprint')}")


def curate_interactive(
    source_files: List[Path],
    *,
    accepted_path: Path = ACCEPTED,
    rejected_path: Path = REJECTED,
) -> Dict[str, int]:
    """Walk every file, prompt per candidate. Returns count summary."""
    counts: Dict[str, int] = {"accepted": 0, "rejected": 0, "skipped": 0}
    candidates: List[dict] = []
    for fp in source_files:
        candidates.extend(_iter_jsonl(fp))
    total = len(candidates)
    if total == 0:
        print("No candidates to review.")
        return counts

    print(f"Reviewing {total} candidates from {len(source_files)} source(s)…")
    for idx, c in enumerate(candidates, 1):
        _display(c, idx, total)
        while True:
            choice = input("[a]ccept / [r]eject / [s]kip / [q]uit: ").strip().lower()
            if choice in {"a", "r", "s", "q"}:
                break
            print("Unrecognised input; try again.")
        if choice == "q":
            print("Quitting; remaining candidates left in source files.")
            break
        if choice == "a":
            _append(accepted_path, c)
            counts["accepted"] += 1
        elif choice == "r":
            _append(rejected_path, c)
            counts["rejected"] += 1
        else:
            counts["skipped"] += 1

    return counts


def stats(source_files: List[Path]) -> None:
    """Print summary stats for all source JSONLs without prompting."""
    total = 0
    by_source: Counter = Counter()
    by_severity: Counter = Counter()
    by_category: Counter = Counter()
    for fp in source_files:
        for c in _iter_jsonl(fp):
            total += 1
            by_source[c.get("source", "?")] += 1
            by_severity[c.get("severity_guess", "?")] += 1
            by_category[c.get("category_guess", "?")] += 1
    print(f"Total candidates: {total}")
    print(f"By source:    {dict(by_source.most_common())}")
    print(f"By severity:  {dict(by_severity.most_common())}")
    print(f"By category:  {dict(by_category.most_common())}")


def auto_accept_by_source(
    source_files: List[Path],
    *,
    accepted_source: CandidateSource,
    accepted_path: Path = ACCEPTED,
) -> int:
    """Bulk-accept every candidate whose `source` matches."""
    accepted = 0
    for fp in source_files:
        for c in _iter_jsonl(fp):
            if c.get("source") == accepted_source.value:
                _append(accepted_path, c)
                accepted += 1
    return accepted


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files", nargs="*", type=Path,
        help="JSONL files to review (default: every *.jsonl in proposed_patterns/)",
    )
    parser.add_argument("--accepted", type=Path, default=ACCEPTED)
    parser.add_argument("--rejected", type=Path, default=REJECTED)
    parser.add_argument("--stats", action="store_true",
                        help="Print summary stats only, no interactive review")
    parser.add_argument("--auto-accept-source",
                        choices=[s.value for s in CandidateSource],
                        help="Bulk-accept every candidate of a given source")
    args = parser.parse_args(argv)

    source_files = args.files
    if not source_files:
        source_files = sorted(
            fp for fp in PROPOSED_DIR.glob("*.jsonl")
            if fp.name not in {"accepted.jsonl", "rejected.jsonl"}
        )
    if not source_files:
        print(f"No source JSONLs in {PROPOSED_DIR}/")
        return 0

    if args.stats:
        stats(source_files)
        return 0

    if args.auto_accept_source:
        n = auto_accept_by_source(
            source_files,
            accepted_source=CandidateSource(args.auto_accept_source),
            accepted_path=args.accepted,
        )
        print(f"Bulk-accepted {n} {args.auto_accept_source} candidates.")
        return 0

    summary = curate_interactive(
        source_files,
        accepted_path=args.accepted,
        rejected_path=args.rejected,
    )
    print()
    print(f"Done. accepted={summary['accepted']} "
          f"rejected={summary['rejected']} skipped={summary['skipped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
