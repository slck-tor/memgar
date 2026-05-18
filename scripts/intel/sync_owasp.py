"""Sync OWASP Top-10-for-LLM (ASI) GitHub releases.

Source: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications

Watches for new release tags and emits a Candidate per release. The
release body tends to contain the official ASI category descriptions
(ASI01–ASI10), which the curator may want to bake into memgar's
pattern docstrings / `mitre_attack` mappings.

Low yield (2-5 releases per year) but high signal — these are
authoritative category definitions, not noise.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import (
    Candidate, CandidateSource, normalize_text, read_seen_fingerprints,
    request_get, write_candidates,
)

logger = logging.getLogger("memgar.intel.owasp")


GITHUB_RELEASES_API = (
    "https://api.github.com/repos/OWASP/"
    "www-project-top-10-for-large-language-model-applications/releases"
)


def _release_to_candidate(release: dict) -> Optional[Candidate]:
    tag = release.get("tag_name", "")
    body = release.get("body", "") or ""
    name = release.get("name", tag)
    if not tag:
        return None
    return Candidate(
        source=CandidateSource.OWASP_ASI,
        source_url=release.get("html_url", ""),
        source_id=tag,
        proposed_id=f"OWASP-ASI-{tag}",
        name=f"OWASP ASI release {tag}",
        description=normalize_text(name, max_len=120),
        severity_guess="high",        # category-level — curator decides per-pattern
        category_guess="injection",   # default; release usually spans multiple categories
        mitre_attack=None,
        keywords=[],
        examples=[],
        regex_proposals=[],
        sample_text=normalize_text(body, max_len=2000),
    )


def sync_owasp(
    *,
    output_path: Path = Path("proposed_patterns/owasp.jsonl"),
    dry_run: bool = False,
    github_token: Optional[str] = None,
    cached_json: Optional[Path] = None,
) -> int:
    if cached_json:
        logger.info("Reading cached releases JSON from %s", cached_json)
        releases = json.loads(cached_json.read_text())
    else:
        headers = {"Accept": "application/vnd.github+json"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        raw = request_get(GITHUB_RELEASES_API, headers=headers)
        releases = json.loads(raw)

    seen = read_seen_fingerprints(output_path)
    candidates: List[Candidate] = []
    for release in releases:
        cand = _release_to_candidate(release)
        if cand is None:
            continue
        candidates.append(cand)

    new_count = len([c for c in candidates if c.fingerprint not in seen])
    logger.info("Found %d OWASP releases, %d new", len(candidates), new_count)

    if dry_run:
        for c in candidates[:5]:
            logger.info(" • %s — %s", c.proposed_id, c.name)
        return len(candidates)

    return write_candidates(candidates, output_path, seen_fingerprints=seen)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("proposed_patterns/owasp.jsonl"))
    p.add_argument("--cached-json", type=Path, default=None)
    p.add_argument("--github-token", default=None,
                   help="GitHub token for higher rate limit")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    count = sync_owasp(
        output_path=args.output,
        github_token=args.github_token,
        dry_run=args.dry_run,
        cached_json=args.cached_json,
    )
    print(f"owasp sync: {count} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
