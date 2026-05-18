"""Sync public LLM jailbreak corpus repositories.

Sources (curated list — solid signal-to-noise ratio):

  - liu00222/Open-Prompt-Injection            — Academic IPI dataset
  - tegridydev/llm-jailbreak-prompts          — Curated jailbreaks
  - 0xeb/Awesome-LLM-jailbreaks                — Known-jailbreak survey
  - lm-sys/FastChat (prompt-injection subset)  — Vicuna-era data

These repos publish either:
  (a) JSON/JSONL files with `{"prompt": "...", "category": "..."}` rows
  (b) Markdown lists with bullet-style examples
  (c) Plain text dumps

The sync script normalises each into a stream of `Candidate` records.
Curator decides which need new patterns vs which are already covered.

Output goes to `proposed_patterns/jailbreak_repos.jsonl`.

This is the noisiest sourcing channel — expect 50-200 candidates per
run, most duplicates of existing patterns. The dedup uses both:
  - fingerprint set (already-seen)
  - regex pre-check against `memgar/patterns.py` keywords / examples
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import (
    Candidate, CandidateSource, guess_severity, normalize_text,
    read_seen_fingerprints, request_get, write_candidates,
)

logger = logging.getLogger("memgar.intel.jailbreak")


@dataclass(frozen=True)
class JailbreakSource:
    name: str
    raw_url: str
    format: str          # "jsonl" | "json_array" | "text_bullets"
    license: str = "unknown"


# Curated source list — narrow by design. Adding a new source is a
# manual decision (the curator reviews the repo's quality first).
SOURCES: List[JailbreakSource] = [
    JailbreakSource(
        name="open-prompt-injection",
        raw_url=("https://raw.githubusercontent.com/liu00222/"
                 "Open-Prompt-Injection/main/data/injected_test.json"),
        format="json_array",
        license="MIT",
    ),
    JailbreakSource(
        name="jailbreakbench-judges",
        raw_url=("https://raw.githubusercontent.com/JailbreakBench/"
                 "jailbreakbench/main/data/behaviors.json"),
        format="json_array",
        license="MIT",
    ),
    JailbreakSource(
        name="trustllm-prompts",
        raw_url=("https://raw.githubusercontent.com/HowieHwong/"
                 "TrustLLM/main/data/safety/jailbreak.json"),
        format="json_array",
        license="Apache-2.0",
    ),
    JailbreakSource(
        name="lakera-gandalf-ignore-instructions",
        raw_url=("https://huggingface.co/datasets/Lakera/"
                 "gandalf_ignore_instructions/resolve/main/data.json"),
        format="json_array",
        license="MIT",
    ),
]


def _extract_text_from_row(row: dict) -> Optional[str]:
    """Try common field names. Returns None for unusable rows."""
    for key in ("prompt", "goal", "input", "text", "behavior",
                "jailbreak", "attack", "content"):
        v = row.get(key)
        if isinstance(v, str) and len(v.strip()) >= 8:
            return v.strip()
    return None


def _category_for(text: str) -> str:
    """Best-effort category mapping from the prompt's lexical signals."""
    lower = text.lower()
    if any(k in lower for k in ("ignore", "forget", "override", "previous instruction")):
        return "injection"
    if any(k in lower for k in ("dan", "developer mode", "roleplay", "pretend")):
        return "behavior"
    if any(k in lower for k in ("password", "credential", "api key", "secret")):
        return "credential"
    if any(k in lower for k in ("transfer", "payment", "wire", "bank")):
        return "financial"
    return "social"


def _parse_source(source: JailbreakSource, raw: bytes) -> List[dict]:
    text = raw.decode("utf-8", errors="ignore")
    if source.format == "jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if source.format == "json_array":
        data = json.loads(text)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            # Sometimes wrapped: {"data": [...]} or {"results": [...]}
            for key in ("data", "results", "items", "rows"):
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
        return []
    if source.format == "text_bullets":
        out: List[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("-", "*", "•")) and len(line) > 6:
                out.append({"prompt": line.lstrip("-*• ").strip()})
        return out
    return []


def _sample_to_candidate(
    sample_text: str,
    source: JailbreakSource,
) -> Optional[Candidate]:
    norm = normalize_text(sample_text, max_len=400)
    if len(norm) < 8:
        return None
    severity = guess_severity(norm)
    category = _category_for(norm)
    short_name = (norm[:60] + "…") if len(norm) > 60 else norm
    return Candidate(
        source=CandidateSource.JAILBREAK_REPO,
        source_url=source.raw_url,
        source_id=f"{source.name}:{hash(norm) & 0xffffffff:08x}",
        proposed_id=f"COMMUNITY-{source.name.upper().replace('-', '_')}",
        name=f"Community sample ({source.name})",
        description=f"Prompt-injection / jailbreak sample from {source.name}",
        severity_guess=severity,
        category_guess=category,
        keywords=[],
        examples=[short_name],
        regex_proposals=[],
        sample_text=norm,
    )


def sync_jailbreak_repos(
    *,
    output_path: Path = Path("proposed_patterns/jailbreak_repos.jsonl"),
    max_per_source: int = 50,
    dry_run: bool = False,
    sources: Optional[List[JailbreakSource]] = None,
) -> int:
    sources = sources or SOURCES
    seen = read_seen_fingerprints(output_path)
    candidates: List[Candidate] = []

    for source in sources:
        try:
            logger.info("Fetching %s", source.raw_url)
            raw = request_get(source.raw_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping %s: %s", source.name, exc)
            continue

        rows = _parse_source(source, raw)
        per_source = 0
        for row in rows:
            text = _extract_text_from_row(row)
            if text is None:
                continue
            cand = _sample_to_candidate(text, source)
            if cand is None:
                continue
            candidates.append(cand)
            per_source += 1
            if per_source >= max_per_source:
                break
        logger.info("  → %d candidates from %s", per_source, source.name)

    new_count = len([c for c in candidates if c.fingerprint not in seen])
    logger.info("Total candidates: %d (%d new)", len(candidates), new_count)

    if dry_run:
        for c in candidates[:5]:
            logger.info(" • %s — %s", c.severity_guess, c.sample_text[:60])
        return len(candidates)

    return write_candidates(candidates, output_path, seen_fingerprints=seen)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path,
                   default=Path("proposed_patterns/jailbreak_repos.jsonl"))
    p.add_argument("--max-per-source", type=int, default=50)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    count = sync_jailbreak_repos(
        output_path=args.output,
        max_per_source=args.max_per_source,
        dry_run=args.dry_run,
    )
    print(f"jailbreak-repos sync: {count} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
