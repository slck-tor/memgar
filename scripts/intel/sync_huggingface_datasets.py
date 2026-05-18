"""Sync gated HuggingFace datasets via the public datasets-server API.

Supported datasets:
  - allenai/wildjailbreak
  - JailbreakBench/JBB-Behaviors
  - TrustAIRLab/in-the-wild-jailbreak-prompts
  - deepset/prompt-injections

These are popular community-curated corpora that grow over time. We
poll them weekly via the public datasets-server endpoints (no auth
needed for ungated datasets; gated ones use `HF_TOKEN`).

To keep the candidate volume manageable, each run pulls at most
`max_rows_per_dataset` (default 100) and dedupes against previously-
seen fingerprints.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import (
    Candidate, CandidateSource, guess_severity, normalize_text,
    read_seen_fingerprints, request_get, write_candidates,
)

logger = logging.getLogger("memgar.intel.hf")


@dataclass(frozen=True)
class HFDataset:
    repo: str
    config: str = "default"
    split: str = "train"
    text_field: str = "prompt"
    gated: bool = False


DATASETS: List[HFDataset] = [
    HFDataset(repo="JailbreakBench/JBB-Behaviors", text_field="Goal"),
    HFDataset(repo="deepset/prompt-injections", text_field="text"),
    HFDataset(repo="allenai/wildjailbreak",
              config="train",
              split="train",
              text_field="adversarial",
              gated=True),
    HFDataset(repo="TrustAIRLab/in-the-wild-jailbreak-prompts",
              config="jailbreak_2023_12_25",
              text_field="prompt"),
]


def _datasets_server_url(ds: HFDataset, offset: int, length: int) -> str:
    return (
        f"https://datasets-server.huggingface.co/rows?"
        f"dataset={ds.repo}"
        f"&config={ds.config}"
        f"&split={ds.split}"
        f"&offset={offset}&length={length}"
    )


def _row_to_candidate(row: dict, ds: HFDataset) -> Optional[Candidate]:
    fields = row.get("row", {}) or row.get("fields", {})
    text = fields.get(ds.text_field) or fields.get("prompt") or fields.get("text")
    if not isinstance(text, str) or len(text.strip()) < 8:
        return None
    norm = normalize_text(text, max_len=400)
    severity = guess_severity(norm)
    return Candidate(
        source=CandidateSource.HUGGINGFACE,
        source_url=f"https://huggingface.co/datasets/{ds.repo}",
        source_id=f"{ds.repo}:{hash(norm) & 0xffffffff:08x}",
        proposed_id=f"HF-{ds.repo.split('/')[-1].upper().replace('-', '_')}",
        name=f"HF sample ({ds.repo})",
        description=f"Sample from {ds.repo} ({ds.split} split)",
        severity_guess=severity,
        category_guess="injection",
        keywords=[],
        examples=[norm[:80]],
        regex_proposals=[],
        sample_text=norm,
    )


def sync_huggingface(
    *,
    output_path: Path = Path("proposed_patterns/huggingface.jsonl"),
    max_rows_per_dataset: int = 100,
    dry_run: bool = False,
    hf_token: Optional[str] = None,
    datasets: Optional[List[HFDataset]] = None,
) -> int:
    datasets = datasets or DATASETS
    token = hf_token or os.environ.get("HF_TOKEN")
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    seen = read_seen_fingerprints(output_path)
    candidates: List[Candidate] = []

    for ds in datasets:
        if ds.gated and not token:
            logger.warning("Skipping gated %s: no HF_TOKEN", ds.repo)
            continue
        url = _datasets_server_url(ds, offset=0, length=max_rows_per_dataset)
        try:
            logger.info("Fetching %s", ds.repo)
            raw = request_get(url, headers=headers or None)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping %s: %s", ds.repo, exc)
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Bad JSON from %s: %s", ds.repo, exc)
            continue

        per_ds = 0
        for row in data.get("rows", []):
            cand = _row_to_candidate(row, ds)
            if cand is None:
                continue
            candidates.append(cand)
            per_ds += 1
        logger.info("  → %d candidates from %s", per_ds, ds.repo)

    new_count = len([c for c in candidates if c.fingerprint not in seen])
    logger.info("Total: %d candidates (%d new)", len(candidates), new_count)

    if dry_run:
        for c in candidates[:5]:
            logger.info(" • [%s] %s", c.severity_guess, c.sample_text[:60])
        return len(candidates)

    return write_candidates(candidates, output_path, seen_fingerprints=seen)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path,
                   default=Path("proposed_patterns/huggingface.jsonl"))
    p.add_argument("--max-rows-per-dataset", type=int, default=100)
    p.add_argument("--hf-token", default=None,
                   help="HuggingFace token (env: HF_TOKEN)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    count = sync_huggingface(
        output_path=args.output,
        max_rows_per_dataset=args.max_rows_per_dataset,
        hf_token=args.hf_token,
        dry_run=args.dry_run,
    )
    print(f"huggingface sync: {count} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
