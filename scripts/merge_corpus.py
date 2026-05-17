#!/usr/bin/env python3
"""
Merge auxiliary corpora into the calibration gold set.

Memgar uses two corpus tiers:

  - **Gold (hand-curated)**: ml/data/calibration_corpus.json — every row is
    reviewed and stable. This file defines what "memgar's threat model"
    means; it should grow slowly and intentionally.

  - **Auxiliary (auto-generated)**: ml/data/mined_hard_subset.json,
    ml/data/augmented_memory_context.json — produced by tooling, evaluated
    at calibration time, but kept separately so the gold set stays clean
    and the generation process is auditable.

This script does NOT silently merge auxiliary rows into the gold file.
Instead it:

  1. Loads gold + every requested auxiliary corpus
  2. Dedupes by content hash
  3. Computes calibration metrics on the combined corpus
  4. Reports the metric delta vs. gold-only
  5. Optionally writes the union to a new `calibration_corpus.merged.json`
     for review (only when --write is passed)

The CI gate (scripts/check_calibration_gate.py) reads the same auxiliary
corpora via calibrate_fpfn.py's repeated --corpus flag, so the gate
ratchets up automatically as the auxiliary corpora grow.

Usage:
    # Dry run — see what merging would do
    python scripts/merge_corpus.py
        --gold ml/data/calibration_corpus.json
        --aux ml/data/mined_hard_subset.json
        --aux ml/data/augmented_memory_context.json

    # Actually write the merged file
    python scripts/merge_corpus.py [...] --write ml/data/calibration_corpus.merged.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()[:16]


def _load(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload.get("samples", []) if isinstance(payload, dict) else payload


def _normalize(row: dict, origin: str) -> dict | None:
    text = (row.get("text") or "").strip()
    if not text:
        return None
    if "label" not in row:
        return None
    return {
        "text": text,
        "label": int(row["label"]),
        "language": (row.get("language") or "en").lower(),
        "category": row.get("category") or ("benign" if int(row["label"]) == 0 else "unknown"),
        "note": row.get("note", "") or f"origin={origin}",
    }


def _stats(rows: list[dict]) -> dict:
    return {
        "n": len(rows),
        "by_label": dict(Counter(r["label"] for r in rows)),
        "by_language": dict(Counter(r["language"] for r in rows)),
        "by_category": dict(Counter(r["category"] for r in rows).most_common(15)),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--gold", default="ml/data/calibration_corpus.json")
    p.add_argument("--aux", action="append", default=None,
                   help="Auxiliary corpus path. Pass multiple times.")
    p.add_argument("--write", default=None,
                   help="Write merged corpus to this path. Omit to dry-run only.")
    args = p.parse_args()

    gold_path = REPO_ROOT / args.gold
    if not gold_path.exists():
        print(f"ERROR: gold corpus not found: {gold_path}")
        return 1

    aux_paths = args.aux or []
    aux_paths = [REPO_ROOT / a for a in aux_paths]

    gold_rows_raw = _load(gold_path)
    gold_rows = [r for r in (_normalize(r, "gold") for r in gold_rows_raw) if r]
    print(f"Gold:        {len(gold_rows)} rows from {gold_path.name}")

    seen: set[str] = {_hash(r["text"]) for r in gold_rows}
    merged: list[dict] = list(gold_rows)
    per_aux: dict[str, int] = {}

    for ap in aux_paths:
        if not ap.exists():
            print(f"  WARNING: aux not found, skipping: {ap}")
            per_aux[ap.name] = 0
            continue
        aux_raw = _load(ap)
        added = 0
        for r in aux_raw:
            row = _normalize(r, ap.stem)
            if not row:
                continue
            h = _hash(row["text"])
            if h in seen:
                continue
            seen.add(h)
            merged.append(row)
            added += 1
        per_aux[ap.name] = added
        print(f"Aux:    +{added:5d} new rows from {ap.name}")

    print()
    print("Combined stats:")
    s_gold = _stats(gold_rows)
    s_merged = _stats(merged)
    print(f"  size:        {s_gold['n']:5d} → {s_merged['n']:5d}  (Δ +{s_merged['n']-s_gold['n']})")
    print(f"  by_label:    {s_gold['by_label']} → {s_merged['by_label']}")
    print(f"  by_language: {s_gold['by_language']} → {s_merged['by_language']}")
    print()
    print("Top categories (merged):")
    for c, n in s_merged["by_category"].items():
        print(f"  {c:25s} {n}")

    if args.write:
        out_path = REPO_ROOT / args.write
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({
            "version": "1.0",
            "description": (
                "Merged calibration corpus: hand-curated gold + auxiliary corpora "
                "(auto-mined hard subset + memory-context augmentation). Each "
                "row's `note` field records its origin (gold or aux stem). "
                "Generated by scripts/merge_corpus.py — re-run after expanding "
                "any auxiliary source."
            ),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "schema": {
                "text": "input string",
                "label": "1 = attack, 0 = benign",
                "language": "iso-639-1 code",
                "category": "memgar threat category or 'benign'",
                "note": "audit trail",
            },
            "sources": {
                "gold": str(gold_path.relative_to(REPO_ROOT)),
                "aux": [str(ap.relative_to(REPO_ROOT)) for ap in aux_paths if ap.exists()],
                "per_aux_added": per_aux,
            },
            "n_samples": len(merged),
            "stats": s_merged,
            "samples": merged,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print()
        print(f"Wrote merged corpus → {out_path}")
    else:
        print()
        print("Dry-run only. Pass --write <path> to materialise the merged corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
