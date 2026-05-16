#!/usr/bin/env python3
"""
Mine the most diagnostic samples from the public-corpus hard subset.

The full hard subset (`ml/data/external_corpus_hard.json`) contains 500+
rows — too many to merge into the calibration corpus blindly, and dumping
all of them would distort the CI gate (rare-edge attacks would dominate
ordinary signal). This tool produces a curated, deduped, prioritised
review queue plus an auto-curated subset that can be merged with high
confidence.

Selection logic, ordered by priority:

  1. **All false positives** — every FP is a real over-flagging case.
     Adding these as label=0 to the calibration corpus directly improves
     FPR without further review.

  2. **Top-N hardest false negatives per category** — the lowest
     risk_score FN within each threat category, deduped by TF-IDF cosine
     similarity to avoid clustering the corpus on near-duplicates.

  3. **Boundary cases** — risk_score in [20, 60). These are samples the
     model is uncertain on; valuable for calibration, riskier for direct
     merging (so kept as a separate `review` queue).

Output files (default paths):

  ml/data/mined_hard_subset.json    — auto-merge-safe selection (every FP +
                                       hardest-N FN per category, deduped)
  ml/data/mined_review_queue.json   — boundary cases for human review

Usage:
    python scripts/mine_hard_negatives.py
        [--hard-subset ml/data/external_corpus_hard.json]
        [--top-n-fn 5]
        [--similarity-threshold 0.85]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")


# ---------------------------------------------------------------------------
# Lightweight TF-IDF cosine dedup (no scikit-learn dependency required)
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize(text: str) -> list[str]:
    return [w.lower() for w in _WORD_RE.findall(text)]


def _tfidf_vectors(texts: list[str]) -> list[dict[str, float]]:
    """Return TF-IDF dicts per document. Sparse representation as {token: weight}."""
    import math
    docs = [_tokenize(t) for t in texts]
    n = len(docs)
    if n == 0:
        return []
    df: dict[str, int] = {}
    for doc in docs:
        for tok in set(doc):
            df[tok] = df.get(tok, 0) + 1
    idf = {tok: math.log((n + 1) / (1 + cnt)) + 1.0 for tok, cnt in df.items()}
    vectors: list[dict[str, float]] = []
    for doc in docs:
        if not doc:
            vectors.append({})
            continue
        tf: dict[str, int] = {}
        for tok in doc:
            tf[tok] = tf.get(tok, 0) + 1
        weights = {tok: (cnt / len(doc)) * idf.get(tok, 0.0) for tok, cnt in tf.items()}
        # L2 normalise so cosine = dot product
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        vectors.append({k: v / norm for k, v in weights.items()})
    return vectors


def _cosine(v1: dict[str, float], v2: dict[str, float]) -> float:
    if len(v1) > len(v2):
        v1, v2 = v2, v1
    return sum(w * v2.get(k, 0.0) for k, w in v1.items())


def _greedy_dedup(samples: list[dict], threshold: float) -> list[dict]:
    """Keep the first occurrence; drop any subsequent sample whose TF-IDF
    cosine to a kept sample exceeds `threshold`. O(n^2) but fine for n<2k."""
    if not samples:
        return []
    vectors = _tfidf_vectors([s["text"] for s in samples])
    kept: list[dict] = []
    kept_vecs: list[dict[str, float]] = []
    for s, v in zip(samples, vectors):
        if any(_cosine(v, kv) >= threshold for kv in kept_vecs):
            continue
        kept.append(s)
        kept_vecs.append(v)
    return kept


# ---------------------------------------------------------------------------
# Stratification
# ---------------------------------------------------------------------------

def _stratify_fn(fn_samples: list[dict], top_n_per_cat: int) -> list[dict]:
    """Group FN by category, keep top-N hardest (lowest risk_score) per category."""
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for s in fn_samples:
        by_cat[s.get("category", "unknown")].append(s)
    out: list[dict] = []
    for cat, items in by_cat.items():
        items_sorted = sorted(items, key=lambda x: x.get("risk_score") or 0.0)
        out.extend(items_sorted[:top_n_per_cat])
    return out


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

_AUTO_MERGE_SCHEMA = {
    "text": "input string",
    "label": "1 = attack, 0 = benign",
    "language": "iso-639-1 (en | tr | ...)",
    "category": "memgar threat category or 'benign'",
    "note": "audit trail: mining origin + source + risk_score at mine time",
}


def _normalize_for_merge(sample: dict, mining_reason: str) -> dict:
    """Strip transient fields (risk_score, decision) and add an audit-trail note."""
    base_note = sample.get("note", "")
    new_note = f"mined={mining_reason}; rs_at_mine={sample.get('risk_score')}"
    if base_note:
        new_note = f"{new_note}; {base_note}"
    return {
        "text": sample["text"],
        "label": int(sample["label"]),
        "language": sample.get("language", "en"),
        "category": sample.get("category", "unknown"),
        "note": new_note,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hard-subset", default="ml/data/external_corpus_hard.json")
    p.add_argument("--out-merge", default="ml/data/mined_hard_subset.json",
                   help="Auto-merge-safe rows (all FPs + top-N FN/category).")
    p.add_argument("--out-review", default="ml/data/mined_review_queue.json",
                   help="Boundary cases for human review (not auto-merged).")
    p.add_argument("--top-n-fn", type=int, default=5,
                   help="Hardest-N FN per threat category to auto-merge.")
    p.add_argument("--similarity-threshold", type=float, default=0.85,
                   help="TF-IDF cosine above which a sample is treated as duplicate.")
    p.add_argument("--max-merge-total", type=int, default=120,
                   help="Hard cap on auto-merge rows (defends against accidental flooding).")
    args = p.parse_args()

    hard_path = REPO_ROOT / args.hard_subset
    if not hard_path.exists():
        print(f"ERROR: hard subset not found: {hard_path}")
        print("Run first: python scripts/import_public_corpora.py")
        return 1

    payload = json.loads(hard_path.read_text(encoding="utf-8"))
    samples = payload.get("samples", [])
    fn = [s for s in samples if s.get("hard_reason") == "fn"]
    fp = [s for s in samples if s.get("hard_reason") == "fp"]
    boundary = [s for s in samples if s.get("hard_reason") == "boundary"]

    print(f"Input hard subset: {len(samples)} total ({len(fn)} FN, {len(fp)} FP, {len(boundary)} boundary)")
    print()

    # ---- Auto-merge: every FP + top-N FN/category, deduped --------------
    fn_top = _stratify_fn(fn, top_n_per_cat=args.top_n_fn)
    print(f"Top-{args.top_n_fn} FN per category: {len(fn_top)} (before dedup)")
    fn_top_dedup = _greedy_dedup(fn_top, threshold=args.similarity_threshold)
    print(f"  after dedup @ cosine>={args.similarity_threshold}: {len(fn_top_dedup)}")
    fp_dedup = _greedy_dedup(fp, threshold=args.similarity_threshold)
    print(f"All FPs after dedup: {len(fp_dedup)} (was {len(fp)})")

    merge_rows: list[dict] = []
    merge_rows.extend(_normalize_for_merge(s, "fp_all") for s in fp_dedup)
    merge_rows.extend(_normalize_for_merge(s, "fn_top_by_category") for s in fn_top_dedup)
    if len(merge_rows) > args.max_merge_total:
        print(f"  capping merge at {args.max_merge_total} (had {len(merge_rows)})")
        merge_rows = merge_rows[: args.max_merge_total]

    # ---- Review queue: boundary cases only (no auto-merge) --------------
    boundary_dedup = _greedy_dedup(boundary, threshold=args.similarity_threshold)
    review_rows: list[dict] = []
    for s in boundary_dedup:
        review_rows.append({
            **_normalize_for_merge(s, "boundary"),
            "_review_metadata": {
                "risk_score_at_mine": s.get("risk_score"),
                "hard_reason": s.get("hard_reason"),
                "decision": s.get("decision"),
            },
        })

    # ---- Write outputs --------------------------------------------------
    merge_path = REPO_ROOT / args.out_merge
    review_path = REPO_ROOT / args.out_review
    for path in (merge_path, review_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    n_fp = sum(1 for r in merge_rows if r["label"] == 0)
    n_fn = sum(1 for r in merge_rows if r["label"] == 1)
    merge_path.write_text(json.dumps({
        "version": "1.0",
        "description": (
            "Auto-merge-safe subset of the external corpus hard mining. Every "
            "FP (legitimate sample memgar over-flagged) is included; FN are "
            "capped at top-N hardest per category to prevent any single threat "
            "type from dominating the corpus. TF-IDF cosine dedup applied at "
            f"threshold={args.similarity_threshold}. These rows are appended "
            "to calibration_corpus.json via scripts/merge_corpus.py."
        ),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "schema": _AUTO_MERGE_SCHEMA,
        "n_samples": len(merge_rows),
        "breakdown": {"fp": n_fp, "fn_top": n_fn},
        "source": "ml/data/external_corpus_hard.json",
        "samples": merge_rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    review_path.write_text(json.dumps({
        "version": "1.0",
        "description": (
            "Boundary cases (risk_score in [20, 60)) extracted from the public "
            "corpus hard subset. These need human review before merging — they "
            "are samples the model is genuinely uncertain on, and adding them "
            "blindly could distort the calibration gate either way."
        ),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "schema": _AUTO_MERGE_SCHEMA,
        "n_samples": len(review_rows),
        "samples": review_rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print(f"Wrote {len(merge_rows)} auto-merge rows ({n_fp} FP, {n_fn} FN) → {merge_path}")
    print(f"Wrote {len(review_rows)} review rows → {review_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
