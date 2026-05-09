"""
Expand the SimilarityLayer threat corpus (THREAT_EXAMPLES in embeddings.py).

Two sources:
  1. Diverse examples mined from training_data.json via greedy max-cosine-distance
     selection (picks examples that are maximally spread across the embedding
     space within each subcategory — avoids redundant near-duplicates).
  2. Adversarial variants of existing THREAT_EXAMPLES using AttackGenerator
     offline mutations (homoglyph, leetspeak, base64, passive rewrite).

Usage
-----
    python scripts/expand_threat_corpus.py                 # default settings
    python scripts/expand_threat_corpus.py --per-sub 8    # 8 examples/subcategory
    python scripts/expand_threat_corpus.py --dry-run       # print, don't patch
    python scripts/expand_threat_corpus.py --no-adversarial  # mining only

Result
------
  * Patches memgar/embeddings.py — appends new categories to THREAT_EXAMPLES
  * Saves ml/artifacts/corpus_expansion.json — audit trail
  * Prints before/after count
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("expand_corpus")

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "ml" / "data" / "training_data.json"
ARTIFACT_PATH = ROOT / "ml" / "artifacts" / "corpus_expansion.json"

# Subcategory → THREAT_EXAMPLES category mapping
# (subcategories not listed here get a new category named after the subcategory)
_SUB_TO_CAT: Dict[str, str] = {
    "financial_fraud":        "financial",
    "data_exfiltration":      "exfiltration",
    "identity_spoofing":      "manipulation",
    "confidence_bypass":      "paraphrase_authority",
    "prompt_injection_direct": "manipulation",
    "prompt_injection_subtle": "paraphrase_authority",
    "social_engineering":     "paraphrase_authority",
    "persistence":            "paraphrase_persistence",
    "code_injection":         "privilege",
    "privilege_escalation":   "privilege",
    "memory_tampering":       "behavior",
    "filter_bypass":          "paraphrase_authority",
    "roleplay_jailbreak":     "manipulation",
    "obfuscated":             "manipulation",
    "obfuscation_advanced":   "manipulation",
    "rag_poisoning":          "behavior",
    "hitl_bypass":            "paraphrase_authority",
    "supply_chain":           "behavior",
    "denial_of_wallet":       "paraphrase_financial",
    "multi_agent_attack":     "exfiltration",
    "multi_stage_payload":    "sleeper",
    "injection_prefix":       "manipulation",
    "websocket_attack":       "exfiltration",
    "ehr_attacks":            "exfiltration",
}


# ─────────────────────────────────────────────────────────────────
# Step 1: load + group training data
# ─────────────────────────────────────────────────────────────────

def load_attacks(path: Path) -> Dict[str, List[str]]:
    log.info("Loading %s …", path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    by_sub: Dict[str, List[str]] = defaultdict(list)
    for item in data:
        if item.get("label") != 1:
            continue
        sub = item.get("subcategory", "unknown")
        text = item["text"].strip()
        if text:
            by_sub[sub].append(text)
    log.info(
        "Loaded %d attack examples across %d subcategories",
        sum(len(v) for v in by_sub.values()),
        len(by_sub),
    )
    return dict(by_sub)


# ─────────────────────────────────────────────────────────────────
# Step 2: greedy diversity selection
# ─────────────────────────────────────────────────────────────────

def diverse_select(
    texts: List[str],
    model,
    n: int,
    seed_text: str | None = None,
) -> List[str]:
    """
    Greedy max-min cosine distance selection.

    Picks ``n`` texts from ``texts`` that are as spread-apart as possible
    in embedding space.  If ``seed_text`` is given, the first pick is the
    text most *similar* to the seed (so we stay on-topic), then we maximise
    distance from everything already selected.
    """
    import numpy as np

    if len(texts) <= n:
        return texts

    import random
    rng = random.Random(42)
    sample = rng.sample(texts, min(500, len(texts)))  # cap to 500 for speed

    embs = model.encode(
        sample,
        convert_to_numpy=True,
        normalize_embeddings=True,
        batch_size=64,
        show_progress_bar=False,
    )  # (M, D)

    selected_idx: List[int] = []

    if seed_text:
        seed_emb = model.encode(
            seed_text,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        sims = embs @ seed_emb
        selected_idx.append(int(np.argmax(sims)))
    else:
        selected_idx.append(0)

    while len(selected_idx) < n:
        sel_embs = embs[selected_idx]           # (K, D)
        # For each candidate, min similarity to any selected item
        sim_to_sel = embs @ sel_embs.T          # (M, K)
        min_sim = sim_to_sel.min(axis=1)         # (M,)
        # Mask already selected
        min_sim[selected_idx] = 2.0
        selected_idx.append(int(np.argmin(min_sim)))

    return [sample[i] for i in selected_idx]


def mine_examples(
    by_sub: Dict[str, List[str]],
    model,
    per_sub: int,
    existing: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    """Mine diverse examples per subcategory, deduplicated against existing."""
    from sentence_transformers import util
    import numpy as np

    # Build a set of existing example embeddings for dedup
    existing_texts = [t for texts in existing.values() for t in texts]
    if existing_texts:
        existing_embs = model.encode(
            existing_texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            batch_size=64,
            show_progress_bar=False,
        )
    else:
        existing_embs = None

    new_by_cat: Dict[str, List[str]] = defaultdict(list)
    total_added = 0

    for sub, texts in sorted(by_sub.items()):
        cat = _SUB_TO_CAT.get(sub, sub.replace("_", "_"))
        seed = existing.get(cat, [""])[0] if existing.get(cat) else None

        candidates = diverse_select(texts, model, n=per_sub * 3, seed_text=seed)

        # Dedup against existing
        if existing_embs is not None and len(candidates) > 0:
            cand_embs = model.encode(
                candidates,
                convert_to_numpy=True,
                normalize_embeddings=True,
                batch_size=64,
                show_progress_bar=False,
            )
            sims = cand_embs @ existing_embs.T   # (C, E)
            max_sim_to_existing = sims.max(axis=1)  # (C,)
            candidates = [
                c for c, s in zip(candidates, max_sim_to_existing) if s < 0.92
            ]

        kept = candidates[:per_sub]
        if kept:
            new_by_cat[cat].extend(kept)
            total_added += len(kept)
            log.info("  %-30s → cat=%-28s  +%d examples", sub, cat, len(kept))

    log.info("Mined %d new examples across %d categories", total_added, len(new_by_cat))
    return dict(new_by_cat)


# ─────────────────────────────────────────────────────────────────
# Step 3: adversarial variants of existing examples
# ─────────────────────────────────────────────────────────────────

def generate_adversarial(existing: Dict[str, List[str]]) -> Dict[str, List[str]]:
    sys.path.insert(0, str(ROOT))
    from ml.adversarial.attack_generator import AttackGenerator

    # api_key=None + offline_fallback=True → template mutations only (no network)
    gen = AttackGenerator(api_key=None, offline_fallback=True)
    adv_by_cat: Dict[str, List[str]] = defaultdict(list)

    for cat, texts in existing.items():
        # Take at most 5 seeds per category to avoid explosion
        seeds = [{"text": t, "category": cat} for t in texts[:5]]
        variants = gen.generate_variants(seeds, n_variants_per_seed=3)
        for v in variants:
            text = v.get("text", "").strip()
            if text:
                adv_by_cat[cat].append(text)

    total = sum(len(v) for v in adv_by_cat.values())
    log.info("Generated %d adversarial variants across %d categories", total, len(adv_by_cat))
    return dict(adv_by_cat)


# ─────────────────────────────────────────────────────────────────
# Step 4: patch embeddings.py
# ─────────────────────────────────────────────────────────────────

def merge_into_threat_examples(
    new_by_cat: Dict[str, List[str]],
    adv_by_cat: Dict[str, List[str]],
) -> Tuple[Dict[str, List[str]], int, int]:
    """
    Load current THREAT_EXAMPLES, merge new + adversarial, return updated dict.
    Deduplicates at the text level (exact match).
    """
    sys.path.insert(0, str(ROOT))
    from memgar.embeddings import THREAT_EXAMPLES

    merged = {k: list(v) for k, v in THREAT_EXAMPLES.items()}
    before = sum(len(v) for v in merged.values())

    for cat, texts in {**new_by_cat, **adv_by_cat}.items():
        existing_set = set(merged.get(cat, []))
        unique_new = [t for t in texts if t not in existing_set]
        if unique_new:
            merged.setdefault(cat, []).extend(unique_new)
            existing_set.update(unique_new)

    after = sum(len(v) for v in merged.values())
    return merged, before, after


def patch_embeddings_py(updated: Dict[str, List[str]]) -> None:
    target = ROOT / "memgar" / "embeddings.py"
    src = target.read_text(encoding="utf-8")

    # Find the THREAT_EXAMPLES dict block and replace it
    import re

    # Build new THREAT_EXAMPLES string
    lines = ["THREAT_EXAMPLES = {\n"]
    for cat, texts in sorted(updated.items()):
        lines.append(f'    "{cat}": [\n')
        for t in texts:
            escaped = t.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'        "{escaped}",\n')
        lines.append("    ],\n")
    lines.append("}\n")
    new_block = "".join(lines)

    # Replace from THREAT_EXAMPLES = { ... } to closing }
    pattern = re.compile(
        r"^THREAT_EXAMPLES\s*=\s*\{.*?^\}",
        re.MULTILINE | re.DOTALL,
    )
    if not pattern.search(src):
        raise RuntimeError("Could not locate THREAT_EXAMPLES in embeddings.py")

    new_src = pattern.sub(new_block.rstrip("\n"), src, count=1)
    target.write_text(new_src, encoding="utf-8")
    log.info("Patched embeddings.py with updated THREAT_EXAMPLES")


# ─────────────────────────────────────────────────────────────────
# Artifact
# ─────────────────────────────────────────────────────────────────

def save_artifact(
    new_by_cat: Dict[str, List[str]],
    adv_by_cat: Dict[str, List[str]],
    before: int,
    after: int,
) -> None:
    payload = {
        "expansion_date": time.strftime("%Y-%m-%d"),
        "before_count": before,
        "after_count": after,
        "added": after - before,
        "mined_by_category": {k: len(v) for k, v in new_by_cat.items()},
        "adversarial_by_category": {k: len(v) for k, v in adv_by_cat.items()},
    }
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ARTIFACT_PATH.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    log.info("Saved expansion artifact → %s", ARTIFACT_PATH)


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Expand SimilarityLayer threat corpus")
    parser.add_argument("--per-sub", type=int, default=6,
                        help="Diverse examples to mine per subcategory (default 6)")
    parser.add_argument("--no-adversarial", action="store_true",
                        help="Skip adversarial variant generation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be added without patching files")
    args = parser.parse_args()

    if not DATA_PATH.exists():
        log.error("Training data not found: %s", DATA_PATH)
        sys.exit(1)

    # Load model once
    log.info("Loading sentence-transformer model …")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")

    # Load current corpus
    sys.path.insert(0, str(ROOT))
    from memgar.embeddings import THREAT_EXAMPLES
    existing = dict(THREAT_EXAMPLES)
    current_count = sum(len(v) for v in existing.values())
    log.info("Current THREAT_EXAMPLES: %d examples across %d categories",
             current_count, len(existing))

    # Mine diverse examples from training data
    log.info("Mining diverse examples from training data …")
    by_sub = load_attacks(DATA_PATH)
    new_by_cat = mine_examples(by_sub, model, per_sub=args.per_sub, existing=existing)

    # Generate adversarial variants
    adv_by_cat: Dict[str, List[str]] = {}
    if not args.no_adversarial:
        log.info("Generating adversarial variants …")
        adv_by_cat = generate_adversarial(existing)

    # Merge
    updated, before, after = merge_into_threat_examples(new_by_cat, adv_by_cat)

    # Report
    print()
    print("=" * 65)
    print("THREAT CORPUS EXPANSION SUMMARY")
    print("=" * 65)
    print(f"  Before:  {before} examples")
    print(f"  Mined:  +{sum(len(v) for v in new_by_cat.values())} from training data")
    if adv_by_cat:
        print(f"  Adversarial: +{sum(len(v) for v in adv_by_cat.values())} variants")
    print(f"  After:   {after} examples  ({after - before:+d})")
    print()
    print("  New categories added:")
    for cat in sorted(set(updated) - set(existing)):
        print(f"    + {cat}  ({len(updated[cat])} examples)")
    print()
    print("  Existing categories expanded:")
    for cat in sorted(set(updated) & set(existing)):
        old = len(existing[cat])
        new = len(updated[cat])
        if new > old:
            print(f"    ~ {cat}: {old} → {new}  (+{new - old})")
    print("=" * 65)
    print()

    if args.dry_run:
        log.info("--dry-run: no files modified")
        return

    patch_embeddings_py(updated)
    save_artifact(new_by_cat, adv_by_cat, before, after)
    log.info("Done. Run calibrate_similarity.py to update thresholds.")


if __name__ == "__main__":
    main()
