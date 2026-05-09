"""
Threshold calibration for SimilarityLayer.

Usage
-----
    python scripts/calibrate_similarity.py                   # default 800 per class
    python scripts/calibrate_similarity.py --n 1500          # larger sample
    python scripts/calibrate_similarity.py --dry-run         # print report, don't save

What it does
------------
1. Loads ``ml/data/training_data.json`` (42 k labeled examples, label=1 attack).
2. Takes a stratified sample (n per class) and scores each text with SimilarityLayer.
3. Sweeps thresholds 0.30 → 0.95 (step 0.01) and computes precision, recall, F1.
4. Identifies:
   - ``threat_threshold``  — maximises F1
   - ``quarantine_threshold`` — precision ≥ 0.90 or first above F1-optimal
5. Saves calibration artefact to ``ml/artifacts/similarity_calibration.json``.
6. Prints a human-readable report and recommendation.

The output JSON can be consumed by SimilarityLayer at init time to replace the
hard-coded defaults (0.68 / 0.50).
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("calibrate")

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "ml" / "data" / "training_data.json"
ARTIFACT_PATH = ROOT / "ml" / "artifacts" / "similarity_calibration.json"

# ─────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────

def load_dataset(path: Path, n_per_class: int, seed: int = 42) -> list[dict]:
    """Return a stratified balanced sample from the training data."""
    log.info("Loading %s …", path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    positives = [x for x in data if x.get("label") == 1]
    negatives = [x for x in data if x.get("label") == 0]

    rng = random.Random(seed)
    pos_sample = rng.sample(positives, min(n_per_class, len(positives)))
    neg_sample = rng.sample(negatives, min(n_per_class, len(negatives)))

    log.info(
        "Sampled %d positives (attack) + %d negatives (benign) = %d total",
        len(pos_sample), len(neg_sample), len(pos_sample) + len(neg_sample),
    )
    return pos_sample + neg_sample


# ─────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────

def score_dataset(samples: list[dict]) -> list[dict]:
    """Score each sample with SimilarityLayer; return enriched dicts."""
    sys.path.insert(0, str(ROOT))
    from memgar.similarity_layer import SimilarityLayer

    log.info("Initialising SimilarityLayer (model load ~5-15 s) …")
    layer = SimilarityLayer()
    if not layer.available:
        raise RuntimeError(
            "SimilarityLayer not available — install: pip install sentence-transformers numpy"
        )

    log.info("Scoring %d examples …", len(samples))
    t0 = time.perf_counter()
    scored = []
    for i, item in enumerate(samples, 1):
        result = layer.score(item["text"])
        scored.append({
            "text": item["text"],
            "label": item["label"],
            "category": item.get("category", ""),
            "similarity": result.score,
            "latency_ms": result.latency_ms,
        })
        if i % 200 == 0:
            elapsed = time.perf_counter() - t0
            log.info(
                "  %d / %d scored  (%.1f s, %.1f ms/item)",
                i, len(samples), elapsed, elapsed / i * 1000,
            )

    total_ms = (time.perf_counter() - t0) * 1000
    log.info("Scoring done — %.0f ms total, avg %.2f ms/item", total_ms, total_ms / len(samples))
    return scored


# ─────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────

def compute_metrics_at_threshold(scored: list[dict], threshold: float) -> dict:
    tp = fp = fn = tn = 0
    for item in scored:
        pred = item["similarity"] >= threshold
        actual = item["label"] == 1
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    acc       = (tp + tn) / len(scored)

    return {
        "threshold": round(threshold, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(acc, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def sweep_thresholds(scored: list[dict], lo: float = 0.30, hi: float = 0.95, step: float = 0.01) -> list[dict]:
    thresholds = [lo + i * step for i in range(int((hi - lo) / step) + 1)]
    return [compute_metrics_at_threshold(scored, t) for t in thresholds]


# ─────────────────────────────────────────────────────────────────
# Optimal threshold selection
# ─────────────────────────────────────────────────────────────────

def select_thresholds(curve: list[dict]) -> dict:
    """
    Returns three calibrated profiles:

    strict    — max F1 threshold (highest recall, higher FPR; good for
                Analyzer ensemble where similarity is one of 9 signals)
    balanced  — precision ≥ 0.85, maximises F1 in that zone (reasonable
                standalone use; default for SimilarityLayer)
    precision — precision ≥ 0.92, minimises false positives (high-stakes
                environments where false blocks are costly)

    Each profile also carries a quarantine_threshold below the threat
    threshold (early-warning zone: elevated risk, not blocked outright).

    Invariant: quarantine_threshold < threat_threshold for all profiles.
    """
    best_f1_row = max(curve, key=lambda r: r["f1"])

    def _best_in_band(min_prec: float) -> dict:
        candidates = [r for r in curve if r["precision"] >= min_prec]
        return max(candidates, key=lambda r: r["f1"]) if candidates else best_f1_row

    def _quarantine_for(threat_t: float) -> float:
        below = [r for r in curve if r["threshold"] < threat_t and r["precision"] >= 0.55]
        if below:
            # use the F1-optimal point below threat — widest net with >55% precision
            return round(max(below, key=lambda r: r["f1"])["threshold"], 4)
        return round(max(0.10, threat_t - 0.10), 4)

    strict_row    = best_f1_row
    balanced_row  = _best_in_band(0.85)
    precision_row = _best_in_band(0.92)

    profiles = {
        "strict":    {
            "threat_threshold": round(strict_row["threshold"], 4),
            "quarantine_threshold": _quarantine_for(strict_row["threshold"]),
            "metrics": strict_row,
            "note": "max F1 — use inside Analyzer ensemble (one of 9 signals)",
        },
        "balanced": {
            "threat_threshold": round(balanced_row["threshold"], 4),
            "quarantine_threshold": _quarantine_for(balanced_row["threshold"]),
            "metrics": balanced_row,
            "note": "precision≥85% — default for standalone SimilarityLayer",
        },
        "precision": {
            "threat_threshold": round(precision_row["threshold"], 4),
            "quarantine_threshold": _quarantine_for(precision_row["threshold"]),
            "metrics": precision_row,
            "note": "precision≥92% — low-FP environments",
        },
    }

    return {
        "profiles": profiles,
        "recommended_default": "balanced",
        "best_f1": best_f1_row,
        # flat keys for backward compat with patch_similarity_layer
        "threat_threshold": profiles["balanced"]["threat_threshold"],
        "quarantine_threshold": profiles["balanced"]["quarantine_threshold"],
    }


# ─────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────

def print_report(curve: list[dict], selected: dict, n_pos: int, n_neg: int) -> None:
    profiles = selected["profiles"]
    marked_thresholds = {
        p["threat_threshold"]: name for name, p in profiles.items()
    }
    marked_thresholds.update({
        p["quarantine_threshold"]: f"{name}_quarantine" for name, p in profiles.items()
    })

    print()
    print("=" * 75)
    print("SIMILARITY LAYER THRESHOLD CALIBRATION REPORT")
    print("=" * 75)
    print(f"Dataset:  {n_pos} attacks  +  {n_neg} benign  =  {n_pos + n_neg} total")
    print()
    print(f"{'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FPR':>7}")
    print("-" * 60)

    STEP = 0.05
    for row in curve:
        t = row["threshold"]
        marker = ""
        for mt, label in marked_thresholds.items():
            if abs(t - mt) < 0.005:
                marker = f" ◄ {label.upper()}"
                break

        is_round = abs(round(t / STEP) * STEP - t) < 0.005
        if not marker and not is_round:
            continue

        print(
            f"  {t:>8.2f}  {row['precision']:>10.4f}  "
            f"{row['recall']:>8.4f}  {row['f1']:>8.4f}  {row['fpr']:>7.4f}{marker}"
        )

    print()
    print("CALIBRATED PROFILES")
    print("-" * 60)
    for name, p in profiles.items():
        m = p["metrics"]
        print(
            f"  {name:<12}  threat={p['threat_threshold']:.2f}  "
            f"quarantine={p['quarantine_threshold']:.2f}  "
            f"F1={m['f1']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  "
            f"FPR={m['fpr']:.3f}"
        )
        print(f"             → {p['note']}")

    default = selected["recommended_default"]
    dp = profiles[default]
    print()
    print(f"DEFAULT ('{default}') applied to similarity_layer.py:")
    print(f"  threat_threshold     = {dp['threat_threshold']}")
    print(f"  quarantine_threshold = {dp['quarantine_threshold']}")
    print("=" * 75)
    print()


# ─────────────────────────────────────────────────────────────────
# Artefact persistence
# ─────────────────────────────────────────────────────────────────

def save_artifact(scored: list[dict], curve: list[dict], selected: dict) -> None:
    n_pos = sum(1 for s in scored if s["label"] == 1)
    n_neg = sum(1 for s in scored if s["label"] == 0)

    payload = {
        "version": "1.1",
        "calibration_date": time.strftime("%Y-%m-%d"),
        "dataset": {
            "n_positive": n_pos,
            "n_negative": n_neg,
            "n_total": len(scored),
        },
        "recommended_default": selected["recommended_default"],
        "profiles": selected["profiles"],
        "applied": {
            "threat_threshold": selected["threat_threshold"],
            "quarantine_threshold": selected["quarantine_threshold"],
        },
        "best_f1_metrics": selected["best_f1"],
        "full_curve": curve,
        "score_histogram": _histogram(scored),
    }

    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ARTIFACT_PATH.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    log.info("Saved calibration artefact → %s", ARTIFACT_PATH)


def _histogram(scored: list[dict], bins: int = 20) -> dict:
    """Separate score histograms for positives and negatives."""
    step = 1.0 / bins
    edges = [round(i * step, 4) for i in range(bins + 1)]
    pos_counts = [0] * bins
    neg_counts = [0] * bins
    for item in scored:
        idx = min(int(item["similarity"] / step), bins - 1)
        if item["label"] == 1:
            pos_counts[idx] += 1
        else:
            neg_counts[idx] += 1
    return {
        "edges": edges,
        "attack": pos_counts,
        "benign": neg_counts,
    }


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Calibrate SimilarityLayer thresholds")
    parser.add_argument("--n", type=int, default=800,
                        help="Samples per class (default 800; more = slower but more accurate)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print report but do not save artifact or patch similarity_layer.py")
    parser.add_argument("--lo", type=float, default=0.20)
    parser.add_argument("--hi", type=float, default=0.95)
    args = parser.parse_args()

    if not DATA_PATH.exists():
        log.error("Training data not found: %s", DATA_PATH)
        sys.exit(1)

    samples = load_dataset(DATA_PATH, n_per_class=args.n, seed=args.seed)
    scored = score_dataset(samples)
    curve = sweep_thresholds(scored, lo=args.lo, hi=args.hi)
    selected = select_thresholds(curve)

    n_pos = sum(1 for s in scored if s["label"] == 1)
    n_neg = sum(1 for s in scored if s["label"] == 0)
    print_report(curve, selected, n_pos, n_neg)

    if not args.dry_run:
        save_artifact(scored, curve, selected)
        patch_similarity_layer(selected)
    else:
        log.info("--dry-run: skipping artefact save and source patch")


def patch_similarity_layer(selected: dict) -> None:
    """Update the default thresholds in similarity_layer.py from calibration results."""
    target = ROOT / "memgar" / "similarity_layer.py"
    src = target.read_text(encoding="utf-8")

    threat_t = selected["threat_threshold"]
    quaran_t = selected["quarantine_threshold"]

    import re

    # Replace the default argument values in the __init__ signature
    src = re.sub(
        r"(threat_threshold\s*:\s*float\s*=\s*)[0-9.]+",
        lambda m: m.group(1) + str(threat_t),
        src,
    )
    src = re.sub(
        r"(quarantine_threshold\s*:\s*float\s*=\s*)[0-9.]+",
        lambda m: m.group(1) + str(quaran_t),
        src,
    )

    target.write_text(src, encoding="utf-8")
    log.info(
        "Patched similarity_layer.py → threat_threshold=%s, quarantine_threshold=%s",
        threat_t, quaran_t,
    )


if __name__ == "__main__":
    main()
