#!/usr/bin/env python3
"""
End-to-end FP/FN calibration for the full Memgar Analyzer.

Why this exists
---------------
``ml/artifacts/similarity_calibration.json`` only calibrates the standalone
SimilarityLayer (one of nine signals) on an English-only corpus. The final
``Decision`` is produced by ``Analyzer.analyze()`` with risk_score thresholds
that have never had a published FP/FN table — especially for non-English
content. This script closes that gap.

What it does
------------
1. Loads a labeled corpus (default: ``ml/data/calibration_corpus.json``)
   containing ``text``, ``label`` (1 = attack, 0 = benign) and ``language``.
2. Runs the full ``Analyzer`` pipeline on every sample.
3. Builds:
   - A risk_score sweep (P / R / F1 / FPR / accuracy at thresholds 0..100).
   - Per-language breakdown (e.g. tr vs en).
   - Per-category recall breakdown (so you see which attack families leak).
   - Recommended thresholds for ``strict`` / ``balanced`` / ``lenient``
     profiles, picked from the sweep.
4. Writes a JSON report to ``ml/artifacts/fpfn_calibration.json`` and prints
   a short markdown summary.

Usage
-----
    python scripts/calibrate_fpfn.py
    python scripts/calibrate_fpfn.py --corpus path/to/my_corpus.json
    python scripts/calibrate_fpfn.py --output reports/fpfn.json --no-llm
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import statistics
import sys
import time
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Quiet third-party progress bars so the stdout summary stays readable.
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
warnings.filterwarnings("ignore", category=DeprecationWarning)
for _noisy in ("sentence_transformers", "transformers", "huggingface_hub", "httpx"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("calibrate_fpfn")


def _load_corpus(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    samples = payload.get("samples", payload) if isinstance(payload, dict) else payload
    if not samples:
        raise ValueError(f"No samples found in {path}")
    for row in samples:
        if "text" not in row or "label" not in row:
            raise ValueError(
                "Every sample must have 'text' and 'label' keys; "
                f"offending row: {row}"
            )
    return samples


def _metrics_at(threshold: int, scores: list[tuple[int, int]]) -> dict[str, float]:
    """
    Compute classification metrics where prediction = risk_score >= threshold.

    scores: list of (risk_score, true_label) tuples.
    """
    tp = fp = tn = fn = 0
    for score, label in scores:
        pred = 1 if score >= threshold else 0
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    fpr = fp / max(fp + tn, 1)
    accuracy = (tp + tn) / max(tp + fp + tn + fn, 1)
    return {
        "threshold": threshold,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def _recommend_profile(curve: list[dict], *, name: str, **constraints) -> dict | None:
    """
    Pick the best threshold meeting all `constraints` (e.g. min_precision=0.9).
    Optimises F1 within the feasible region. Returns None if no threshold qualifies.
    """
    candidates = []
    for row in curve:
        ok = True
        for key, target in constraints.items():
            metric = key.replace("min_", "").replace("max_", "")
            val = row[metric]
            if key.startswith("min_") and val < target:
                ok = False
                break
            if key.startswith("max_") and val > target:
                ok = False
                break
        if ok:
            candidates.append(row)
    if not candidates:
        return None
    best = max(candidates, key=lambda r: (r["f1"], r["recall"]))
    return {"profile": name, "constraints": constraints, **best}


def _decision_block_rate(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    return sum(1 for r in rows if r["decision"] == "block") / len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--corpus",
        default=None,
        action="append",
        help=(
            "Path to a labeled corpus JSON. Pass multiple times to evaluate "
            "on a merged corpus (e.g. --corpus a.json --corpus b.json). "
            "Defaults to ml/data/calibration_corpus.json. Useful for layering "
            "hand-curated gold with auto-mined or augmented corpora."
        ),
    )
    parser.add_argument(
        "--output",
        default="ml/artifacts/fpfn_calibration.json",
        help="Output path for the calibration report JSON",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force use_llm=False (default; pass --use-llm to enable Layer 2)",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enable Layer 2 LLM analysis (costs API tokens)",
    )
    parser.add_argument(
        "--step",
        type=int,
        default=2,
        help="Threshold sweep step size (default: 2)",
    )
    args = parser.parse_args()

    use_llm = bool(args.use_llm) and not args.no_llm

    # argparse with action="append" stays None when nothing is passed, since
    # the `default=` is overridden on first --corpus. Restore default when empty.
    corpus_args = args.corpus or ["ml/data/calibration_corpus.json"]
    corpus_paths = [(ROOT / c) if not Path(c).is_absolute() else Path(c) for c in corpus_args]
    samples: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    for cp in corpus_paths:
        rows = _load_corpus(cp)
        kept = 0
        for r in rows:
            key = (r.get("text") or "").strip().lower()
            if not key or key in seen_text:
                continue
            seen_text.add(key)
            samples.append(r)
            kept += 1
        logger.info("Loaded %d new samples from %s (dedup applied)", kept, cp)
    corpus_path = corpus_paths[0]  # primary corpus for report metadata
    logger.info("Merged corpus size: %d samples across %d files", len(samples), len(corpus_paths))

    # Build Analyzer
    from memgar.analyzer import Analyzer
    from memgar.models import MemoryEntry

    analyzer = Analyzer(use_llm=use_llm)
    health = analyzer.health_check()
    logger.info(
        "Analyzer health: %s (layer1.5=%s)",
        health["status"],
        health["layers"]["layer1_5_semantic_guard"].get("status"),
    )

    # Score every sample
    rows: list[dict[str, Any]] = []
    t0 = time.perf_counter()
    for i, row in enumerate(samples):
        entry = MemoryEntry(content=row["text"])
        try:
            res = analyzer.analyze(entry)
        except Exception as e:
            logger.warning("Analyzer crashed on sample %d (%s): %s", i, row.get("category"), e)
            continue
        rows.append({
            "text": row["text"][:120],
            "label": int(row["label"]),
            "language": row.get("language", "unknown"),
            "category": row.get("category", "unknown"),
            "risk_score": int(res.risk_score),
            "decision": res.decision.value,
            "layers_used": list(res.layers_used or []),
            "analysis_time_ms": round(res.analysis_time_ms, 2),
        })

    elapsed = time.perf_counter() - t0
    logger.info("Scored %d samples in %.2fs (%.1f ms/sample)",
                len(rows), elapsed, 1000 * elapsed / max(len(rows), 1))

    score_label_pairs = [(r["risk_score"], r["label"]) for r in rows]

    # Threshold sweep across risk_score 0..100
    curve = [_metrics_at(t, score_label_pairs) for t in range(0, 101, args.step)]

    # Per-language breakdown at the analyzer's actual decisions
    per_lang: dict[str, dict] = defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for r in rows:
        lang = r["language"]
        bucket = per_lang[lang]
        bucket["n"] += 1
        # Decision-based confusion (block = positive prediction)
        pred = 1 if r["decision"] == "block" else 0
        if pred == 1 and r["label"] == 1:
            bucket["tp"] += 1
        elif pred == 1 and r["label"] == 0:
            bucket["fp"] += 1
        elif pred == 0 and r["label"] == 0:
            bucket["tn"] += 1
        else:
            bucket["fn"] += 1
    for lang, b in per_lang.items():
        tp, fp, tn, fn = b["tp"], b["fp"], b["tn"], b["fn"]
        b["precision"] = round(tp / max(tp + fp, 1), 4)
        b["recall"] = round(tp / max(tp + fn, 1), 4)
        b["fpr"] = round(fp / max(fp + tn, 1), 4)

    # Per-category recall (attack samples only)
    per_cat: dict[str, dict] = defaultdict(lambda: {"n": 0, "blocked": 0, "missed_examples": []})
    for r in rows:
        if r["label"] != 1:
            continue
        cat = r["category"]
        per_cat[cat]["n"] += 1
        if r["decision"] == "block":
            per_cat[cat]["blocked"] += 1
        elif len(per_cat[cat]["missed_examples"]) < 3:
            per_cat[cat]["missed_examples"].append({
                "text": r["text"],
                "risk_score": r["risk_score"],
                "decision": r["decision"],
            })
    for cat, c in per_cat.items():
        c["recall"] = round(c["blocked"] / max(c["n"], 1), 4)

    # Recommended thresholds
    recommendations = {
        "strict": _recommend_profile(curve, name="strict", min_recall=0.95),
        "balanced": _recommend_profile(curve, name="balanced", min_precision=0.85, min_recall=0.80),
        "precision": _recommend_profile(curve, name="precision", min_precision=0.95),
    }

    # Score distribution summary
    benign_scores = [r["risk_score"] for r in rows if r["label"] == 0]
    attack_scores = [r["risk_score"] for r in rows if r["label"] == 1]

    def _summary(scores: list[int]) -> dict:
        if not scores:
            return {"n": 0}
        return {
            "n": len(scores),
            "mean": round(statistics.mean(scores), 2),
            "median": int(statistics.median(scores)),
            "p90": int(sorted(scores)[int(0.9 * (len(scores) - 1))]),
            "p99": int(sorted(scores)[int(0.99 * (len(scores) - 1))]),
            "min": min(scores),
            "max": max(scores),
        }

    report = {
        "version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_path": str(corpus_path),
        "n_samples": len(rows),
        "n_attack": sum(1 for r in rows if r["label"] == 1),
        "n_benign": sum(1 for r in rows if r["label"] == 0),
        "use_llm": use_llm,
        "analyzer_health": health,
        "score_distribution": {
            "benign": _summary(benign_scores),
            "attack": _summary(attack_scores),
        },
        "analyzer_default_metrics": {
            "block_rate_overall": round(_decision_block_rate(rows), 4),
            "block_rate_attack": round(
                _decision_block_rate([r for r in rows if r["label"] == 1]), 4
            ),
            "block_rate_benign": round(
                _decision_block_rate([r for r in rows if r["label"] == 0]), 4
            ),
        },
        "threshold_sweep": curve,
        "per_language": dict(per_lang),
        "per_category_recall": dict(per_cat),
        "recommended_thresholds": recommendations,
        "latency_ms": {
            "p50": round(statistics.median([r["analysis_time_ms"] for r in rows]), 2),
            "p95": round(sorted([r["analysis_time_ms"] for r in rows])[int(0.95 * (len(rows) - 1))], 2),
        },
    }

    output_path = (ROOT / args.output) if not Path(args.output).is_absolute() else Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Calibration report saved to %s", output_path)

    # Pretty stdout summary
    print()
    print("=" * 72)
    print(f"FP/FN Calibration  —  {report['n_samples']} samples "
          f"({report['n_attack']} attack, {report['n_benign']} benign)")
    print("=" * 72)
    print(f"Analyzer health   : {health['status']}")
    print(f"Layer 1.5 status  : {health['layers']['layer1_5_semantic_guard'].get('status')}")
    print()
    print("At default Analyzer thresholds (Decision.block):")
    m = report["analyzer_default_metrics"]
    print(f"  recall on attacks : {m['block_rate_attack']:.3f}")
    print(f"  FP rate on benign : {m['block_rate_benign']:.3f}")
    print()
    print("Per-language (decision-based):")
    for lang, b in sorted(per_lang.items()):
        print(f"  {lang:6}  n={b['n']:3}  precision={b['precision']:.3f}  "
              f"recall={b['recall']:.3f}  FPR={b['fpr']:.3f}")
    print()
    print("Per-category recall (attack samples):")
    for cat, c in sorted(per_cat.items()):
        print(f"  {cat:20}  n={c['n']:3}  recall={c['recall']:.3f}")
    print()
    print("Recommended risk_score thresholds:")
    for name, rec in recommendations.items():
        if rec is None:
            print(f"  {name:10}  (no threshold satisfies the constraints — corpus too small or model too weak)")
        else:
            print(f"  {name:10}  threshold={rec['threshold']:3}  "
                  f"P={rec['precision']:.3f}  R={rec['recall']:.3f}  "
                  f"F1={rec['f1']:.3f}  FPR={rec['fpr']:.3f}")
    print()
    print(f"Full report: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
