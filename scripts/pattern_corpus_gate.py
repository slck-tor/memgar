#!/usr/bin/env python3
"""Run Memgar pattern corpus quality gates."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memgar.pattern_corpus import PatternQualityGateProfile, run_pattern_corpus_gate


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Memgar pattern corpus governance gates")
    parser.add_argument("--min-recall", type=float, default=0.80)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--min-vector-coverage", type=int, default=16)
    parser.add_argument("--risk-threshold", type=int, default=50)
    parser.add_argument("--include-variants", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON report")
    args = parser.parse_args(argv)

    profile = PatternQualityGateProfile(
        min_attack_recall=args.min_recall,
        max_false_positive_rate=args.max_fpr,
        min_vector_coverage=args.min_vector_coverage,
        risk_threshold=args.risk_threshold,
        include_variants=args.include_variants,
    )
    result = run_pattern_corpus_gate(profile=profile)

    if args.json:
        print(result.to_json())
    else:
        status = "PASSED" if result.passed else "FAILED"
        print(f"Pattern corpus gate: {status}")
        print(f"Patterns: {result.library.total_patterns}")
        print(f"Regexes: {result.library.regex_count}")
        print(f"Attack recall: {result.evaluation.attack_recall:.1%}")
        print(f"False positive rate: {result.evaluation.false_positive_rate:.1%}")
        print("Recommendations:")
        for item in result.recommendations:
            print(f"- {item}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
