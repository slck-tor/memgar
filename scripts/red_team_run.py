#!/usr/bin/env python3
"""
Red-team adversarial loop runner.

Generates obfuscated attack variants from seed data, curates them,
injects into the continuous-learning pipeline, and optionally triggers
a full retrain with quality-gate validation.

Usage:
    python scripts/red_team_run.py                          # online + retrain
    python scripts/red_team_run.py --offline --dry-run      # CI-safe smoke test
    python scripts/red_team_run.py --n-seeds 20 --n-variants 8
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("red_team")


def load_seeds(data_path: Path, n: int, seed: int = 42) -> list[dict]:
    if not data_path.exists():
        logger.error("Training data not found: %s", data_path)
        return []
    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    attacks = [row for row in data if row.get("label") == 1]
    rng = random.Random(seed)
    return rng.sample(attacks, min(n, len(attacks)))


def main() -> int:
    parser = argparse.ArgumentParser(description="Memgar red-team adversarial loop")
    parser.add_argument("--n-seeds", type=int, default=10, help="Number of seed attacks to sample")
    parser.add_argument("--n-variants", type=int, default=5, help="Variants per seed")
    parser.add_argument("--data-path", default="ml/data/training_data.json")
    parser.add_argument("--dry-run", action="store_true", help="Generate but do not retrain")
    parser.add_argument("--offline", action="store_true", help="Force offline template mutations")
    parser.add_argument("--max-total", type=int, default=500, help="Max curated variants")
    parser.add_argument("--storage-path", default="ml/continuous_learning/storage")
    args = parser.parse_args()

    # 1. Load seeds
    seeds = load_seeds(Path(args.data_path), args.n_seeds)
    if not seeds:
        logger.error("No attack seeds found — aborting")
        return 1
    logger.info("Loaded %d seed attacks", len(seeds))

    # 2. Generate variants
    from ml.adversarial.attack_generator import AttackGenerator

    api_key = None if args.offline else None  # reads ANTHROPIC_API_KEY from env
    generator = AttackGenerator(
        api_key=api_key,
        offline_fallback=True,
    )
    if args.offline:
        # Monkeypatch to force offline path even if key is set
        generator._anthropic_available = False

    variants = generator.generate_variants(seeds, n_variants_per_seed=args.n_variants)
    logger.info("Generated %d raw variants", len(variants))

    # 3. Curate
    from ml.adversarial.variant_curator import VariantCurator

    curator = VariantCurator()
    curated = curator.curate(variants, max_total=args.max_total)
    logger.info("Curated down to %d unique variants", len(curated))

    if args.dry_run:
        print(json.dumps({"dry_run": True, "curated_count": len(curated)}, indent=2))
        return 0

    # 4. Inject into continuous-learning storage
    from ml.continuous_learning import AutoRetrainer, StorageManager

    storage = StorageManager(base_path=args.storage_path)
    retrainer = AutoRetrainer(storage=storage)
    written = retrainer.inject_adversarial_variants(curated)
    logger.info("Injected %d variants into storage", written)

    # 5. Retrain
    logger.info("Starting retrain (includes quality gate)…")
    result = retrainer.retrain(min_new_samples=0)  # 0 → always attempt
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
