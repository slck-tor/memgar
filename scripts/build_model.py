#!/usr/bin/env python3
"""
Build (or rebuild) the ML threat detection model.

Usage:
    python scripts/build_model.py                        # default paths
    python scripts/build_model.py --data path/data.json  # custom data
    python scripts/build_model.py --out path/model.pkl   # custom output

Exit codes:
    0  — success
    1  — training data not found or training failed
"""

import argparse
import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_DATA = ROOT / "ml" / "data" / "training_data.json"
DEFAULT_OUT = ROOT / "ml" / "artifacts" / "gradient_boost_model.pkl"


def build(data_path: Path, out_path: Path) -> bool:
    if not data_path.exists():
        print(f"[build_model] ERROR: training data not found: {data_path}", file=sys.stderr)
        return False

    try:
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import accuracy_score, f1_score
        from sklearn.model_selection import train_test_split
    except ImportError as e:
        print(f"[build_model] ERROR: missing ML dependency — {e}", file=sys.stderr)
        print("[build_model] Run: pip install numpy scikit-learn", file=sys.stderr)
        return False

    try:
        from ml.training.ml_feature_extractor import MLFeatureExtractor
    except ImportError as e:
        print(f"[build_model] ERROR: cannot import feature extractor — {e}", file=sys.stderr)
        return False

    print(f"[build_model] Loading training data: {data_path}")
    with open(data_path) as f:
        data = json.load(f)

    texts = [d["text"] for d in data]
    labels = [d["label"] for d in data]
    y = np.array(labels)
    attacks = int(y.sum())
    print(f"[build_model] {len(texts)} examples  ({attacks} attacks, {len(texts)-attacks} legitimate)")

    print("[build_model] Extracting features …")
    extractor = MLFeatureExtractor()
    X = np.vstack([extractor.extract(t).to_numpy() for t in texts])
    print(f"[build_model] Feature matrix: {X.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[build_model] Training GradientBoostingClassifier …")
    model = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f"[build_model] Test accuracy: {acc:.4f}  F1: {f1:.4f}")

    if acc < 0.95:
        print(f"[build_model] WARNING: accuracy {acc:.4f} is below 0.95 threshold", file=sys.stderr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(model, f)

    size_kb = out_path.stat().st_size // 1024
    print(f"[build_model] Model saved: {out_path}  ({size_kb} KB)")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Build memgar ML model")
    parser.add_argument("--data", default=str(DEFAULT_DATA), help="Path to training_data.json")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output path for .pkl model")
    args = parser.parse_args()

    ok = build(Path(args.data), Path(args.out))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
