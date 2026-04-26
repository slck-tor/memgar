"""Maintainer tool: sign and package a threat-intelligence feed bundle.

Usage
-----
    python scripts/publish_feed.py \
        --patterns-file memgar/patterns.py \
        --private-key-file feed_private.pem \
        --output-dir dist/ \
        [--feed-version 1.2.3] \
        [--min-memgar-version 0.5.0]

The script:
  1. Parses PATTERNS from the given patterns file (or memgar/patterns.py by
     default) and serialises them to canonical JSON.
  2. Computes SHA-256 of the canonical bundle.
  3. Signs the bundle bytes with the Ed25519 private key loaded from the PEM
     file.
  4. Writes  dist/memgar-feed.json.gz  (gzip-compressed JSON bundle ready for
     a GitHub Release asset).
  5. Prints the matching public key in base64 so the maintainer can update
     FEED_PUBLIC_KEY_B64 in memgar/feed/verifier.py.

Requires: cryptography>=41.0.0   (pip install 'memgar[feed]')
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_patterns_from_file(patterns_file: Path) -> list:
    """Import PATTERNS from an arbitrary .py file without modifying sys.path."""
    spec = importlib.util.spec_from_file_location("_patterns_module", patterns_file)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load {patterns_file}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    patterns = getattr(mod, "PATTERNS", None)
    if patterns is None:
        raise AttributeError(f"No PATTERNS attribute found in {patterns_file}")
    return list(patterns)


def _pattern_to_dict(p: object) -> dict:
    """Convert a Threat dataclass (or plain dict) to a JSON-serialisable dict."""
    if isinstance(p, dict):
        return p
    try:
        d = asdict(p)  # type: ignore[arg-type]
    except TypeError:
        d = p.__dict__.copy()  # type: ignore[attr-defined]
    # Convert enum values to their string representation.
    for key, val in list(d.items()):
        if hasattr(val, "value"):
            d[key] = val.value
    return d


def _canonical_bytes(patterns: list) -> bytes:
    """Produce deterministic JSON bytes (matches PatternBundle.bundle_bytes())."""
    dicts = [_pattern_to_dict(p) for p in patterns]
    return json.dumps(dicts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_bundle(bundle_bytes: bytes, private_key_path: Path) -> tuple[str, str]:
    """Sign *bundle_bytes* with an Ed25519 PEM private key.

    Returns (signature_b64, public_key_b64).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
            load_pem_private_key,
        )
    except ImportError as exc:
        print(
            "ERROR: 'cryptography' is required. Install with: pip install 'memgar[feed]'",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    pem_bytes = private_key_path.read_bytes()
    private_key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(f"{private_key_path} does not contain an Ed25519 private key")

    sig_bytes = private_key.sign(bundle_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode()

    pub_bytes = private_key.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()

    return sig_b64, pub_b64


def _build_bundle_payload(
    patterns_dicts: list,
    bundle_bytes: bytes,
    sig_b64: str,
    feed_version: str,
    min_memgar_version: str,
) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "manifest": {
            "feed_version": feed_version,
            "published_at": now,
            "min_memgar_version": min_memgar_version,
            "pattern_count": len(patterns_dicts),
            "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "signature": {
                "signature_b64": sig_b64,
                "algorithm": "ed25519",
                "signed_at": now,
                "signer": "memgar-maintainer",
            },
        },
        "patterns": patterns_dicts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign and package a memgar threat-intelligence feed bundle."
    )
    parser.add_argument(
        "--patterns-file",
        default="memgar/patterns.py",
        help="Path to the Python file that contains a PATTERNS list (default: memgar/patterns.py)",
    )
    parser.add_argument(
        "--private-key-file",
        required=True,
        help="Path to the Ed25519 private key in PEM format",
    )
    parser.add_argument(
        "--output-dir",
        default="dist",
        help="Directory to write memgar-feed.json.gz into (default: dist/)",
    )
    parser.add_argument(
        "--feed-version",
        default="1.0.0",
        help="Semantic version string for this feed release (default: 1.0.0)",
    )
    parser.add_argument(
        "--min-memgar-version",
        default="0.5.0",
        help="Minimum memgar version required to load this feed (default: 0.5.0)",
    )
    args = parser.parse_args()

    patterns_file = Path(args.patterns_file)
    private_key_file = Path(args.private_key_file)
    output_dir = Path(args.output_dir)

    if not patterns_file.exists():
        print(f"ERROR: patterns file not found: {patterns_file}", file=sys.stderr)
        raise SystemExit(1)
    if not private_key_file.exists():
        print(f"ERROR: private key file not found: {private_key_file}", file=sys.stderr)
        raise SystemExit(1)

    print(f"Loading patterns from {patterns_file} ...")
    raw_patterns = _load_patterns_from_file(patterns_file)
    patterns_dicts = [_pattern_to_dict(p) for p in raw_patterns]
    print(f"  {len(patterns_dicts)} patterns loaded.")

    print("Canonicalising bundle bytes ...")
    bundle_bytes = _canonical_bytes(raw_patterns)
    sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    print(f"  SHA-256: {sha256}")

    print(f"Signing with {private_key_file} ...")
    sig_b64, pub_b64 = _sign_bundle(bundle_bytes, private_key_file)
    print(f"  Signature: {sig_b64[:32]}...")

    payload = _build_bundle_payload(
        patterns_dicts=patterns_dicts,
        bundle_bytes=bundle_bytes,
        sig_b64=sig_b64,
        feed_version=args.feed_version,
        min_memgar_version=args.min_memgar_version,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "memgar-feed.json.gz"
    raw_json = json.dumps(payload, sort_keys=False, ensure_ascii=False).encode("utf-8")
    out_path.write_bytes(gzip.compress(raw_json))
    print(f"\nWrote {out_path}  ({out_path.stat().st_size} bytes compressed)")

    print("\n" + "=" * 60)
    print("IMPORTANT: update FEED_PUBLIC_KEY_B64 in memgar/feed/verifier.py")
    print("with the following public key before publishing this release:")
    print()
    print(f'FEED_PUBLIC_KEY_B64: str = "{pub_b64}"')
    print("=" * 60)


if __name__ == "__main__":
    main()
