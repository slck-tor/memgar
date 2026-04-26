"""Versioned local cache for threat-intelligence feed bundles."""

from __future__ import annotations

import gzip
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_SUBDIR = "feeds"


def _cache_dir() -> Path:
    base = os.environ.get("MEMGAR_CACHE_DIR", str(Path.home() / ".cache" / "memgar"))
    return Path(base) / _DEFAULT_CACHE_SUBDIR


class FeedCache:
    """Store and retrieve feed bundles from local disk."""

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        self._dir = Path(cache_dir) if cache_dir else _cache_dir()

    def _manifest_path(self) -> Path:
        return self._dir / "feed_manifest.json"

    def _bundle_path(self) -> Path:
        return self._dir / "feed_bundle.json.gz"

    def is_stale(self, max_age_days: int = 7) -> bool:
        mp = self._manifest_path()
        if not mp.exists():
            return True
        try:
            data = json.loads(mp.read_text(encoding="utf-8"))
            cached_at_str = data.get("cached_at", "")
            if not cached_at_str:
                return True
            cached_at = datetime.fromisoformat(cached_at_str)
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            age = (datetime.now(tz=timezone.utc) - cached_at).days
            return age >= max_age_days
        except Exception:
            return True

    _MAX_COMPRESSED = 20 * 1024 * 1024   # 20 MB
    _MAX_DECOMPRESSED = 100 * 1024 * 1024  # 100 MB

    def get_cached_bundle(self, max_age_days: int = 7) -> Optional["PatternBundle"]:  # type: ignore[name-defined]
        if self.is_stale(max_age_days):
            return None
        bp = self._bundle_path()
        if not bp.exists():
            return None
        try:
            compressed = bp.read_bytes()
            if len(compressed) > self._MAX_COMPRESSED:
                logger.warning("Cached feed exceeds size limit — discarding")
                return None
            raw = gzip.decompress(compressed)
            if len(raw) > self._MAX_DECOMPRESSED:
                logger.warning("Decompressed feed exceeds size limit — discarding")
                return None
            data = json.loads(raw.decode("utf-8"))
            return _bundle_from_dict(data)
        except Exception as exc:
            logger.debug("Cache read error: %s", exc)
            return None

    def save_bundle(self, bundle: "PatternBundle") -> None:  # type: ignore[name-defined]
        self._dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "manifest": {
                "feed_version": bundle.manifest.feed_version,
                "published_at": bundle.manifest.published_at,
                "min_memgar_version": bundle.manifest.min_memgar_version,
                "pattern_count": bundle.manifest.pattern_count,
                "bundle_sha256": bundle.manifest.bundle_sha256,
                "signature": {
                    "signature_b64": bundle.manifest.signature.signature_b64,
                    "algorithm": bundle.manifest.signature.algorithm,
                    "signed_at": bundle.manifest.signature.signed_at,
                    "signer": bundle.manifest.signature.signer,
                },
            },
            "patterns": bundle.patterns,
        }
        compressed = gzip.compress(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        self._bundle_path().write_bytes(compressed)

        manifest_data = dict(payload["manifest"])
        manifest_data["cached_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._manifest_path().write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        logger.debug("Feed bundle cached at %s (version %s)", self._dir, bundle.manifest.feed_version)

    def clear(self) -> None:
        for p in (self._manifest_path(), self._bundle_path()):
            if p.exists():
                p.unlink()


def _bundle_from_dict(data: dict) -> "PatternBundle":  # type: ignore[name-defined]
    from memgar.feed.models import FeedManifest, PatternBundle
    manifest = FeedManifest.from_dict(data.get("manifest", {}))
    bundle = PatternBundle(manifest=manifest, patterns=data.get("patterns", []))
    # Verify this feed is compatible with the running memgar version.
    _check_version_compat(manifest.min_memgar_version)
    return bundle


def _check_version_compat(min_version_str: str) -> None:
    """Log a warning (non-fatal) when the feed requires a newer memgar."""
    if not min_version_str:
        return
    try:
        from memgar import __version__

        def _parse(v: str):
            parts = v.strip().lstrip("v").split(".")
            return tuple(int(x) for x in parts[:3])

        running = _parse(__version__)
        required = _parse(min_version_str)
        if running < required:
            logger.warning(
                "Feed requires memgar >= %s but running %s — some patterns may not load correctly.",
                min_version_str, __version__,
            )
    except Exception:
        pass


# Late import to satisfy type checkers
from memgar.feed.models import PatternBundle  # noqa: E402, F401
