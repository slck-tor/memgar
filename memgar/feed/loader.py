"""Download, verify, and cache the threat-intelligence feed from GitHub Releases."""

from __future__ import annotations

import gzip
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from memgar import __version__
from memgar.feed.cache import FeedCache
from memgar.feed.models import FeedManifest, PatternBundle
from memgar.feed.verifier import FeedSignatureError, FeedVerifier

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"
_FEED_ASSET_NAME = "memgar-feed.json.gz"
# Fallback: committed dist/ file served via raw.githubusercontent.com.
# Used when no GitHub Release exists yet (e.g. early deployments, forks).
_RAW_FALLBACK_URL = "https://raw.githubusercontent.com/{repo}/main/feeds/memgar-feed.json.gz"
_TIMEOUT = 30

# Suppress duplicate WARNINGs when load()/sync() is retried in a loop.
_WARNED_FEED: set[tuple[str, str]] = set()


def _warn_feed_once(repo: str, reason: str) -> None:
    key = (repo, reason)
    if key in _WARNED_FEED:
        return
    _WARNED_FEED.add(key)
    logger.warning(
        "FeedLoader DEGRADED for %s: %s. Patterns will fall back to the "
        "bundled PATTERNS list — threat coverage may be stale. Check network "
        "policy or run: memgar feed sync",
        repo,
        reason,
    )


class FeedLoader:
    """Download and cache the signed threat-intelligence feed bundle."""

    def __init__(
        self,
        github_repo: str = "slcxtor/memgar",
        verify_signature: bool = True,
        max_age_days: int = 7,
        cache_dir: Optional[str] = None,
    ) -> None:
        self._repo = github_repo
        self._verify = verify_signature
        self._max_age = max_age_days
        self._cache = FeedCache(cache_dir=cache_dir)
        self._verifier = FeedVerifier()
        # Last attempt bookkeeping — surfaced via health().
        self._last_attempt_at: Optional[float] = None
        self._last_outcome: str = "never_attempted"  # success | failure | cache_hit
        self._last_error: Optional[str] = None
        self._last_bundle_version: Optional[str] = None
        self._last_pattern_count: int = 0
        self._used_fallback_url: bool = False

    def load(self, auto_sync: bool = True) -> Optional[PatternBundle]:
        """Return a valid bundle, syncing from GitHub if cache is stale."""
        self._last_attempt_at = time.time()
        cached = self._cache.get_cached_bundle(max_age_days=self._max_age)
        if cached is not None:
            self._last_outcome = "cache_hit"
            self._last_error = None
            self._last_bundle_version = cached.manifest.feed_version
            self._last_pattern_count = len(cached.patterns)
            return cached
        if auto_sync:
            try:
                bundle = self.sync()
                if bundle is None:
                    # sync() returned None — treat as a soft failure so health()
                    # reports it rather than claiming success.
                    if self._last_outcome != "success":
                        self._last_outcome = "failure"
                        self._last_error = self._last_error or "sync_returned_none"
                        _warn_feed_once(self._repo, self._last_error)
                return bundle
            except Exception as exc:
                self._last_outcome = "failure"
                self._last_error = f"{type(exc).__name__}: {exc}"
                _warn_feed_once(self._repo, self._last_error)
        else:
            self._last_outcome = "no_cache_no_sync"
            self._last_error = "cache stale and auto_sync disabled"
        return None

    def sync(self) -> Optional[PatternBundle]:
        """Fetch the latest release, verify signature, cache, and return bundle."""
        self._last_attempt_at = time.time()
        release = self._fetch_release_info()  # None means release metadata was unreachable.
        self._used_fallback_url = False
        if release is None:
            self._last_outcome = "failure"
            self._last_error = "release_info_unavailable"
            return None

        download_url = self._find_asset_url(release)
        if not download_url:
            # Release metadata was reachable, but no release asset exists yet —
            # fall back to the committed dist/ file.
            fallback = _RAW_FALLBACK_URL.format(repo=self._repo)
            logger.info("No release asset found, trying fallback URL: %s", fallback)
            download_url = fallback
            self._used_fallback_url = True

        raw_bytes = self._download(download_url)
        bundle = self._parse(raw_bytes)
        if bundle is None:
            self._last_outcome = "failure"
            self._last_error = "parse_failed"
            return None

        if self._verify:
            if not self._verifier.verify_manifest(bundle.manifest, bundle.bundle_bytes()):
                self._last_outcome = "failure"
                self._last_error = "signature_verification_failed"
                raise FeedSignatureError(
                    f"Feed bundle signature verification failed (version {bundle.manifest.feed_version}). "
                    "The feed may have been tampered with."
                )

        self._cache.save_bundle(bundle)
        self._last_outcome = "success"
        self._last_error = None
        self._last_bundle_version = bundle.manifest.feed_version
        self._last_pattern_count = len(bundle.patterns)
        logger.info("Feed synced: version %s, %d patterns", bundle.manifest.feed_version, len(bundle.patterns))
        return bundle

    def health(self) -> Dict[str, Any]:
        """
        Return a structured snapshot of the feed loader state.

        ``status`` is one of:
            - ``"ok"``       — last load returned a fresh bundle (sync success or cache hit)
            - ``"degraded"`` — last load failed; falling back to bundled PATTERNS
            - ``"unknown"``  — load() / sync() has not been called yet
        """
        if self._last_outcome == "never_attempted":
            status = "unknown"
        elif self._last_outcome in ("success", "cache_hit"):
            status = "ok"
        else:
            status = "degraded"

        # Inspect cache regardless of staleness so the health snapshot can
        # show "we have a stale bundle to fall back on" vs "nothing at all".
        cached_meta = None
        try:
            cached = self._cache.get_cached_bundle(max_age_days=10 ** 9)
            if cached is not None:
                cached_meta = {
                    "version": cached.manifest.feed_version,
                    "n_patterns": len(cached.patterns),
                    "is_stale": self._cache.is_stale(self._max_age),
                }
        except Exception:
            cached_meta = None

        fix_hint: Optional[str] = None
        if status == "degraded":
            fix_hint = "Check outbound HTTPS access to github.com / *.githubusercontent.com or run: memgar feed sync"
        elif status == "unknown":
            fix_hint = "Call FeedLoader.load() at startup to populate health state"

        return {
            "status": status,
            "repo": self._repo,
            "last_outcome": self._last_outcome,
            "last_error": self._last_error,
            "last_attempt_at": self._last_attempt_at,
            "last_bundle_version": self._last_bundle_version,
            "last_pattern_count": self._last_pattern_count,
            "used_fallback_url": self._used_fallback_url,
            "verify_signature": self._verify,
            "max_age_days": self._max_age,
            "cached_bundle": cached_meta,
            "fix_hint": fix_hint,
        }

    def _fetch_release_info(self) -> Optional[Dict[str, Any]]:
        url = _GITHUB_API.format(repo=self._repo)
        req = urllib.request.Request(url, headers={"User-Agent": f"memgar/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                logger.info("No GitHub release found for %s: %s", self._repo, exc)
                return {"assets": []}
            logger.warning("GitHub API request failed: %s", exc)
            return None
        except urllib.error.URLError as exc:
            logger.warning("GitHub API request failed: %s", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to fetch release info: %s", exc)
            return None

    def _find_asset_url(self, release: Dict[str, Any]) -> Optional[str]:
        for asset in release.get("assets", []):
            if asset.get("name") == _FEED_ASSET_NAME:
                return asset.get("browser_download_url")
        return None

    # Domains allowed as feed download sources.
    _ALLOWED_HOSTS = frozenset({
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "github.githubusercontent.com",
        "releases.githubusercontent.com",
    })
    # Hard limits to prevent zip-bomb / memory exhaustion.
    _MAX_COMPRESSED_BYTES = 20 * 1024 * 1024    # 20 MB
    _MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB

    def _download(self, url: str) -> bytes:
        # Validate URL is from an allowed GitHub host (SSRF prevention).
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("https",):
            raise ValueError(f"Feed URL must use HTTPS, got: {parsed.scheme!r}")
        if parsed.hostname not in self._ALLOWED_HOSTS:
            raise ValueError(
                f"Feed URL host {parsed.hostname!r} is not in the allowed list. "
                f"Allowed: {sorted(self._ALLOWED_HOSTS)}"
            )

        req = urllib.request.Request(url, headers={"User-Agent": f"memgar/{__version__}"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            compressed = resp.read(self._MAX_COMPRESSED_BYTES + 1)

        if len(compressed) > self._MAX_COMPRESSED_BYTES:
            raise ValueError(
                f"Compressed feed exceeds {self._MAX_COMPRESSED_BYTES // (1024*1024)} MB limit"
            )

        decompressed = gzip.decompress(compressed)
        if len(decompressed) > self._MAX_DECOMPRESSED_BYTES:
            raise ValueError(
                f"Decompressed feed exceeds {self._MAX_DECOMPRESSED_BYTES // (1024*1024)} MB limit"
            )
        return decompressed

    def _parse(self, raw_bytes: bytes) -> Optional[PatternBundle]:
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
            manifest = FeedManifest.from_dict(data.get("manifest", {}))
            return PatternBundle(manifest=manifest, patterns=data.get("patterns", []))
        except Exception as exc:
            logger.warning("Failed to parse feed bundle: %s", exc)
            return None


def sync_feed(repo: str = "slcxtor/memgar") -> Optional[PatternBundle]:
    """Convenience wrapper: sync and return the latest feed bundle."""
    return FeedLoader(github_repo=repo).sync()