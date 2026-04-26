"""Download, verify, and cache the threat-intelligence feed from GitHub Releases."""

from __future__ import annotations

import gzip
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from memgar import __version__
from memgar.feed.cache import FeedCache
from memgar.feed.models import FeedManifest, FeedSignature, PatternBundle
from memgar.feed.verifier import FeedSignatureError, FeedVerifier

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"
_FEED_ASSET_NAME = "memgar-feed.json.gz"
# Fallback: committed dist/ file served via raw.githubusercontent.com.
# Used when no GitHub Release exists yet (e.g. early deployments, forks).
_RAW_FALLBACK_URL = "https://raw.githubusercontent.com/{repo}/main/feeds/memgar-feed.json.gz"
_TIMEOUT = 30


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

    def load(self, auto_sync: bool = True) -> Optional[PatternBundle]:
        """Return a valid bundle, syncing from GitHub if cache is stale."""
        cached = self._cache.get_cached_bundle(max_age_days=self._max_age)
        if cached is not None:
            return cached
        if auto_sync:
            try:
                return self.sync()
            except Exception as exc:
                logger.warning("Feed sync failed: %s", exc)
        return None

    def sync(self) -> Optional[PatternBundle]:
        """Fetch the latest release, verify signature, cache, and return bundle."""
        release = self._fetch_release_info()  # None when no release or network failure

        download_url = self._find_asset_url(release) if release else None
        if not download_url:
            # No release asset — fall back to the committed dist/ file.
            fallback = _RAW_FALLBACK_URL.format(repo=self._repo)
            logger.info("No release asset found, trying fallback URL: %s", fallback)
            download_url = fallback

        raw_bytes = self._download(download_url)
        bundle = self._parse(raw_bytes)
        if bundle is None:
            return None

        if self._verify:
            if not self._verifier.verify_manifest(bundle.manifest, bundle.bundle_bytes()):
                raise FeedSignatureError(
                    f"Feed bundle signature verification failed (version {bundle.manifest.feed_version}). "
                    "The feed may have been tampered with."
                )

        self._cache.save_bundle(bundle)
        logger.info("Feed synced: version %s, %d patterns", bundle.manifest.feed_version, len(bundle.patterns))
        return bundle

    def _fetch_release_info(self) -> Optional[Dict[str, Any]]:
        url = _GITHUB_API.format(repo=self._repo)
        req = urllib.request.Request(url, headers={"User-Agent": f"memgar/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
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
