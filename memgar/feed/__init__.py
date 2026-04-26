"""
Threat Intelligence Feed
========================

Download, verify, and apply versioned, Ed25519-signed pattern bundles
published to GitHub Releases independently of code releases.

Usage:
    from memgar.feed import sync_feed, FeedLoader

    # One-shot sync
    bundle = sync_feed()

    # With options
    loader = FeedLoader(verify_signature=True, max_age_days=3)
    bundle = loader.load()
    if bundle:
        print(f"Feed v{bundle.manifest.feed_version}: {len(bundle.patterns)} patterns")

Enable via config:
    feed:
      enabled: true
      auto_sync: true
"""

from __future__ import annotations

from memgar.feed.loader import FeedLoader, sync_feed
from memgar.feed.models import FeedManifest, FeedSignature, PatternBundle
from memgar.feed.verifier import FeedSignatureError, FeedVerifier

__all__ = [
    "FeedLoader",
    "sync_feed",
    "FeedManifest",
    "FeedSignature",
    "PatternBundle",
    "FeedSignatureError",
    "FeedVerifier",
]
