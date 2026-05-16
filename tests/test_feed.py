"""Tests for the threat-intelligence feed (Phase 2)."""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module-level guard: pyo3-backed cryptography can panic at import time,
# which `_try_import_ed25519()` (a regular method) cannot catch because the
# panic happens before the function body runs.  Detect it once here so that
# pytest.mark.skipif can skip the whole test at *collection* time instead.
# ---------------------------------------------------------------------------
_CRYPTO_FUNCTIONAL = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed25519PrivateKey
    _Ed25519PrivateKey.generate()  # triggers the pyo3 panic on broken installs
    _CRYPTO_FUNCTIONAL = True
except BaseException:  # pyo3_runtime.PanicException is BaseException, not Exception
    pass

requires_crypto = pytest.mark.skipif(
    not _CRYPTO_FUNCTIONAL,
    reason="cryptography with Ed25519 not functional in this environment",
)


# ---------------------------------------------------------------------------
# Feed models
# ---------------------------------------------------------------------------

class TestFeedModels:
    def _sample_bundle_dict(self):
        return {
            "manifest": {
                "feed_version": "1.0.0",
                "published_at": "2026-01-01T00:00:00Z",
                "min_memgar_version": "0.5.0",
                "pattern_count": 2,
                "bundle_sha256": "abc123",
                "signature": {
                    "signature_b64": "AAAA",
                    "algorithm": "ed25519",
                    "signed_at": "2026-01-01T00:00:00Z",
                    "signer": "memgar-maintainer",
                },
            },
            "patterns": [
                {
                    "id": "TEST-001",
                    "name": "Test Pattern",
                    "description": "A test pattern",
                    "severity": "high",
                    "category": "injection",
                    "patterns": [r"ignore.*instructions"],
                    "keywords": ["ignore"],
                },
                {
                    "id": "TEST-002",
                    "name": "Another Test",
                    "description": "Second test pattern",
                    "severity": "medium",
                    "category": "exfiltration",
                    "patterns": [],
                    "keywords": ["exfiltrate"],
                },
            ],
        }

    def test_manifest_from_dict(self):
        from memgar.feed.models import FeedManifest
        data = self._sample_bundle_dict()["manifest"]
        manifest = FeedManifest.from_dict(data)
        assert manifest.feed_version == "1.0.0"
        assert manifest.pattern_count == 2
        assert manifest.signature.algorithm == "ed25519"

    def test_pattern_bundle_to_threat_objects(self):
        from memgar.feed.models import FeedManifest, PatternBundle
        data = self._sample_bundle_dict()
        manifest = FeedManifest.from_dict(data["manifest"])
        bundle = PatternBundle(manifest=manifest, patterns=data["patterns"])
        threats = bundle.to_threat_objects()
        assert len(threats) == 2
        ids = {t.id for t in threats}
        assert "TEST-001" in ids
        assert "TEST-002" in ids

    def test_unknown_category_falls_back_to_anomaly(self):
        from memgar.feed.models import FeedManifest, PatternBundle
        from memgar.models import ThreatCategory
        data = self._sample_bundle_dict()
        data["patterns"][0]["category"] = "totally_unknown_xyz"
        manifest = FeedManifest.from_dict(data["manifest"])
        bundle = PatternBundle(manifest=manifest, patterns=data["patterns"])
        threats = bundle.to_threat_objects()
        test_001 = next(t for t in threats if t.id == "TEST-001")
        assert test_001.category == ThreatCategory.ANOMALY

    def test_unknown_severity_falls_back_to_medium(self):
        from memgar.feed.models import FeedManifest, PatternBundle
        from memgar.models import Severity
        data = self._sample_bundle_dict()
        data["patterns"][0]["severity"] = "not_a_real_severity"
        manifest = FeedManifest.from_dict(data["manifest"])
        bundle = PatternBundle(manifest=manifest, patterns=data["patterns"])
        threats = bundle.to_threat_objects()
        test_001 = next(t for t in threats if t.id == "TEST-001")
        assert test_001.severity == Severity.MEDIUM

    def test_bundle_bytes_is_canonical_json(self):
        from memgar.feed.models import FeedManifest, PatternBundle
        data = self._sample_bundle_dict()
        manifest = FeedManifest.from_dict(data["manifest"])
        bundle = PatternBundle(manifest=manifest, patterns=data["patterns"])
        raw = bundle.bundle_bytes()
        assert isinstance(raw, bytes)
        # Canonical: no extra whitespace
        assert b"\n" not in raw


# ---------------------------------------------------------------------------
# FeedVerifier
# ---------------------------------------------------------------------------

class TestFeedVerifier:
    def _try_import_ed25519(self):
        """Skip test if cryptography or its native backend is broken/missing."""
        import base64
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            Ed25519PrivateKey.generate()
        except Exception:
            pytest.skip("cryptography with Ed25519 not functional in this environment")

    @requires_crypto
    def test_verify_invalid_signature_returns_false(self):
        self._try_import_ed25519()
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from memgar.feed.verifier import FeedVerifier

        # Generate keypair, but sign with wrong key → verify with right key → False
        private_key = Ed25519PrivateKey.generate()
        other_key = Ed25519PrivateKey.generate()
        public_key = other_key.public_key()
        pub_b64 = base64.b64encode(public_key.public_bytes_raw()).decode()

        sig_bytes = private_key.sign(b"bundle bytes")  # signed with wrong key
        sig_b64 = base64.b64encode(sig_bytes).decode()

        verifier = FeedVerifier(public_key_b64=pub_b64)
        assert verifier.verify(b"bundle bytes", sig_b64) is False

    @requires_crypto
    def test_verify_valid_signature_with_real_keypair(self):
        """Generate a real Ed25519 keypair, sign, and verify with FeedVerifier."""
        self._try_import_ed25519()
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from memgar.feed.verifier import FeedVerifier

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_b64 = base64.b64encode(public_key.public_bytes_raw()).decode()

        bundle_bytes = b"test bundle content for signing"
        sig_b64 = base64.b64encode(private_key.sign(bundle_bytes)).decode()

        verifier = FeedVerifier(public_key_b64=pub_b64)
        assert verifier.verify(bundle_bytes, sig_b64) is True

    @requires_crypto
    def test_verify_wrong_data_returns_false(self):
        self._try_import_ed25519()
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from memgar.feed.verifier import FeedVerifier

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_b64 = base64.b64encode(public_key.public_bytes_raw()).decode()

        sig_b64 = base64.b64encode(private_key.sign(b"original content")).decode()

        verifier = FeedVerifier(public_key_b64=pub_b64)
        assert verifier.verify(b"tampered content", sig_b64) is False

    def test_missing_cryptography_raises_import_error(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("mocked missing")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        from memgar.feed.verifier import FeedVerifier
        verifier = FeedVerifier()
        with pytest.raises(ImportError, match="cryptography"):
            verifier.verify(b"data", "AAAA==")


# ---------------------------------------------------------------------------
# FeedCache
# ---------------------------------------------------------------------------

class TestFeedCache:
    def _make_bundle(self):
        from memgar.feed.models import FeedManifest, FeedSignature, PatternBundle
        sig = FeedSignature(signature_b64="AAAA==", signed_at="2026-01-01T00:00:00Z")
        manifest = FeedManifest(
            feed_version="1.2.3",
            published_at="2026-01-01T00:00:00Z",
            min_memgar_version="0.5.0",
            pattern_count=1,
            bundle_sha256="deadbeef",
            signature=sig,
        )
        return PatternBundle(manifest=manifest, patterns=[{"id": "T-001", "name": "Test"}])

    def test_save_and_load_bundle(self, tmp_path):
        from memgar.feed.cache import FeedCache
        cache = FeedCache(cache_dir=str(tmp_path))
        bundle = self._make_bundle()
        cache.save_bundle(bundle)
        loaded = cache.get_cached_bundle(max_age_days=30)
        assert loaded is not None
        assert loaded.manifest.feed_version == "1.2.3"
        assert len(loaded.patterns) == 1

    def test_stale_when_no_cache(self, tmp_path):
        from memgar.feed.cache import FeedCache
        cache = FeedCache(cache_dir=str(tmp_path))
        assert cache.is_stale(max_age_days=7) is True

    def test_fresh_bundle_not_stale(self, tmp_path):
        from memgar.feed.cache import FeedCache
        cache = FeedCache(cache_dir=str(tmp_path))
        bundle = self._make_bundle()
        cache.save_bundle(bundle)
        assert cache.is_stale(max_age_days=7) is False

    def test_clear_removes_files(self, tmp_path):
        from memgar.feed.cache import FeedCache
        cache = FeedCache(cache_dir=str(tmp_path))
        cache.save_bundle(self._make_bundle())
        cache.clear()
        assert cache.get_cached_bundle(max_age_days=9999) is None


# ---------------------------------------------------------------------------
# FeedLoader
# ---------------------------------------------------------------------------

class TestFeedLoader:
    def _make_bundle_json(self) -> bytes:
        """Create a minimal valid feed bundle payload as raw JSON bytes (post-decompress)."""
        payload = {
            "manifest": {
                "feed_version": "2.0.0",
                "published_at": "2026-04-01T00:00:00Z",
                "min_memgar_version": "0.5.0",
                "pattern_count": 1,
                "bundle_sha256": "abc",
                "signature": {"signature_b64": "AAAA==", "algorithm": "ed25519", "signed_at": "", "signer": "test"},
            },
            "patterns": [{"id": "F-001", "name": "Feed Test"}],
        }
        return json.dumps(payload).encode("utf-8")

    def test_load_returns_cached_when_fresh(self, tmp_path):
        """If cache is fresh, sync() should NOT be called."""
        from memgar.feed.cache import FeedCache
        from memgar.feed.loader import FeedLoader
        from memgar.feed.models import FeedManifest, FeedSignature, PatternBundle

        # Pre-prime cache
        cache = FeedCache(cache_dir=str(tmp_path))
        sig = FeedSignature(signature_b64="AAAA==", signed_at="")
        manifest = FeedManifest(
            feed_version="1.0.0", published_at="", min_memgar_version="0.5.0",
            pattern_count=0, bundle_sha256="", signature=sig,
        )
        cache.save_bundle(PatternBundle(manifest=manifest, patterns=[]))

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=False)
        # Patch sync to detect if called
        called = []
        original_sync = loader.sync
        loader.sync = lambda: called.append(True) or None

        result = loader.load(auto_sync=True)
        assert len(called) == 0  # sync was NOT called
        assert result is not None

    def test_load_returns_none_on_network_failure(self, tmp_path):
        from memgar.feed.loader import FeedLoader

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=False, max_age_days=0)

        def fail_fetch(self):
            return None

        loader._fetch_release_info = lambda: None
        result = loader.load(auto_sync=True)
        assert result is None

    def test_sync_raises_feed_signature_error_on_bad_sig(self, tmp_path, monkeypatch):
        from memgar.feed.loader import FeedLoader
        from memgar.feed.verifier import FeedSignatureError

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=True)
        payload = {
            "manifest": {
                "feed_version": "2.0.0", "published_at": "2026-04-01T00:00:00Z",
                "min_memgar_version": "0.5.0", "pattern_count": 1, "bundle_sha256": "abc",
                "signature": {"signature_b64": "AAAA==", "algorithm": "ed25519", "signed_at": "", "signer": "test"},
            },
            "patterns": [{"id": "F-001", "name": "Feed Test"}],
        }
        bundle_json = json.dumps(payload).encode("utf-8")

        loader._fetch_release_info = lambda: {
            "assets": [{"name": "memgar-feed.json.gz", "browser_download_url": "http://x"}]
        }
        # _download returns decompressed bytes (loader already calls gzip.decompress internally)
        loader._download = lambda url: bundle_json
        loader._verifier.verify_manifest = lambda manifest, bundle_bytes: False

        with pytest.raises(FeedSignatureError):
            loader.sync()

    def test_health_unknown_before_load(self, tmp_path):
        from memgar.feed.loader import FeedLoader

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=False)
        h = loader.health()
        assert h["status"] == "unknown"
        assert h["last_outcome"] == "never_attempted"
        assert h["fix_hint"] is not None

    def test_health_reports_degraded_on_sync_failure(self, tmp_path):
        from memgar.feed.loader import FeedLoader

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=False, max_age_days=0)
        loader._fetch_release_info = lambda: None

        def _boom(url):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        loader._download = _boom

        result = loader.load(auto_sync=True)
        assert result is None

        h = loader.health()
        assert h["status"] == "degraded"
        assert h["last_outcome"] == "failure"
        assert h["last_error"] is not None
        assert "404" in h["last_error"] or "HTTPError" in h["last_error"]

    def test_health_reports_ok_on_cache_hit(self, tmp_path):
        from memgar.feed.cache import FeedCache
        from memgar.feed.loader import FeedLoader
        from memgar.feed.models import FeedManifest, FeedSignature, PatternBundle

        cache = FeedCache(cache_dir=str(tmp_path))
        sig = FeedSignature(signature_b64="AAAA==", signed_at="")
        manifest = FeedManifest(
            feed_version="1.2.3", published_at="", min_memgar_version="0.5.0",
            pattern_count=0, bundle_sha256="", signature=sig,
        )
        cache.save_bundle(PatternBundle(manifest=manifest, patterns=[]))

        loader = FeedLoader(cache_dir=str(tmp_path), verify_signature=False)
        loader.load(auto_sync=False)

        h = loader.health()
        assert h["status"] == "ok"
        assert h["last_outcome"] == "cache_hit"
        assert h["last_bundle_version"] == "1.2.3"
        assert h["cached_bundle"] is not None


# Import for the new tests above (kept local so we don't change module-level
# imports that other test classes might depend on).
import urllib.error  # noqa: E402


# ---------------------------------------------------------------------------
# CLI feed commands
# ---------------------------------------------------------------------------

class TestCLIFeedCommands:
    def test_feed_status_no_cache(self):
        from click.testing import CliRunner
        from memgar.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["feed", "status"])
        assert result.exit_code == 0
        assert "No feed cached" in result.output or "Feed version" in result.output

    def test_feed_verify_no_cache(self):
        from click.testing import CliRunner
        from memgar.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["feed", "verify"])
        assert result.exit_code == 0
        assert "No cached feed" in result.output or "Signature" in result.output

    def test_feed_help(self):
        from click.testing import CliRunner
        from memgar.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["feed", "--help"])
        assert result.exit_code == 0
        assert "sync" in result.output
        assert "status" in result.output
        assert "verify" in result.output
