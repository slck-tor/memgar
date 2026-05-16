"""
Health-visibility tests for the systemic "silently disabled subsystem" fix.

Regression guard for the failure mode where SemanticGuard / TransformerDetector
/ FeedLoader end up disabled (missing artifacts, network policy, etc.) without
any operator-visible signal. Each subsystem must report degraded state through
its own ``health()``, and ``Analyzer.health_check()`` must aggregate them.
"""

from __future__ import annotations

import logging
import urllib.error
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# TransformerDetector
# ---------------------------------------------------------------------------

class TestTransformerDetectorHealth:

    def test_health_degraded_when_tokenizer_missing(self, tmp_path):
        from ml.inference.transformer_detector import TransformerDetector

        det = TransformerDetector(
            onnx_path=str(tmp_path / "nope.onnx"),
            tokenizer_dir=str(tmp_path / "no-tokenizer"),
            warn_if_unready=False,
        )
        h = det.health()
        assert h["status"] == "degraded"
        assert h["is_ready"] is False
        assert h["backend"] == "none"
        assert h["reason"] is not None
        assert h["fix_hint"] is not None
        # Reason should pinpoint the actual gap so users don't have to guess.
        assert "tokenizer" in h["reason"]

    def test_health_distinguishes_model_missing_from_tokenizer_missing(self, tmp_path, monkeypatch):
        """If tokenizer loads but model file is missing, reason should say so."""
        from ml.inference import transformer_detector as td

        tok_dir = tmp_path / "tokenizer"
        tok_dir.mkdir()
        # Convince _init_tokenizer it succeeded by patching the inner import.
        monkeypatch.setattr(
            td.TransformerDetector,
            "_init_tokenizer",
            lambda self, p: setattr(self, "_tokenizer", object()),
        )

        det = td.TransformerDetector(
            onnx_path=str(tmp_path / "nope.onnx"),
            tokenizer_dir=str(tok_dir),
            warn_if_unready=False,
        )
        h = det.health()
        assert h["status"] == "degraded"
        assert h["reason"] is not None
        assert "model_missing" in h["reason"]

    def test_warning_is_suppressed_with_flag(self, tmp_path, caplog):
        from ml.inference.transformer_detector import TransformerDetector

        caplog.set_level(logging.WARNING, logger="ml.inference.transformer_detector")
        TransformerDetector(
            onnx_path=str(tmp_path / "nope.onnx"),
            tokenizer_dir=str(tmp_path / "no-tokenizer"),
            warn_if_unready=False,
        )
        warns = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert all("DISABLED" not in r.getMessage() for r in warns)

    def test_warning_fires_once_then_dedups(self, tmp_path, caplog):
        from ml.inference import transformer_detector as td

        # Reset the module-level dedup set so this test is hermetic regardless
        # of prior tests that may have already triggered the same warning.
        td._WARNED_UNREADY.clear()

        caplog.set_level(logging.WARNING, logger="ml.inference.transformer_detector")
        for _ in range(3):
            td.TransformerDetector(
                onnx_path=str(tmp_path / "nope.onnx"),
                tokenizer_dir=str(tmp_path / "no-tokenizer"),
                warn_if_unready=True,
            )
        disabled_warns = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "DISABLED" in r.getMessage()
        ]
        # Three constructions, one warning.
        assert len(disabled_warns) == 1


# ---------------------------------------------------------------------------
# FeedLoader
# ---------------------------------------------------------------------------

class TestFeedLoaderHealth:

    def test_warning_dedups(self, tmp_path, caplog):
        from memgar.feed import loader as feed_loader

        feed_loader._WARNED_FEED.clear()
        caplog.set_level(logging.WARNING, logger="memgar.feed.loader")

        for _ in range(3):
            ld = feed_loader.FeedLoader(
                cache_dir=str(tmp_path), verify_signature=False, max_age_days=0
            )
            ld._fetch_release_info = lambda: None

            def _boom(url):
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

            ld._download = _boom
            ld.load(auto_sync=True)

        degraded_warns = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "DEGRADED" in r.getMessage()
        ]
        assert len(degraded_warns) == 1


# ---------------------------------------------------------------------------
# Analyzer.health_check()
# ---------------------------------------------------------------------------

class TestAnalyzerHealthCheck:

    def test_health_check_includes_all_subsystems(self):
        from memgar.analyzer import Analyzer

        a = Analyzer(use_llm=False)
        h = a.health_check()
        assert set(h["layers"].keys()) >= {
            "layer1_patterns",
            "layer1_5_semantic_guard",
            "layer2_llm",
            "layer2_ml_transformer",
            "layer3_trust",
            "layer4_behavioral",
            "threat_feed",
        }

    def test_overall_status_is_degraded_when_any_layer_is(self):
        from memgar.analyzer import Analyzer

        a = Analyzer(use_llm=False)
        h = a.health_check()
        # At least one of SemanticGuard / TransformerDetector / feed is
        # expected to be degraded in CI (artifacts not built, no network).
        # If any are degraded, the overall status must reflect that — that's
        # the whole point of the aggregator.
        if any(l.get("status") == "degraded" for l in h["layers"].values()):
            assert h["status"] == "degraded"

    def test_transformer_layer_reported_when_degraded(self):
        from memgar.analyzer import Analyzer

        a = Analyzer(use_llm=False)
        h = a.health_check()
        tx = h["layers"]["layer2_ml_transformer"]
        # In CI we don't ship the ONNX model, so this must be visible.
        if tx.get("status") == "degraded":
            assert tx.get("reason") is not None
            assert tx.get("fix_hint") is not None

    def test_health_check_does_not_raise_when_no_layers_enabled(self):
        """Defensive: health_check must work even on a minimal config."""
        from memgar.analyzer import Analyzer

        a = Analyzer(
            use_llm=False,
            semantic_guard=False,
            use_transformer_ml=False,
        )
        h = a.health_check()
        assert "status" in h
        assert h["layers"]["layer1_5_semantic_guard"]["status"] == "disabled"
        assert h["layers"]["layer2_ml_transformer"]["status"] == "disabled"
