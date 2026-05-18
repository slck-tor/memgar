"""Tests for memgar.embedding_anomaly — outlier / density / cross-cluster."""

from __future__ import annotations

import math
import random

import pytest

from memgar.embedding_anomaly import (
    AnomalyVerdict,
    ClusterStats,
    EmbeddingAnomalyDetector,
    cosine_distance,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cluster_centered_at(center, n=100, sigma=0.05, seed=42):
    """Generate n vectors normally distributed around `center`."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        out.append([c + rng.gauss(0, sigma) for c in center])
    return out


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


class TestCosineDistance:
    def test_identical_vectors_zero_distance(self):
        assert cosine_distance([1.0, 0.0, 0.0], [1.0, 0.0, 0.0]) == pytest.approx(0.0)

    def test_orthogonal_vectors_distance_one(self):
        assert cosine_distance([1.0, 0.0], [0.0, 1.0]) == pytest.approx(1.0)

    def test_opposite_vectors_distance_two(self):
        assert cosine_distance([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(2.0)

    def test_zero_vector_returns_one(self):
        # Convention: 0-norm vector → cosine_similarity=0 → distance=1
        assert cosine_distance([0.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# ClusterStats (Welford)
# ---------------------------------------------------------------------------


class TestClusterStats:
    def test_initial_state(self):
        s = ClusterStats()
        assert s.count == 0
        assert s.mean_distance == 0.0
        assert s.stddev == 0.0

    def test_welford_matches_naive_mean(self):
        s = ClusterStats()
        for d in [0.1, 0.2, 0.15, 0.3, 0.25]:
            s.update_distance(d)
        assert s.mean_distance == pytest.approx(0.2)

    def test_welford_variance_correct(self):
        s = ClusterStats()
        samples = [0.1, 0.2, 0.15, 0.3, 0.25]
        for d in samples:
            s.update_distance(d)
        # Bessel-corrected variance
        n = len(samples)
        mean = sum(samples) / n
        expected_var = sum((x - mean) ** 2 for x in samples) / (n - 1)
        assert s.variance == pytest.approx(expected_var, rel=1e-6)

    def test_centroid_running_average(self):
        s = ClusterStats()
        s.update_centroid([0.0, 0.0])
        s.update_centroid([2.0, 4.0])
        s.update_centroid([4.0, 8.0])
        # Mean is (2.0, 4.0)
        assert s.centroid == pytest.approx([2.0, 4.0], abs=1e-6)


# ---------------------------------------------------------------------------
# Detector — basic baseline and scoring
# ---------------------------------------------------------------------------


class TestDetectorBaseline:
    def test_insufficient_observations_returns_none_verdict(self):
        det = EmbeddingAnomalyDetector(min_observations=50)
        det.observe([1.0, 0.0, 0.0], cluster="A")
        v = det.score([1.0, 0.0, 0.0], cluster="A")
        assert v.severity == "none"
        assert "insufficient baseline" in v.explanation

    def test_baseline_built_normal_vector_in_envelope(self):
        det = EmbeddingAnomalyDetector(min_observations=20)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100):
            det.observe(vec, cluster="payments")
        # A new vector from the same distribution should be normal
        new_vec = [1.02, 0.01, -0.01]
        v = det.score(new_vec, cluster="payments")
        assert v.is_outlier is False
        assert v.severity in ("none", "low")

    def test_far_outlier_flagged(self):
        det = EmbeddingAnomalyDetector(min_observations=20, z_threshold=3.0)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100, sigma=0.02):
            det.observe(vec, cluster="payments")
        outlier = [-0.5, 0.8, 0.1]  # Quite different from cluster center
        v = det.score(outlier, cluster="payments")
        assert v.is_outlier is True
        assert v.z_score > 3.0
        assert v.severity in ("medium", "high")
        assert "z-score" in v.explanation


# ---------------------------------------------------------------------------
# Density anomalies
# ---------------------------------------------------------------------------


class TestDensityAnomaly:
    def test_dense_neighborhood_not_anomalous(self):
        det = EmbeddingAnomalyDetector(min_observations=20)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=200, sigma=0.05):
            det.observe(vec, cluster="A")
        # Probe with a fresh vector from same distribution
        rng = random.Random(123)
        probe = [1.0 + rng.gauss(0, 0.05), rng.gauss(0, 0.05), rng.gauss(0, 0.05)]
        v = det.score(probe, cluster="A")
        # Most likely not flagged — but tolerance for stochasticity
        assert v.severity in ("none", "low")

    def test_sparse_neighborhood_flagged(self):
        det = EmbeddingAnomalyDetector(
            min_observations=20, density_quantile=0.5  # tight threshold
        )
        # Tight cluster around (1, 0, 0)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100, sigma=0.01):
            det.observe(vec, cluster="A")
        # A point on the cluster edge — k-NN distances are large
        edge = [1.0, 0.4, 0.0]
        v = det.score(edge, cluster="A")
        # Either centroid-outlier or density-anomaly should fire
        assert v.is_outlier or v.is_density_anomaly


# ---------------------------------------------------------------------------
# Cross-cluster collision
# ---------------------------------------------------------------------------


class TestCrossClusterCollision:
    def test_collision_detected(self):
        det = EmbeddingAnomalyDetector(min_observations=20)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100, sigma=0.05):
            det.observe(vec, cluster="users")
        for vec in _cluster_centered_at([0.0, 1.0, 0.0], n=100, sigma=0.05):
            det.observe(vec, cluster="admin")
        # A vector that's much closer to "admin" than to "users"
        sneaky = [0.05, 0.95, 0.0]
        v = det.score(
            sneaky, cluster="users", compare_clusters=["users", "admin"]
        )
        assert v.cross_cluster_collision == "admin"

    def test_no_collision_when_closer_to_declared_cluster(self):
        det = EmbeddingAnomalyDetector(min_observations=20)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100, sigma=0.05):
            det.observe(vec, cluster="users")
        for vec in _cluster_centered_at([0.0, 1.0, 0.0], n=100, sigma=0.05):
            det.observe(vec, cluster="admin")
        # Genuine user vector
        probe = [0.95, 0.02, 0.0]
        v = det.score(
            probe, cluster="users", compare_clusters=["users", "admin"]
        )
        assert v.cross_cluster_collision is None


# ---------------------------------------------------------------------------
# observe_batch
# ---------------------------------------------------------------------------


class TestBatchObservation:
    def test_observe_batch_equivalent_to_loop(self):
        det1 = EmbeddingAnomalyDetector()
        det2 = EmbeddingAnomalyDetector()
        vectors = _cluster_centered_at([1.0, 0.0, 0.0], n=50)
        for v in vectors:
            det1.observe(v, cluster="A")
        det2.observe_batch(vectors, cluster="A")
        s1 = det1.cluster_summary()["A"]
        s2 = det2.cluster_summary()["A"]
        assert s1["count"] == s2["count"]
        assert s1["mean_distance"] == pytest.approx(s2["mean_distance"], rel=1e-9)


# ---------------------------------------------------------------------------
# Summary / serialisation
# ---------------------------------------------------------------------------


class TestSummary:
    def test_cluster_summary_has_basic_stats(self):
        det = EmbeddingAnomalyDetector()
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=30):
            det.observe(vec, cluster="A")
        summary = det.cluster_summary()
        assert "A" in summary
        assert summary["A"]["count"] == 30
        assert summary["A"]["mean_distance"] >= 0

    def test_verdict_to_dict_includes_severity(self):
        det = EmbeddingAnomalyDetector(min_observations=20)
        for vec in _cluster_centered_at([1.0, 0.0, 0.0], n=100, sigma=0.02):
            det.observe(vec, cluster="payments")
        v = det.score([1.0, 0.0, 0.0], cluster="payments")
        d = v.to_dict()
        assert "severity" in d
        assert "z_score" in d
        assert "is_outlier" in d
