"""Embedding-space anomaly detection.

Lightweight outlier detection over embedding vectors so memgar can flag
poison that bypasses pattern matching but lands in suspicious regions of
your vector space.

Three complementary signals, all stdlib-only (no sklearn / scipy):

  1. **Centroid distance** — How far is this vector from the running mean
     of the cluster it claims to belong to? Spike → outlier.

  2. **k-NN density** — How close is the vector to its k nearest neighbors
     in the same cluster? Sparse neighborhoods are unusual.

  3. **Cross-cluster ambiguity** — If the vector's nearest-neighbor in
     cluster A is closer than its nearest in cluster B (where it claims
     to belong), it is either mis-labeled or actively attacking the
     similarity surface (`VECNN-001`-style cluster injection).

The detector is incremental — `observe()` updates the cluster's running
statistics, `score()` returns an anomaly score for a candidate. Use
`observe()` during normal operation to build a baseline; switch to `score()`
on writes to flag suspicious inserts before they hit the vector store.

Designed to bolt onto the existing Layer 1.5 SemanticGuard architecture
without requiring sentence-transformers — works with any precomputed
embedding (list[float] or numpy array if available).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Sequence

Vector = Sequence[float]


# ---------------------------------------------------------------------------
# Vector primitives — stdlib-only
# ---------------------------------------------------------------------------


def _norm(v: Vector) -> float:
    return math.sqrt(sum(x * x for x in v))


def _cosine(a: Vector, b: Vector) -> float:
    """Cosine similarity in [-1, 1]. 1 = identical direction."""
    na = _norm(a)
    nb = _norm(b)
    if na == 0.0 or nb == 0.0:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (na * nb)


def cosine_distance(a: Vector, b: Vector) -> float:
    """Cosine distance in [0, 2]. 0 = identical, 2 = opposite."""
    return 1.0 - _cosine(a, b)


def _euclidean(a: Vector, b: Vector) -> float:
    return math.sqrt(sum((x - y) * (x - y) for x, y in zip(a, b)))


# ---------------------------------------------------------------------------
# Cluster statistics — incremental Welford
# ---------------------------------------------------------------------------


@dataclass
class ClusterStats:
    """Running mean and variance of per-vector centroid-distance.

    Welford's online algorithm: O(1) update, O(1) memory, numerically stable.
    """

    count: int = 0
    mean_distance: float = 0.0
    m2: float = 0.0  # sum of squared deviations
    centroid: List[float] = field(default_factory=list)
    centroid_n: int = 0
    recent: Deque[List[float]] = field(default_factory=lambda: deque(maxlen=200))

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def update_distance(self, distance: float) -> None:
        self.count += 1
        delta = distance - self.mean_distance
        self.mean_distance += delta / self.count
        delta2 = distance - self.mean_distance
        self.m2 += delta * delta2

    def update_centroid(self, vector: Vector) -> None:
        vec = list(vector)
        if not self.centroid:
            self.centroid = list(vec)
            self.centroid_n = 1
            return
        self.centroid_n += 1
        scale = 1.0 / self.centroid_n
        for i, x in enumerate(vec):
            self.centroid[i] += (x - self.centroid[i]) * scale

    def remember(self, vector: Vector) -> None:
        self.recent.append(list(vector))


# ---------------------------------------------------------------------------
# Anomaly score
# ---------------------------------------------------------------------------


@dataclass
class AnomalyVerdict:
    """Detector output for a single (cluster, vector) pair."""

    cluster: str
    centroid_distance: float
    z_score: float
    is_outlier: bool
    nearest_neighbor_distance: Optional[float]
    is_density_anomaly: bool
    cross_cluster_collision: Optional[str] = None
    explanation: str = ""

    @property
    def severity(self) -> str:
        if self.is_outlier and self.is_density_anomaly:
            return "high"
        if self.is_outlier or self.cross_cluster_collision:
            return "medium"
        if self.is_density_anomaly:
            return "low"
        return "none"

    def to_dict(self) -> dict:
        return {
            "cluster": self.cluster,
            "centroid_distance": self.centroid_distance,
            "z_score": self.z_score,
            "is_outlier": self.is_outlier,
            "nearest_neighbor_distance": self.nearest_neighbor_distance,
            "is_density_anomaly": self.is_density_anomaly,
            "cross_cluster_collision": self.cross_cluster_collision,
            "severity": self.severity,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class EmbeddingAnomalyDetector:
    """Incremental embedding-space anomaly detector.

    Args:
        z_threshold: Mahalanobis-style 1-D z-score above which a vector is
            flagged as an outlier. Default 3.0 (≈99.7% normal under
            Gaussian).
        k: Number of nearest neighbors to consult for density checks.
        density_quantile: A density anomaly triggers when the vector's
            mean-distance-to-k-NN is above this quantile of historical
            mean distances. Default 0.95.
        min_observations: Minimum baseline observations before scoring
            against a cluster. Below this, `score()` returns `severity=none`.
    """

    def __init__(
        self,
        *,
        z_threshold: float = 3.0,
        k: int = 5,
        density_quantile: float = 0.95,
        min_observations: int = 20,
    ) -> None:
        self.z_threshold = z_threshold
        self.k = k
        self.density_quantile = density_quantile
        self.min_observations = min_observations
        self._clusters: Dict[str, ClusterStats] = {}
        self._density_history: Dict[str, Deque[float]] = {}

    # ------------------------------------------------------------------
    # Baseline ingestion
    # ------------------------------------------------------------------

    def observe(self, vector: Vector, *, cluster: str) -> None:
        """Add `vector` to the baseline for `cluster`."""
        stats = self._clusters.setdefault(cluster, ClusterStats())
        stats.update_centroid(vector)
        d = cosine_distance(vector, stats.centroid)
        stats.update_distance(d)
        stats.remember(vector)
        # Track recent k-NN mean distance for density-quantile scoring
        knn_d = self._knn_mean_distance(vector, stats)
        if knn_d is not None:
            buf = self._density_history.setdefault(
                cluster, deque(maxlen=500)
            )
            buf.append(knn_d)

    def observe_batch(
        self, vectors: Iterable[Vector], *, cluster: str
    ) -> None:
        for v in vectors:
            self.observe(v, cluster=cluster)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(
        self,
        vector: Vector,
        *,
        cluster: str,
        compare_clusters: Optional[Sequence[str]] = None,
    ) -> AnomalyVerdict:
        """Score `vector` against the named `cluster`.

        If `compare_clusters` is provided, also check whether the vector's
        nearest neighbor in any of those *other* clusters is closer than
        its nearest neighbor in `cluster` — a strong signal of cluster
        injection / nearest-neighbor poisoning (VECNN-001 family).
        """
        stats = self._clusters.get(cluster)
        if stats is None or stats.count < self.min_observations:
            return AnomalyVerdict(
                cluster=cluster,
                centroid_distance=0.0,
                z_score=0.0,
                is_outlier=False,
                nearest_neighbor_distance=None,
                is_density_anomaly=False,
                explanation=(
                    f"insufficient baseline (have {stats.count if stats else 0}, "
                    f"need {self.min_observations}); skipping scoring"
                ),
            )

        # 1. Centroid distance + z-score
        d = cosine_distance(vector, stats.centroid)
        z = (d - stats.mean_distance) / stats.stddev if stats.stddev > 0 else 0.0
        is_outlier = z >= self.z_threshold

        # 2. k-NN density
        knn_d = self._knn_mean_distance(vector, stats)
        is_density_anomaly = False
        if knn_d is not None:
            hist = self._density_history.get(cluster)
            if hist and len(hist) >= 20:
                threshold = self._quantile(hist, self.density_quantile)
                is_density_anomaly = knn_d > threshold

        # 3. Cross-cluster collision
        collision = None
        if compare_clusters:
            best_other_d = float("inf")
            best_other_name = None
            for other in compare_clusters:
                if other == cluster:
                    continue
                other_stats = self._clusters.get(other)
                if other_stats is None:
                    continue
                ckd = self._knn_mean_distance(vector, other_stats)
                if ckd is not None and ckd < best_other_d:
                    best_other_d = ckd
                    best_other_name = other
            if (
                best_other_name is not None
                and knn_d is not None
                and best_other_d < knn_d
            ):
                collision = best_other_name

        return AnomalyVerdict(
            cluster=cluster,
            centroid_distance=d,
            z_score=z,
            is_outlier=is_outlier,
            nearest_neighbor_distance=knn_d,
            is_density_anomaly=is_density_anomaly,
            cross_cluster_collision=collision,
            explanation=self._explain(
                z, is_outlier, is_density_anomaly, collision
            ),
        )

    # ------------------------------------------------------------------
    # Snapshot / serialization (for SIEM forwarding)
    # ------------------------------------------------------------------

    def cluster_summary(self) -> Dict[str, dict]:
        return {
            name: {
                "count": s.count,
                "mean_distance": s.mean_distance,
                "stddev": s.stddev,
                "recent_samples": len(s.recent),
            }
            for name, s in self._clusters.items()
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _knn_mean_distance(
        self, vector: Vector, stats: ClusterStats
    ) -> Optional[float]:
        if not stats.recent:
            return None
        distances = [cosine_distance(vector, v) for v in stats.recent]
        distances.sort()
        k = min(self.k, len(distances))
        if k == 0:
            return None
        return sum(distances[:k]) / k

    @staticmethod
    def _quantile(samples: Iterable[float], q: float) -> float:
        sorted_samples = sorted(samples)
        if not sorted_samples:
            return 0.0
        idx = int(q * (len(sorted_samples) - 1))
        return sorted_samples[idx]

    @staticmethod
    def _explain(
        z: float,
        outlier: bool,
        density: bool,
        collision: Optional[str],
    ) -> str:
        parts: List[str] = []
        if outlier:
            parts.append(f"centroid-distance z-score={z:.2f}")
        if density:
            parts.append("sparse local neighborhood (k-NN density anomaly)")
        if collision:
            parts.append(f"closer to cluster {collision!r} than declared cluster")
        if not parts:
            return "within normal embedding-space envelope"
        return "; ".join(parts)


__all__ = [
    "EmbeddingAnomalyDetector",
    "AnomalyVerdict",
    "ClusterStats",
    "cosine_distance",
]
