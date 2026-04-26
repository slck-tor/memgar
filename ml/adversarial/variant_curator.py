"""
Variant curation: deduplicate and cluster LLM-generated attack variants
before retraining. Prevents near-duplicates from dominating the new dataset.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Sequence

logger = logging.getLogger(__name__)


class VariantCurator:
    """Deduplicate and cluster-cap adversarial variants."""

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        max_variants_per_cluster: int = 3,
    ):
        self.similarity_threshold = similarity_threshold
        self.max_variants_per_cluster = max_variants_per_cluster

    def deduplicate(self, variants: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Greedy near-duplicate removal using TF-IDF cosine similarity."""
        rows = [v for v in variants if str(v.get("text", "")).strip()]
        if len(rows) <= 1:
            return list(rows)

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
        except ImportError:
            # If sklearn is missing, fall back to exact-text dedup.
            seen = set()
            out: List[Dict[str, Any]] = []
            for r in rows:
                text = r["text"]
                if text not in seen:
                    seen.add(text)
                    out.append(r)
            return out

        texts = [r["text"] for r in rows]
        try:
            vec = TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 4),
                min_df=1,
            )
            mat = vec.fit_transform(texts)
        except ValueError:
            # Empty vocabulary (all-stopwords / tiny corpus) — exact-text dedup.
            seen = set()
            out2: List[Dict[str, Any]] = []
            for r in rows:
                if r["text"] not in seen:
                    seen.add(r["text"])
                    out2.append(r)
            return out2

        sim = cosine_similarity(mat)
        kept: List[int] = []
        for i in range(len(rows)):
            duplicate = False
            for j in kept:
                if sim[i, j] >= self.similarity_threshold:
                    duplicate = True
                    break
            if not duplicate:
                kept.append(i)
        return [rows[i] for i in kept]

    def curate(
        self,
        variants: Sequence[Dict[str, Any]],
        max_total: int = 500,
    ) -> List[Dict[str, Any]]:
        """Dedup + per-subcategory cap + global cap."""
        deduped = self.deduplicate(variants)

        clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for v in deduped:
            key = str(v.get("subcategory", "default"))
            clusters[key].append(v)

        capped: List[Dict[str, Any]] = []
        for items in clusters.values():
            capped.extend(items[: self.max_variants_per_cluster])

        if len(capped) > max_total:
            capped = capped[:max_total]
        return capped
