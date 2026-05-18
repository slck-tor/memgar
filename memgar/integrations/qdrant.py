"""Qdrant integration — secure wrapper for `qdrant_client.QdrantClient`.

Qdrant (https://qdrant.tech) is a Rust-based vector DB with strong
filtering and a growing share of the open-source self-hosted market.

Text is conventionally stored in `payload.text` or `payload.content`.

Usage:
    from qdrant_client import QdrantClient
    from qdrant_client.models import PointStruct
    from memgar.integrations.qdrant import MemgarQdrantClient

    raw = QdrantClient(":memory:")
    client = MemgarQdrantClient(raw)

    client.upsert(
        collection_name="memory",
        points=[
            PointStruct(id=1, vector=[...], payload={"text": "User..."}),
        ],
    )
    hits = client.search(collection_name="memory", query_vector=[...], limit=5)
    for hit in hits:
        print(hit.payload.get("memgar_risk_score"))
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from memgar import Analyzer
from memgar.integrations._vector_base import (
    VectorStoreSecurityShell,
    WritePolicy,
    coerce_text,
)

logger = logging.getLogger("memgar.integrations.qdrant")


try:
    import qdrant_client  # noqa: F401
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False


class MemgarQdrantClient:
    """Wrap a Qdrant client with memgar write-scanning + read-scoring.

    Args:
        client: A `QdrantClient` (sync or async wrapper).
        analyzer: Optional pre-configured `Analyzer`.
        write_policy: `block`, `sanitize`, or `audit`.
        text_key: Payload key holding the document text. Default `"text"`.
        min_risk_to_act: Risk-score threshold.
    """

    def __init__(
        self,
        client: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
        text_key: str = "text",
    ) -> None:
        self._client = client
        self._text_key = text_key
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
        )

    def upsert(self, collection_name: str, points: List[Any], **kwargs: Any) -> Any:
        bodies, sids = self._extract(points)
        if bodies:
            records = self.shell.scan_writes(
                bodies, source_type="qdrant", source_ids=sids
            )
            safe_bodies = self.shell.apply_policy(records)
            self._inject(points, safe_bodies, records)
        return self._client.upsert(collection_name=collection_name, points=points, **kwargs)

    def search(
        self,
        collection_name: str,
        query_vector: Any,
        limit: int = 10,
        **kwargs: Any,
    ) -> List[Any]:
        results = self._client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=limit,
            **kwargs,
        )
        self._decorate(results)
        return results

    def query_points(
        self,
        collection_name: str,
        query: Any = None,
        limit: int = 10,
        **kwargs: Any,
    ) -> Any:
        """Qdrant v1.10+ unified query API."""
        results = self._client.query_points(
            collection_name=collection_name, query=query, limit=limit, **kwargs
        )
        points = getattr(results, "points", None) or (
            results if isinstance(results, list) else []
        )
        self._decorate(points)
        return results

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _extract(self, points: List[Any]) -> tuple[List[str], List[str]]:
        bodies: List[str] = []
        sids: List[str] = []
        for p in points:
            payload = self._payload(p)
            bodies.append(coerce_text(payload.get(self._text_key, "")))
            sids.append(str(self._id(p) or ""))
        return bodies, sids

    def _inject(
        self,
        points: List[Any],
        safe_bodies: List[str],
        records,
    ) -> None:
        for i, p in enumerate(points):
            payload = self._payload(p)
            if self._text_key in payload:
                payload[self._text_key] = safe_bodies[i]
            if records[i].metadata_patch:
                payload.update(records[i].metadata_patch)

    def _decorate(self, hits: List[Any]) -> None:
        contents = [
            coerce_text(self._payload(h).get(self._text_key, "")) for h in hits
        ]
        patches = self.shell.score_reads(contents, source_type="qdrant")
        for h, patch in zip(hits, patches):
            payload = self._payload(h)
            payload.update(patch)

    @staticmethod
    def _payload(point: Any) -> Dict[str, Any]:
        if isinstance(point, dict):
            return point.setdefault("payload", {})
        payload = getattr(point, "payload", None)
        if payload is None:
            try:
                point.payload = {}
                payload = point.payload
            except Exception:  # noqa: BLE001
                payload = {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _id(point: Any) -> Any:
        if isinstance(point, dict):
            return point.get("id")
        return getattr(point, "id", None)


__all__ = ["MemgarQdrantClient", "QDRANT_AVAILABLE"]
