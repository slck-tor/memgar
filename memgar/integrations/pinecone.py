"""Pinecone integration — secure wrapper for `pinecone.Index`.

Pinecone (https://docs.pinecone.io) is the most widely-deployed managed
vector database. This module wraps the v3 client (`pinecone>=3.0`) Index
object to scan upsert payloads and decorate query results.

In Pinecone, text content is stored in vector metadata under the `text`
key by convention (matches LangChain / LlamaIndex defaults).

Usage:
    from pinecone import Pinecone
    from memgar.integrations.pinecone import MemgarPineconeIndex

    pc = Pinecone(api_key="...")
    raw_index = pc.Index("my-index")
    index = MemgarPineconeIndex(raw_index)

    index.upsert(vectors=[
        {"id": "doc1", "values": [...], "metadata": {"text": "User prefers..."}}
    ])
    results = index.query(vector=[...], top_k=5, include_metadata=True)
    for match in results["matches"]:
        print(match["metadata"]["memgar_risk_score"])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Union

from memgar import Analyzer
from memgar.integrations._vector_base import (
    VectorStoreSecurityShell,
    WritePolicy,
    coerce_text,
)

logger = logging.getLogger("memgar.integrations.pinecone")


try:
    import pinecone  # noqa: F401
    PINECONE_AVAILABLE = True
except ImportError:
    PINECONE_AVAILABLE = False


class MemgarPineconeIndex:
    """Wrap a Pinecone Index with memgar write-scanning + read-scoring.

    Args:
        index: A `pinecone.Index` (or `pinecone.data.index.Index`) instance.
        analyzer: Optional pre-configured `Analyzer`.
        write_policy: `block`, `sanitize`, or `audit`.
        text_key: Metadata key holding the document text. Default `"text"`.
        min_risk_to_act: Risk-score threshold for policy activation.
    """

    def __init__(
        self,
        index: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
        text_key: str = "text",
    ) -> None:
        self._index = index
        self._text_key = text_key
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def upsert(
        self,
        vectors: Iterable[Union[Dict[str, Any], tuple]],
        **kwargs: Any,
    ) -> Any:
        vec_list = list(vectors)
        bodies, sids = self._extract_texts(vec_list)
        if bodies:
            records = self.shell.scan_writes(
                bodies, source_type="pinecone", source_ids=sids
            )
            safe_bodies = self.shell.apply_policy(records)
            self._inject_texts(vec_list, safe_bodies, records)
        return self._index.upsert(vectors=vec_list, **kwargs)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def query(self, **kwargs: Any) -> Any:
        kwargs.setdefault("include_metadata", True)
        results = self._index.query(**kwargs)
        self._decorate_query_results(results)
        return results

    # ------------------------------------------------------------------
    # Passthroughs
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._index, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _extract_texts(
        self,
        vectors: List[Union[Dict[str, Any], tuple]],
    ) -> tuple[List[str], List[str]]:
        bodies: List[str] = []
        sids: List[str] = []
        for v in vectors:
            if isinstance(v, dict):
                meta = v.get("metadata", {}) or {}
                bodies.append(coerce_text(meta.get(self._text_key, "")))
                sids.append(str(v.get("id", "")))
            elif isinstance(v, tuple) and len(v) >= 3:
                # (id, values, metadata)
                meta = v[2] if isinstance(v[2], dict) else {}
                bodies.append(coerce_text(meta.get(self._text_key, "")))
                sids.append(str(v[0]))
        return bodies, sids

    def _inject_texts(
        self,
        vectors: List[Union[Dict[str, Any], tuple]],
        safe_bodies: List[str],
        records,
    ) -> None:
        bi = 0
        for idx, v in enumerate(vectors):
            if isinstance(v, dict):
                meta = v.setdefault("metadata", {})
                if self._text_key in meta:
                    meta[self._text_key] = safe_bodies[bi]
                rec = records[bi] if bi < len(records) else None
                if rec and rec.metadata_patch:
                    meta.update(rec.metadata_patch)
                bi += 1

    def _decorate_query_results(self, results: Any) -> None:
        matches = self._get_matches(results)
        if not matches:
            return
        contents = [
            coerce_text(self._meta(m).get(self._text_key, "")) for m in matches
        ]
        patches = self.shell.score_reads(contents, source_type="pinecone")
        for m, patch in zip(matches, patches):
            meta = self._meta(m)
            meta.update(patch)

    @staticmethod
    def _get_matches(results: Any) -> List[Any]:
        if isinstance(results, dict):
            return results.get("matches") or []
        return getattr(results, "matches", []) or []

    @staticmethod
    def _meta(match: Any) -> Dict[str, Any]:
        if isinstance(match, dict):
            return match.setdefault("metadata", {})
        # Pinecone v3 returns dataclass-like objects
        meta = getattr(match, "metadata", None)
        if meta is None:
            try:
                setattr(match, "metadata", {})
                meta = getattr(match, "metadata")
            except Exception:  # noqa: BLE001
                meta = {}
        return meta if isinstance(meta, dict) else {}


__all__ = ["MemgarPineconeIndex", "PINECONE_AVAILABLE"]
