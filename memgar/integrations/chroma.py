"""Chroma integration — secure wrapper for `chromadb.Collection`.

Chroma (https://docs.trychroma.com) is the most popular embedded /
self-hosted vector store. This module wraps a `Collection` to scan
documents on `add()`/`upsert()` and to decorate `query()` results.

Chroma stores text as a top-level `documents` array (parallel to `ids`,
`embeddings`, `metadatas`).

Usage:
    import chromadb
    from memgar.integrations.chroma import MemgarChromaCollection

    client = chromadb.Client()
    raw = client.get_or_create_collection("agent-memory")
    collection = MemgarChromaCollection(raw)

    collection.add(
        documents=["User prefers dark mode"],
        ids=["doc1"],
        metadatas=[{"source": "user-pref"}],
    )
    results = collection.query(query_texts=["dark mode"], n_results=5)
    for risk in results["metadatas"][0]:
        print(risk["memgar_risk_score"])
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

logger = logging.getLogger("memgar.integrations.chroma")


try:
    import chromadb  # noqa: F401
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False


class MemgarChromaCollection:
    """Wrap a Chroma Collection with memgar write-scanning + read-scoring.

    Args:
        collection: A `chromadb.Collection` instance.
        analyzer: Optional pre-configured `Analyzer`.
        write_policy: `block`, `sanitize`, or `audit`.
        min_risk_to_act: Risk-score threshold for policy activation.
    """

    def __init__(
        self,
        collection: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
    ) -> None:
        self._collection = collection
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def add(
        self,
        documents: List[str],
        ids: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Any:
        safe_docs, safe_metas = self._scan_batch(documents, ids, metadatas)
        return self._collection.add(
            documents=safe_docs, ids=ids, metadatas=safe_metas, **kwargs
        )

    def upsert(
        self,
        documents: List[str],
        ids: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Any:
        safe_docs, safe_metas = self._scan_batch(documents, ids, metadatas)
        return self._collection.upsert(
            documents=safe_docs, ids=ids, metadatas=safe_metas, **kwargs
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def query(
        self,
        query_texts: Optional[List[str]] = None,
        n_results: int = 10,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        results = self._collection.query(
            query_texts=query_texts, n_results=n_results, **kwargs
        )
        self._decorate_results(results)
        return results

    def __getattr__(self, name: str) -> Any:
        return getattr(self._collection, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_batch(
        self,
        documents: List[str],
        ids: List[str],
        metadatas: Optional[List[Dict[str, Any]]],
    ) -> tuple[List[str], List[Dict[str, Any]]]:
        records = self.shell.scan_writes(
            documents, source_type="chroma", source_ids=ids
        )
        safe_docs = self.shell.apply_policy(records)
        out_metas: List[Dict[str, Any]] = []
        for i, _ in enumerate(documents):
            meta = dict(metadatas[i]) if metadatas and i < len(metadatas) else {}
            if records[i].metadata_patch:
                meta.update(records[i].metadata_patch)
            out_metas.append(meta)
        return safe_docs, out_metas

    def _decorate_results(self, results: Dict[str, Any]) -> None:
        # Chroma returns parallel lists nested per query:
        #   {"documents": [[d1, d2]], "metadatas": [[m1, m2]], ...}
        documents = results.get("documents") or []
        metadatas = results.get("metadatas") or []
        for q_idx, doc_group in enumerate(documents):
            patches = self.shell.score_reads(
                [coerce_text(d) for d in doc_group], source_type="chroma"
            )
            if q_idx >= len(metadatas) or metadatas[q_idx] is None:
                # Materialise the metadata slot
                while len(metadatas) <= q_idx:
                    metadatas.append([])
                metadatas[q_idx] = [{} for _ in doc_group]
            for i, patch in enumerate(patches):
                meta = metadatas[q_idx][i] if i < len(metadatas[q_idx]) else {}
                if meta is None:
                    meta = {}
                meta.update(patch)
                if i < len(metadatas[q_idx]):
                    metadatas[q_idx][i] = meta
                else:
                    metadatas[q_idx].append(meta)
        results["metadatas"] = metadatas


__all__ = ["MemgarChromaCollection", "CHROMA_AVAILABLE"]
