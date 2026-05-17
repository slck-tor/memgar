"""Weaviate integration — secure wrapper for `weaviate.collections.Collection`.

Weaviate (https://weaviate.io) is a popular self-hosted / cloud vector DB
with strong hybrid search and a Pythonic v4 client.

Text is stored in named properties (whatever schema the collection defines),
defaulting to `content` or `text` by convention.

Usage:
    import weaviate
    from memgar.integrations.weaviate import MemgarWeaviateCollection

    client = weaviate.connect_to_local()
    raw = client.collections.get("AgentMemory")
    collection = MemgarWeaviateCollection(raw, text_property="content")

    collection.data.insert({"content": "User prefers dark mode", "source": "user"})
    response = collection.query.near_text(query="dark mode", limit=5)
    for obj in response.objects:
        print(obj.properties["memgar_risk_score"])
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

logger = logging.getLogger("memgar.integrations.weaviate")


try:
    import weaviate  # noqa: F401
    WEAVIATE_AVAILABLE = True
except ImportError:
    WEAVIATE_AVAILABLE = False


class _DataProxy:
    """Wraps `collection.data` to scan inserts/replaces."""

    def __init__(self, parent: "MemgarWeaviateCollection") -> None:
        self._parent = parent
        self._data = parent._collection.data

    def insert(self, properties: Dict[str, Any], **kwargs: Any) -> Any:
        safe = self._parent._scan_properties(properties, "insert")
        return self._data.insert(properties=safe, **kwargs)

    def insert_many(self, objects: List[Any], **kwargs: Any) -> Any:
        safe_objects = [self._scan_object(o) for o in objects]
        return self._data.insert_many(objects=safe_objects, **kwargs)

    def replace(self, uuid: Any, properties: Dict[str, Any], **kwargs: Any) -> Any:
        safe = self._parent._scan_properties(properties, "replace")
        return self._data.replace(uuid=uuid, properties=safe, **kwargs)

    def update(self, uuid: Any, properties: Dict[str, Any], **kwargs: Any) -> Any:
        safe = self._parent._scan_properties(properties, "update")
        return self._data.update(uuid=uuid, properties=safe, **kwargs)

    def _scan_object(self, obj: Any) -> Any:
        # weaviate.classes.data.DataObject has .properties
        if isinstance(obj, dict):
            patched = dict(obj)
            patched["properties"] = self._parent._scan_properties(
                patched.get("properties", {}), "insert_many"
            )
            return patched
        props = getattr(obj, "properties", {}) or {}
        new_props = self._parent._scan_properties(props, "insert_many")
        try:
            obj.properties = new_props
        except Exception:  # noqa: BLE001
            pass
        return obj

    def __getattr__(self, name: str) -> Any:
        return getattr(self._data, name)


class _QueryProxy:
    """Wraps `collection.query` to score retrieval results."""

    def __init__(self, parent: "MemgarWeaviateCollection") -> None:
        self._parent = parent
        self._query = parent._collection.query

    def near_text(self, *args: Any, **kwargs: Any) -> Any:
        resp = self._query.near_text(*args, **kwargs)
        self._parent._decorate_response(resp)
        return resp

    def near_vector(self, *args: Any, **kwargs: Any) -> Any:
        resp = self._query.near_vector(*args, **kwargs)
        self._parent._decorate_response(resp)
        return resp

    def hybrid(self, *args: Any, **kwargs: Any) -> Any:
        resp = self._query.hybrid(*args, **kwargs)
        self._parent._decorate_response(resp)
        return resp

    def bm25(self, *args: Any, **kwargs: Any) -> Any:
        resp = self._query.bm25(*args, **kwargs)
        self._parent._decorate_response(resp)
        return resp

    def fetch_objects(self, *args: Any, **kwargs: Any) -> Any:
        resp = self._query.fetch_objects(*args, **kwargs)
        self._parent._decorate_response(resp)
        return resp

    def __getattr__(self, name: str) -> Any:
        return getattr(self._query, name)


class MemgarWeaviateCollection:
    """Wrap a Weaviate v4 Collection with memgar write-scanning + read-scoring.

    Args:
        collection: A `weaviate.collections.Collection` instance.
        analyzer: Optional pre-configured `Analyzer`.
        write_policy: `block`, `sanitize`, or `audit`.
        text_property: Property name holding the document text. Defaults to
            `"content"`; falls back to `"text"` if `"content"` is absent.
        min_risk_to_act: Risk-score threshold for policy activation.
    """

    def __init__(
        self,
        collection: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
        text_property: str = "content",
    ) -> None:
        self._collection = collection
        self._text_property = text_property
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
        )
        self.data = _DataProxy(self)
        self.query = _QueryProxy(self)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._collection, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_properties(
        self,
        properties: Dict[str, Any],
        op: str,
    ) -> Dict[str, Any]:
        props = dict(properties or {})
        body = coerce_text(props.get(self._text_property) or props.get("text") or "")
        if not body:
            return props
        records = self.shell.scan_writes([body], source_type="weaviate")
        safe = self.shell.apply_policy(records)
        target_key = self._text_property if self._text_property in props else (
            "text" if "text" in props else self._text_property
        )
        props[target_key] = safe[0]
        if records[0].metadata_patch:
            props.update(records[0].metadata_patch)
        return props

    def _decorate_response(self, response: Any) -> None:
        objects = getattr(response, "objects", None) or []
        if not objects:
            return
        contents = []
        for obj in objects:
            props = getattr(obj, "properties", None) or {}
            text = props.get(self._text_property) or props.get("text") or ""
            contents.append(coerce_text(text))
        patches = self.shell.score_reads(contents, source_type="weaviate")
        for obj, patch in zip(objects, patches):
            props = getattr(obj, "properties", None)
            if isinstance(props, dict):
                props.update(patch)


__all__ = ["MemgarWeaviateCollection", "WEAVIATE_AVAILABLE"]
