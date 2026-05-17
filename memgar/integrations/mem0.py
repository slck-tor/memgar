"""Mem0 integration — secure wrapper for `mem0ai.Memory`.

Mem0 (https://github.com/mem0ai/mem0) is the most widely-used memory layer
for LLM agents — 1M+ downloads, used by Cursor, Embedchain, and many custom
agents. It manages long-term, semantically-indexed memory backed by various
vector stores.

This module provides `MemgarMem0Guard`, a wrapper around `mem0.Memory` (or
`memory_client.MemoryClient` for hosted Mem0) that:

  - Scans every `add()` payload through memgar's Analyzer before it is
    written, blocking / sanitizing / auditing per `WritePolicy`.
  - Scores every `search()` result and attaches `memgar_risk_score`,
    `memgar_decision`, `memgar_threat_ids` to each item's metadata for
    downstream trust-aware filtering.

The wrapper preserves Mem0's public API surface, so existing code is a
drop-in upgrade: replace `Memory(...)` with `MemgarMem0Guard(Memory(...))`.

Usage:
    from mem0 import Memory
    from memgar.integrations.mem0 import MemgarMem0Guard

    memory = MemgarMem0Guard(Memory())
    memory.add("User prefers dark mode", user_id="alice")
    results = memory.search("dark mode", user_id="alice")
    for r in results:
        print(r["memory"], r.get("metadata", {}).get("memgar_risk_score"))
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

logger = logging.getLogger("memgar.integrations.mem0")


try:
    from mem0 import Memory  # noqa: F401  -- detection-only
    MEM0_AVAILABLE = True
except ImportError:
    Memory = None  # type: ignore[assignment]
    MEM0_AVAILABLE = False


class MemgarMem0Guard:
    """Memgar wrapper around a Mem0 `Memory` instance.

    Args:
        memory: The Mem0 `Memory` or `MemoryClient` instance to wrap.
        analyzer: Optional pre-configured `Analyzer`. Defaults to
            `Analyzer(use_llm=False)`.
        write_policy: `block`, `sanitize`, or `audit`. Default: `block`.
        min_risk_to_act: Risk threshold (0-100) at which the policy fires.
        attach_metadata: When True (default), risk metadata is added to the
            mem0 entry's `metadata` dict on writes (audit/sanitize paths).

    Attributes:
        shell: The underlying `VectorStoreSecurityShell` (use it for advanced
            scan / score access in your application code).
    """

    def __init__(
        self,
        memory: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
        attach_metadata: bool = True,
    ) -> None:
        self._memory = memory
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
            attach_metadata=attach_metadata,
        )

    # ------------------------------------------------------------------
    # Write side
    # ------------------------------------------------------------------

    def add(
        self,
        messages: Union[str, List[Dict[str, str]]],
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Memgar-scanned `Memory.add()`.

        Drop-in replacement for `mem0.Memory.add`. Scans every message body
        (or the single string) and applies the write policy. On `BLOCK` the
        call raises `VectorWriteBlocked` before mem0 sees the payload.
        """
        bodies = self._extract_bodies(messages)
        sids = [str(user_id or agent_id or run_id or "")] * len(bodies)
        records = self.shell.scan_writes(
            bodies, source_type="mem0", source_ids=sids
        )
        # apply_policy raises on BLOCK or returns sanitized bodies
        safe_bodies = self.shell.apply_policy(records)

        # Patch metadata for audit / sanitize paths
        if self.shell.attach_metadata and records:
            metadata = dict(metadata or {})
            patches = [r.metadata_patch for r in records if r.metadata_patch]
            if patches:
                metadata["memgar"] = patches if len(patches) > 1 else patches[0]

        safe_messages = self._reassemble_messages(messages, safe_bodies)
        return self._memory.add(
            safe_messages,
            user_id=user_id,
            agent_id=agent_id,
            run_id=run_id,
            metadata=metadata,
            **kwargs,
        )

    def update(self, memory_id: str, data: str, **kwargs: Any) -> Any:
        """Memgar-scanned `Memory.update()`."""
        records = self.shell.scan_writes(
            [data], source_type="mem0", source_ids=[memory_id]
        )
        safe = self.shell.apply_policy(records)
        return self._memory.update(memory_id=memory_id, data=safe[0], **kwargs)

    # ------------------------------------------------------------------
    # Read side
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 10,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Memgar-scored `Memory.search()`.

        Each result's metadata gets `memgar_risk_score`, `memgar_decision`,
        `memgar_threat_ids`. Caller can filter on those for trust-aware RAG.
        """
        results = self._memory.search(
            query=query, user_id=user_id, agent_id=agent_id, limit=limit, **kwargs
        )
        # Mem0 returns either a list[dict] or {"results": list[dict]}
        items = self._coerce_results(results)
        if not items:
            return results
        contents = [coerce_text(item.get("memory") or item.get("text") or item) for item in items]
        patches = self.shell.score_reads(contents, source_type="mem0")
        for item, patch in zip(items, patches):
            meta = item.setdefault("metadata", {})
            meta.update(patch)
        return results

    def get(self, memory_id: str) -> Any:
        return self._memory.get(memory_id=memory_id)

    def get_all(self, **kwargs: Any) -> Any:
        return self._memory.get_all(**kwargs)

    def delete(self, memory_id: str, **kwargs: Any) -> Any:
        return self._memory.delete(memory_id=memory_id, **kwargs)

    def history(self, memory_id: str, **kwargs: Any) -> Any:
        return self._memory.history(memory_id=memory_id, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_bodies(
        messages: Union[str, List[Dict[str, str]], List[str]],
    ) -> List[str]:
        if isinstance(messages, str):
            return [messages]
        out: List[str] = []
        for m in messages:
            if isinstance(m, str):
                out.append(m)
            elif isinstance(m, dict):
                out.append(m.get("content") or m.get("text") or "")
            else:
                out.append(str(m))
        return out

    @staticmethod
    def _reassemble_messages(
        original: Union[str, List[Dict[str, str]], List[str]],
        safe_bodies: List[str],
    ) -> Union[str, List[Dict[str, str]], List[str]]:
        if isinstance(original, str):
            return safe_bodies[0] if safe_bodies else ""
        out: List[Any] = []
        for m, body in zip(original, safe_bodies):
            if isinstance(m, dict):
                patched = dict(m)
                if "content" in patched:
                    patched["content"] = body
                elif "text" in patched:
                    patched["text"] = body
                else:
                    patched["content"] = body
                out.append(patched)
            else:
                out.append(body)
        return out

    @staticmethod
    def _coerce_results(results: Any) -> List[Dict[str, Any]]:
        if isinstance(results, dict) and "results" in results:
            items = results["results"]
        elif isinstance(results, list):
            items = results
        else:
            return []
        return [item for item in items if isinstance(item, dict)]


__all__ = ["MemgarMem0Guard", "MEM0_AVAILABLE"]
