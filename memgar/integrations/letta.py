"""Letta (MemGPT) integration — secure wrapper for Letta clients.

Letta (https://docs.letta.com, formerly MemGPT) is the memory-centric agent
framework that pioneered hierarchical context management: core memory blocks
(always-on system context), archival memory (long-term searchable storage),
and recall memory (conversation history).

This module provides `MemgarLettaGuard`, a wrapper around `letta.Letta` or
`letta_client.Letta` that:

  - Scans `insert_archival_memory` payloads before write.
  - Scores `query_archival_memory` results with risk metadata.
  - Optionally scans `update_memory_block` writes to core memory blocks
    (most prone to persistent poisoning since they're always in-context).

Letta exposes two API styles — sync (`client.agents.archival_memory.create`)
and the legacy direct methods (`client.insert_archival_memory(...)`). The
wrapper handles both by detecting which methods exist on the underlying
client.

Usage:
    from letta_client import Letta
    from memgar.integrations.letta import MemgarLettaGuard

    client = MemgarLettaGuard(Letta(token="..."))
    client.insert_archival_memory(agent_id="...", memory="User prefers dark mode")
    results = client.query_archival_memory(agent_id="...", query="dark mode")
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

logger = logging.getLogger("memgar.integrations.letta")


try:
    import letta  # noqa: F401
    LETTA_AVAILABLE = True
except ImportError:
    try:
        import letta_client  # noqa: F401
        LETTA_AVAILABLE = True
    except ImportError:
        LETTA_AVAILABLE = False


class MemgarLettaGuard:
    """Wraps a Letta client with memgar write-scanning + read-scoring.

    Args:
        client: A Letta or letta-client instance.
        analyzer: Optional pre-configured `Analyzer`.
        write_policy: `block`, `sanitize`, or `audit`.
        min_risk_to_act: Risk score threshold for policy activation.
        guard_core_memory: When True, also wraps core-memory block updates
            (`update_memory_block`). Defaults to True since core blocks are
            always-on context and the highest-leverage poisoning target.
    """

    def __init__(
        self,
        client: Any,
        *,
        analyzer: Optional[Analyzer] = None,
        write_policy: Union[WritePolicy, str] = WritePolicy.BLOCK,
        min_risk_to_act: int = 40,
        guard_core_memory: bool = True,
    ) -> None:
        self._client = client
        self._guard_core_memory = guard_core_memory
        self.shell = VectorStoreSecurityShell(
            analyzer=analyzer,
            write_policy=write_policy,
            min_risk_to_act=min_risk_to_act,
        )

    # ------------------------------------------------------------------
    # Archival memory (long-term searchable)
    # ------------------------------------------------------------------

    def insert_archival_memory(
        self,
        agent_id: str,
        memory: str,
        **kwargs: Any,
    ) -> Any:
        records = self.shell.scan_writes(
            [memory], source_type="letta_archival", source_ids=[agent_id]
        )
        safe = self.shell.apply_policy(records)[0]
        # Try both APIs — direct method first, then nested client.agents.archival_memory.create
        if hasattr(self._client, "insert_archival_memory"):
            return self._client.insert_archival_memory(
                agent_id=agent_id, memory=safe, **kwargs
            )
        return self._client.agents.archival_memory.create(
            agent_id=agent_id, text=safe, **kwargs
        )

    def query_archival_memory(
        self,
        agent_id: str,
        query: str,
        limit: int = 10,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._client, "query_archival_memory"):
            results = self._client.query_archival_memory(
                agent_id=agent_id, query=query, limit=limit, **kwargs
            )
        else:
            results = self._client.agents.archival_memory.list(
                agent_id=agent_id, **kwargs
            )
        return self._decorate_results(results)

    # ------------------------------------------------------------------
    # Core memory blocks (always-on context)
    # ------------------------------------------------------------------

    def update_memory_block(
        self,
        agent_id: str,
        block_label: str,
        value: str,
        **kwargs: Any,
    ) -> Any:
        if self._guard_core_memory:
            records = self.shell.scan_writes(
                [value],
                source_type="letta_core",
                source_ids=[f"{agent_id}:{block_label}"],
            )
            value = self.shell.apply_policy(records)[0]
        if hasattr(self._client, "update_memory_block"):
            return self._client.update_memory_block(
                agent_id=agent_id, block_label=block_label, value=value, **kwargs
            )
        return self._client.agents.blocks.update(
            agent_id=agent_id, block_label=block_label, value=value, **kwargs
        )

    # ------------------------------------------------------------------
    # Passthroughs
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Pass through any Letta method we haven't explicitly wrapped."""
        return getattr(self._client, name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decorate_results(self, results: Any) -> Any:
        items = results if isinstance(results, list) else getattr(results, "data", None) or []
        if not isinstance(items, list):
            return results
        bodies: List[str] = []
        for item in items:
            if isinstance(item, dict):
                bodies.append(coerce_text(item.get("text") or item.get("memory") or item))
            else:
                bodies.append(coerce_text(getattr(item, "text", None) or getattr(item, "memory", "") or str(item)))
        patches = self.shell.score_reads(bodies, source_type="letta")
        for item, patch in zip(items, patches):
            if isinstance(item, dict):
                meta = item.setdefault("metadata", {})
                meta.update(patch)
            else:
                # SDK object — try to attach as attribute
                try:
                    setattr(item, "memgar_risk_score", patch["memgar_risk_score"])
                    setattr(item, "memgar_decision", patch["memgar_decision"])
                except Exception:  # noqa: BLE001
                    pass
        return results


__all__ = ["MemgarLettaGuard", "LETTA_AVAILABLE"]
