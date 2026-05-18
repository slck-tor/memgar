"""Common scaffolding for vector-store integrations.

Each vendor-specific integration (Pinecone, Weaviate, Chroma, Qdrant) needs:

  - A way to extract free-text from heterogeneous payloads (Pinecone shoves it
    in `metadata.text`, Chroma exposes it as a top-level `documents` field,
    Qdrant uses `payload`, Weaviate uses `properties`).
  - A consistent write-time policy (BLOCK / SANITIZE / ALLOW + audit).
  - A consistent read-time decoration (risk_score, threats list).

`VectorStoreSecurityShell` centralises those concerns so the vendor adapters
stay small and focused on adapting argument shapes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from memgar import Analyzer, MemoryEntry
from memgar.models import AnalysisResult, Decision

logger = logging.getLogger("memgar.integrations.vector")


class WritePolicy(str, Enum):
    """How to handle BLOCK / SUSPICIOUS verdicts on writes."""

    BLOCK = "block"        # Raise — payload never reaches the store
    SANITIZE = "sanitize"  # Replace content with `[blocked by memgar: <ids>]`
    AUDIT_ONLY = "audit"   # Allow write, attach risk metadata, log


class VectorWriteBlocked(Exception):
    """Raised when a write is blocked by `WritePolicy.BLOCK`."""

    def __init__(self, content: str, risk_score: int, decision: str, threat_ids: list):
        self.content = content
        self.risk_score = risk_score
        self.decision = decision
        self.threat_ids = list(threat_ids)
        super().__init__(
            f"memgar blocked vector write: risk={risk_score} "
            f"decision={decision} ids={','.join(self.threat_ids[:5])}"
        )


@dataclass
class WriteScanRecord:
    """Per-document result of a batched scan."""

    index: int
    content: str
    decision: str
    risk_score: int
    threat_ids: List[str] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    blocked: bool = False
    metadata_patch: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VectorStoreSecurityShell:
    """Shared write-scan / read-score logic for vector-store integrations."""

    analyzer: Optional[Analyzer] = None
    write_policy: WritePolicy = WritePolicy.BLOCK
    min_risk_to_act: int = 40
    attach_metadata: bool = True
    sanitized_replacement: str = "[blocked by memgar]"
    on_block: Optional[Callable[[WriteScanRecord], None]] = None

    def __post_init__(self) -> None:
        if isinstance(self.write_policy, str):
            self.write_policy = WritePolicy(self.write_policy)
        self.analyzer = self.analyzer or Analyzer(use_llm=False)

    # ------------------------------------------------------------------
    # Write side — runs Analyzer over each candidate document
    # ------------------------------------------------------------------

    def scan_writes(
        self,
        contents: Sequence[str],
        *,
        source_type: str = "rag",
        source_ids: Optional[Sequence[str]] = None,
    ) -> List[WriteScanRecord]:
        """Scan each candidate write and return a per-document record.

        Caller is responsible for actually applying the policy (raising,
        substituting content, etc.) — `apply_policy` is a convenience helper
        that does it for the common case.
        """
        records: List[WriteScanRecord] = []
        for idx, content in enumerate(contents):
            sid = source_ids[idx] if source_ids and idx < len(source_ids) else None
            entry = MemoryEntry(
                content=content,
                source_type=source_type,
                source_id=sid or "",
            )
            scan = self.analyzer.analyze(entry)
            rec = WriteScanRecord(
                index=idx,
                content=content,
                decision=scan.decision.value,
                risk_score=int(scan.risk_score),
                threat_ids=sorted({t.threat.id for t in scan.threats}),
            )
            if (
                scan.decision == Decision.BLOCK
                or scan.risk_score >= self.min_risk_to_act
            ):
                rec.blocked = self.write_policy == WritePolicy.BLOCK
                rec.metadata_patch = {
                    "memgar_risk_score": rec.risk_score,
                    "memgar_decision": rec.decision,
                    "memgar_threat_ids": rec.threat_ids,
                }
                if self.write_policy == WritePolicy.SANITIZE:
                    rec.sanitized_content = (
                        f"{self.sanitized_replacement} "
                        f"(risk={rec.risk_score}, ids={','.join(rec.threat_ids[:3])})"
                    )
                if rec.blocked and self.on_block is not None:
                    try:
                        self.on_block(rec)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("on_block callback failed: %s", exc)
            records.append(rec)
        return records

    def apply_policy(
        self,
        records: Sequence[WriteScanRecord],
    ) -> List[str]:
        """Return the contents to actually write, raising for blocked records.

        Raises `VectorWriteBlocked` on the first blocked record when policy
        is BLOCK. Otherwise returns the (possibly sanitized) content list.
        """
        out: List[str] = []
        for rec in records:
            if rec.blocked:
                raise VectorWriteBlocked(
                    content=rec.content,
                    risk_score=rec.risk_score,
                    decision=rec.decision,
                    threat_ids=rec.threat_ids,
                )
            if rec.sanitized_content is not None:
                out.append(rec.sanitized_content)
            else:
                out.append(rec.content)
        return out

    # ------------------------------------------------------------------
    # Read side — decorates retrieved documents with risk metadata
    # ------------------------------------------------------------------

    def score_reads(
        self,
        contents: Sequence[str],
        *,
        source_type: str = "rag",
    ) -> List[Dict[str, Any]]:
        """Score each retrieved document; return a list of metadata patches.

        Caller stitches the patch into the vendor-specific result shape
        (Pinecone's match.metadata, Chroma's metadatas[i], etc.).
        """
        patches: List[Dict[str, Any]] = []
        for content in contents:
            entry = MemoryEntry(content=content, source_type=source_type)
            scan = self.analyzer.analyze(entry)
            patches.append({
                "memgar_risk_score": int(scan.risk_score),
                "memgar_decision": scan.decision.value,
                "memgar_threat_ids": sorted({t.threat.id for t in scan.threats}),
            })
        return patches


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def coerce_text(value: Any) -> str:
    """Best-effort coercion of vendor payloads to a single scannable string.

    Vendors mix conventions — `text`, `page_content`, `document`, `body`,
    `content`, `_source.content`. We probe the common keys then fall back
    to `str()`.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    if isinstance(value, dict):
        for key in (
            "text", "page_content", "document", "content", "body",
            "raw_text", "data",
        ):
            if key in value and isinstance(value[key], str):
                return value[key]
        # Nested e.g. {"_source": {"content": "..."}}
        if "_source" in value and isinstance(value["_source"], dict):
            return coerce_text(value["_source"])
    return str(value)


__all__ = [
    "WritePolicy",
    "WriteScanRecord",
    "VectorStoreSecurityShell",
    "VectorWriteBlocked",
    "coerce_text",
]
