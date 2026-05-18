"""Cross-snapshot replay forensics.

When you discover a poisoned entry in your vault, you want to know:

  - When did it first appear?
  - Across which snapshots did it persist?
  - Did the same `source_id` write other suspicious entries?
  - What's the lineage of mutations (every content-hash this entry held)?

`ReplayForensics` answers those questions by walking the snapshot chain
that `MemoryVault` already persists. It is read-only and operates over
any list of `VaultSnapshot` instances — typically `vault._snapshots`.

The motivating threat model: an attacker writes a poisoned memory in
session A and the agent retrieves it in session B days later. Forensic
investigators in session C need a fast way to trace the poison back to
its origin without manually diffing snapshots.

Usage:
    from memgar.memory_vault import MemoryVault
    from memgar.replay_forensics import ReplayForensics

    vault = MemoryVault(db_path="./vault.db")
    forensics = ReplayForensics(vault.snapshots())

    # When was this entry first written?
    appearance = forensics.first_appearance("src:u3")
    print(appearance.snapshot_id, appearance.ts)

    # What other entries did the same source write?
    cohort = forensics.cohort("src:u3", attr="source_id")
    for sib in cohort:
        print(sib.entry_id, sib.first_seen_ts)

    # Did this entry's content change between snapshots?
    lineage = forensics.lineage("src:u3")
    for mutation in lineage:
        print(mutation.snapshot_id, mutation.content_hash, mutation.changed_from)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from memgar.memory_vault import SnapshotEntry, VaultSnapshot


@dataclass
class Appearance:
    """Where an `entry_id` was first observed and where it last persisted."""

    entry_id: str
    first_snapshot_id: str
    first_ts: float
    last_snapshot_id: str
    last_ts: float
    snapshots_seen: int

    @property
    def lifespan_seconds(self) -> float:
        return self.last_ts - self.first_ts

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "first_snapshot_id": self.first_snapshot_id,
            "first_ts": self.first_ts,
            "last_snapshot_id": self.last_snapshot_id,
            "last_ts": self.last_ts,
            "snapshots_seen": self.snapshots_seen,
            "lifespan_seconds": self.lifespan_seconds,
        }


@dataclass
class Mutation:
    """A change in an entry's content_hash between consecutive snapshots."""

    entry_id: str
    snapshot_id: str
    ts: float
    content_hash: str
    content_preview: str
    changed_from: Optional[str] = None
    is_first: bool = False

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "snapshot_id": self.snapshot_id,
            "ts": self.ts,
            "content_hash": self.content_hash,
            "content_preview": self.content_preview,
            "changed_from": self.changed_from,
            "is_first": self.is_first,
        }


@dataclass
class CohortMember:
    """Sibling entry sharing some grouping attribute (source_id, source_type)."""

    entry_id: str
    attr_value: str
    first_seen_ts: float
    first_seen_snapshot_id: str
    last_content_hash: str
    last_content_preview: str

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "attr_value": self.attr_value,
            "first_seen_ts": self.first_seen_ts,
            "first_seen_snapshot_id": self.first_seen_snapshot_id,
            "last_content_hash": self.last_content_hash,
            "last_content_preview": self.last_content_preview,
        }


@dataclass
class SessionTimelineEvent:
    """A single write/mutation/disappearance event in chronological order."""

    ts: float
    snapshot_id: str
    entry_id: str
    event_type: str  # "appear" | "mutate" | "disappear"
    content_hash: str = ""
    content_preview: str = ""

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "snapshot_id": self.snapshot_id,
            "entry_id": self.entry_id,
            "event_type": self.event_type,
            "content_hash": self.content_hash,
            "content_preview": self.content_preview,
        }


# ---------------------------------------------------------------------------
# ReplayForensics
# ---------------------------------------------------------------------------


class ReplayForensics:
    """Read-only forensic queries over a chain of `VaultSnapshot` objects.

    The snapshots are assumed to be chronologically ordered. Pass either a
    list directly, or `vault.snapshots()` if you have a live vault.

    Args:
        snapshots: An ordered sequence of `VaultSnapshot` (oldest first).
    """

    def __init__(self, snapshots: Sequence[VaultSnapshot]) -> None:
        self._snaps: List[VaultSnapshot] = sorted(
            snapshots, key=lambda s: s.ts
        )

    @property
    def snapshot_count(self) -> int:
        return len(self._snaps)

    # ------------------------------------------------------------------
    # Single-entry queries
    # ------------------------------------------------------------------

    def first_appearance(self, entry_id: str) -> Optional[Appearance]:
        """Return when `entry_id` was first and last seen, or `None` if absent."""
        first: Optional[VaultSnapshot] = None
        last: Optional[VaultSnapshot] = None
        seen = 0
        for snap in self._snaps:
            if entry_id in snap.entries:
                if first is None:
                    first = snap
                last = snap
                seen += 1
        if first is None or last is None:
            return None
        return Appearance(
            entry_id=entry_id,
            first_snapshot_id=first.id,
            first_ts=first.ts,
            last_snapshot_id=last.id,
            last_ts=last.ts,
            snapshots_seen=seen,
        )

    def lineage(self, entry_id: str, *, preview_chars: int = 120) -> List[Mutation]:
        """Return the full mutation chain for `entry_id` across snapshots.

        Emits one `Mutation` per snapshot where the entry exists; consecutive
        snapshots with the same content_hash are coalesced — only changes
        produce records (plus the first appearance).
        """
        out: List[Mutation] = []
        prev_hash: Optional[str] = None
        for snap in self._snaps:
            entry = snap.entries.get(entry_id)
            if entry is None:
                continue
            if entry.content_hash == prev_hash:
                continue
            out.append(Mutation(
                entry_id=entry_id,
                snapshot_id=snap.id,
                ts=snap.ts,
                content_hash=entry.content_hash,
                content_preview=entry.content[:preview_chars],
                changed_from=prev_hash,
                is_first=(prev_hash is None),
            ))
            prev_hash = entry.content_hash
        return out

    # ------------------------------------------------------------------
    # Group queries — co-written, same-source, same-type
    # ------------------------------------------------------------------

    def cohort(
        self,
        attr_value: str,
        *,
        attr: str = "source_id",
        preview_chars: int = 120,
    ) -> List[CohortMember]:
        """Return every entry whose `attr` (source_id by default) matches.

        Useful for "what else did this attacker source write?" queries.
        `attr` may be one of: `source_id`, `source_type`.
        """
        if attr not in {"source_id", "source_type"}:
            raise ValueError("attr must be 'source_id' or 'source_type'")
        first_seen: Dict[str, tuple] = {}  # entry_id -> (snapshot, entry)
        last: Dict[str, tuple] = {}
        for snap in self._snaps:
            for eid, entry in snap.entries.items():
                if getattr(entry, attr) != attr_value:
                    continue
                if eid not in first_seen:
                    first_seen[eid] = (snap, entry)
                last[eid] = (snap, entry)
        members: List[CohortMember] = []
        for eid, (snap, entry) in first_seen.items():
            last_snap, last_entry = last[eid]
            members.append(CohortMember(
                entry_id=eid,
                attr_value=attr_value,
                first_seen_ts=snap.ts,
                first_seen_snapshot_id=snap.id,
                last_content_hash=last_entry.content_hash,
                last_content_preview=last_entry.content[:preview_chars],
            ))
        members.sort(key=lambda m: m.first_seen_ts)
        return members

    # ------------------------------------------------------------------
    # Substring search
    # ------------------------------------------------------------------

    def cross_snapshot_search(
        self,
        substring: str,
        *,
        case_sensitive: bool = False,
        preview_chars: int = 120,
    ) -> List[Mutation]:
        """Find every (snapshot, entry) pair whose content contains the substring.

        Returns one `Mutation` per distinct (snapshot, entry_id, content_hash)
        match. Useful for hunting where a known poison phrase appeared.
        """
        needle = substring if case_sensitive else substring.lower()
        out: List[Mutation] = []
        for snap in self._snaps:
            for eid, entry in snap.entries.items():
                haystack = entry.content if case_sensitive else entry.content.lower()
                if needle in haystack:
                    out.append(Mutation(
                        entry_id=eid,
                        snapshot_id=snap.id,
                        ts=snap.ts,
                        content_hash=entry.content_hash,
                        content_preview=entry.content[:preview_chars],
                        changed_from=None,
                        is_first=False,
                    ))
        return out

    # ------------------------------------------------------------------
    # Timeline view
    # ------------------------------------------------------------------

    def session_timeline(
        self,
        attr_value: str,
        *,
        attr: str = "source_id",
        preview_chars: int = 80,
    ) -> List[SessionTimelineEvent]:
        """Render an `attr_value`-scoped chronological event log.

        Emits `appear`, `mutate`, `disappear` events for every entry that ever
        carried the matching `attr` (source_id by default).
        """
        if attr not in {"source_id", "source_type"}:
            raise ValueError("attr must be 'source_id' or 'source_type'")
        events: List[SessionTimelineEvent] = []
        # Track last-seen state per (entry_id) — content_hash + whether still present
        prev_hashes: Dict[str, str] = {}
        for snap in self._snaps:
            matching = {
                eid: entry for eid, entry in snap.entries.items()
                if getattr(entry, attr) == attr_value
            }
            for eid, entry in matching.items():
                if eid not in prev_hashes:
                    events.append(SessionTimelineEvent(
                        ts=snap.ts,
                        snapshot_id=snap.id,
                        entry_id=eid,
                        event_type="appear",
                        content_hash=entry.content_hash,
                        content_preview=entry.content[:preview_chars],
                    ))
                elif prev_hashes[eid] != entry.content_hash:
                    events.append(SessionTimelineEvent(
                        ts=snap.ts,
                        snapshot_id=snap.id,
                        entry_id=eid,
                        event_type="mutate",
                        content_hash=entry.content_hash,
                        content_preview=entry.content[:preview_chars],
                    ))
                prev_hashes[eid] = entry.content_hash
            # Disappear: entry was present before but missing now
            disappeared = set(prev_hashes) - set(matching)
            for eid in disappeared:
                events.append(SessionTimelineEvent(
                    ts=snap.ts,
                    snapshot_id=snap.id,
                    entry_id=eid,
                    event_type="disappear",
                ))
                # Remove from tracking so we don't repeat
                del prev_hashes[eid]
        return events

    # ------------------------------------------------------------------
    # Index summary
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Coarse stats about the entire snapshot chain."""
        if not self._snaps:
            return {
                "snapshot_count": 0,
                "first_ts": None,
                "last_ts": None,
                "distinct_entries": 0,
                "distinct_sources": 0,
            }
        all_eids = set()
        all_sources = set()
        for snap in self._snaps:
            for eid, entry in snap.entries.items():
                all_eids.add(eid)
                if entry.source_id:
                    all_sources.add(entry.source_id)
        return {
            "snapshot_count": len(self._snaps),
            "first_ts": self._snaps[0].ts,
            "last_ts": self._snaps[-1].ts,
            "distinct_entries": len(all_eids),
            "distinct_sources": len(all_sources),
        }


__all__ = [
    "ReplayForensics",
    "Appearance",
    "Mutation",
    "CohortMember",
    "SessionTimelineEvent",
]
