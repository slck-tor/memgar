"""
MemoryVault — cryptographically signed memory snapshots with diff and rollback.

The Problem
-----------
``MemoryIntegrityStore`` tracks per-entry hashes and can roll back one entry.
``MemoryLedger`` keeps an append-only chain. Neither can:

  * Take a **full-store snapshot** (all entries at once) and sign it
  * **Diff** two snapshots to show exactly what changed, was added, or deleted
  * Produce a **rollback plan** ("here are 12 entries to restore") that a human
    or automated system can review *before* applying
  * **Apply** the rollback and return the restored entries so the caller can
    write them back to any storage backend

This module closes those gaps.

Architecture
------------
::

  MemoryVault
    ├── register(entry)            ← call after every safe memory write
    ├── take_snapshot(label)       ← signed point-in-time manifest
    ├── verify_current()           ← compare live entries vs latest snapshot
    ├── verify_snapshot(id)        ← verify a specific snapshot's signature
    ├── diff(snap_a_id, snap_b_id) ← what changed between two snapshots
    ├── rollback(snapshot_id)      ← build RollbackPlan (no writes yet)
    └── apply_rollback(plan)       ← execute the plan; returns safe entries

Signing
-------
Ed25519 signing is **optional**.  If no private key is provided, snapshots are
unsigned (root_hash still provides integrity, just not authenticity).  If the
``cryptography`` package is not installed, signing is silently skipped.

Provide a private key to ``MemoryVault(signing_key=<Ed25519PrivateKey>)`` to
enable signing; use ``MemoryVault.generate_signing_key()`` for key generation.

Storage
-------
Snapshots are kept in-memory by default. Pass ``db_path=`` to persist them
to SQLite (survives process restarts, recommended for production).

Usage
-----
::

    from memgar.memory_vault import MemoryVault
    from memgar.models import MemoryEntry

    vault = MemoryVault()

    # 1. Register each entry as it passes analysis
    entry = MemoryEntry(content="User prefers dark mode", source_id="pref-1")
    vault.register(entry)

    # 2. Take a signed snapshot after the agent has a stable, trusted state
    snap = vault.take_snapshot(label="post-onboarding")
    print(snap.id, snap.root_hash[:16])

    # -- later, after suspected poisoning --

    # 3. Verify current live state vs last snapshot
    report = vault.verify_current()
    for v in report.violations:
        print(f"TAMPERED: {v.entry_id}")

    # 4. Build a rollback plan (dry-run, no writes)
    plan = vault.rollback(snap.id)
    print(plan.summary())         # "Will restore 3 entries, delete 1 new entry"

    # 5. Apply (caller writes .safe_content back to their vector store)
    restored = vault.apply_rollback(plan)
    for entry in restored:
        vector_store.upsert(entry.entry_id, entry.content)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SnapshotEntry:
    """One entry captured inside a VaultSnapshot."""
    entry_id: str
    content_hash: str     # SHA-256 hex
    content: str
    source_type: str = "unknown"
    source_id: str = ""
    captured_ts: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "content_hash": self.content_hash,
            "content": self.content,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "captured_ts": self.captured_ts,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SnapshotEntry":
        return cls(
            entry_id=d["entry_id"],
            content_hash=d["content_hash"],
            content=d["content"],
            source_type=d.get("source_type", "unknown"),
            source_id=d.get("source_id", ""),
            captured_ts=float(d.get("captured_ts", 0.0)),
            metadata=d.get("metadata", {}),
        )


@dataclass
class VaultSnapshot:
    """
    Signed point-in-time manifest of all tracked memory entries.

    Attributes:
        id: UUID for this snapshot.
        label: Human-readable label (e.g. "post-onboarding").
        ts: Unix epoch when the snapshot was taken.
        entry_count: Number of entries captured.
        root_hash: SHA-256 of the sorted concatenation of all entry hashes.
            Changing any entry changes the root hash.
        entries: Map of entry_id → SnapshotEntry.
        signature: Base64 Ed25519 signature over root_hash (empty if unsigned).
        signed: True if a signing key was available.
    """
    id: str
    label: str
    ts: float
    entry_count: int
    root_hash: str
    entries: Dict[str, SnapshotEntry]
    signature: str = ""
    signed: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "ts": self.ts,
            "entry_count": self.entry_count,
            "root_hash": self.root_hash,
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
            "signature": self.signature,
            "signed": self.signed,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "VaultSnapshot":
        return cls(
            id=d["id"],
            label=d.get("label", ""),
            ts=float(d.get("ts", 0.0)),
            entry_count=int(d.get("entry_count", 0)),
            root_hash=d["root_hash"],
            entries={k: SnapshotEntry.from_dict(v) for k, v in d.get("entries", {}).items()},
            signature=d.get("signature", ""),
            signed=bool(d.get("signed", False)),
        )


@dataclass
class DiffEntry:
    """A single changed entry between two snapshots."""
    entry_id: str
    hash_before: str
    hash_after: str
    content_before: str
    content_after: str

    def summary(self) -> str:
        before_words = len(self.content_before.split())
        after_words = len(self.content_after.split())
        return (
            f"[MODIFIED] {self.entry_id}  "
            f"({before_words}w → {after_words}w, "
            f"hash {self.hash_before[:8]}…→{self.hash_after[:8]}…)"
        )


@dataclass
class VaultDiff:
    """
    What changed between two VaultSnapshots.

    Attributes:
        snapshot_a_id: Older (reference) snapshot.
        snapshot_b_id: Newer snapshot (or "live" if comparing against current state).
        added: Entry IDs that appear in B but not A (new entries since snapshot).
        deleted: Entry IDs that appear in A but not B (entries removed since snapshot).
        modified: Entries that exist in both but whose content changed.
    """
    snapshot_a_id: str
    snapshot_b_id: str
    added: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    modified: List[DiffEntry] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not (self.added or self.deleted or self.modified)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.deleted) + len(self.modified)

    def summary(self) -> str:
        if self.is_clean:
            return "No changes detected — memory state is identical."
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.deleted:
            parts.append(f"{len(self.deleted)} deleted")
        return f"Memory diff: {', '.join(parts)} ({self.total_changes} total changes)"

    def to_dict(self) -> dict:
        return {
            "snapshot_a_id": self.snapshot_a_id,
            "snapshot_b_id": self.snapshot_b_id,
            "added": self.added,
            "deleted": self.deleted,
            "modified": [
                {
                    "entry_id": m.entry_id,
                    "hash_before": m.hash_before,
                    "hash_after": m.hash_after,
                }
                for m in self.modified
            ],
            "is_clean": self.is_clean,
            "total_changes": self.total_changes,
        }


@dataclass
class RollbackPlan:
    """
    A proposed rollback to a specific snapshot — no writes until apply_rollback().

    Attributes:
        target_snapshot_id: The snapshot to restore to.
        diff: What will change (modified/added/deleted).
        entries_to_restore: Entries that will be written back (modified + deleted-from-live).
        entry_ids_to_delete: Entry IDs present in live memory but not in the target
            snapshot (should be deleted from the caller's vector store).
        confirmed: Set to True by the caller before passing to apply_rollback().
    """
    target_snapshot_id: str
    diff: VaultDiff
    entries_to_restore: List[SnapshotEntry]
    entry_ids_to_delete: List[str]
    confirmed: bool = False

    def summary(self) -> str:
        lines = [
            f"Rollback plan → snapshot {self.target_snapshot_id[:8]}…",
            f"  Entries to restore : {len(self.entries_to_restore)}",
            f"  Entries to delete  : {len(self.entry_ids_to_delete)}",
            f"  Diff summary       : {self.diff.summary()}",
            f"  Status             : {'CONFIRMED' if self.confirmed else 'PENDING — call plan.confirmed = True to apply'}",
        ]
        return "\n".join(lines)


@dataclass
class VaultVerificationResult:
    """Result of verify_current() or verify_snapshot()."""
    snapshot_id: str
    verified_at: float
    is_valid: bool
    signature_valid: Optional[bool]   # None if snapshot was unsigned
    violations: List[Any]             # IntegrityViolation from memory_integrity
    tampered_ids: List[str]
    root_hash_match: bool

    def summary(self) -> str:
        if self.is_valid:
            return f"Vault OK — snapshot {self.snapshot_id[:8]}… verified, no tampering."
        parts = []
        if not self.root_hash_match:
            parts.append("root hash mismatch")
        if self.signature_valid is False:
            parts.append("signature invalid")
        if self.tampered_ids:
            parts.append(f"{len(self.tampered_ids)} tampered entries: {self.tampered_ids[:3]}")
        return f"Vault COMPROMISED — {'; '.join(parts)}"


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _root_hash(entries: Dict[str, SnapshotEntry]) -> str:
    """Deterministic Merkle-root-style hash of all entry hashes."""
    sorted_hashes = "".join(
        f"{eid}:{e.content_hash}"
        for eid, e in sorted(entries.items())
    )
    return _sha256(sorted_hashes)


def _sign(data: str, private_key: Any) -> str:
    """Sign *data* with *private_key* (Ed25519). Returns base64 string."""
    try:
        sig_bytes = private_key.sign(data.encode("utf-8"))
        return base64.b64encode(sig_bytes).decode("ascii")
    except Exception as exc:
        logger.warning("Vault signing failed: %s", exc)
        return ""


def _verify_sig(data: str, signature_b64: str, public_key: Any) -> bool:
    """Verify an Ed25519 signature. Returns False on any error."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, data.encode("utf-8"))
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# MemoryVault
# ─────────────────────────────────────────────────────────────────────────────

class MemoryVault:
    """
    Cryptographically signed memory snapshots with diff and rollback.

    Args:
        db_path: SQLite path for snapshot persistence (None = in-memory only).
        signing_key: Ed25519PrivateKey from the ``cryptography`` package.
            Use ``MemoryVault.generate_signing_key()`` to create one.
        max_snapshots: Maximum number of snapshots to retain.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        signing_key: Optional[Any] = None,
        max_snapshots: int = 50,
    ) -> None:
        self._lock = threading.Lock()
        self._signing_key = signing_key
        self._public_key: Optional[Any] = None
        self._max_snapshots = max_snapshots
        self._db: Optional[sqlite3.Connection] = None

        # In-memory state: entry_id → latest SnapshotEntry (live registry)
        self._live: Dict[str, SnapshotEntry] = {}
        # Ordered list of VaultSnapshot
        self._snapshots: List[VaultSnapshot] = []

        if signing_key is not None:
            try:
                self._public_key = signing_key.public_key()
            except Exception as exc:
                logger.warning("Could not derive public key from signing key: %s", exc)

        if db_path:
            self._init_db(db_path)

    # ── Key generation ────────────────────────────────────────────────────────

    @staticmethod
    def generate_signing_key() -> Tuple[Any, str]:
        """
        Generate a new Ed25519 signing key pair.

        Returns:
            (private_key, public_key_b64): The private key object and the
            base64-encoded public key suitable for storage/config.

        Requires the ``cryptography`` package.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes_raw()
        return private_key, base64.b64encode(pub_bytes).decode("ascii")

    @staticmethod
    def public_key_from_b64(b64: str) -> Any:
        """Load an Ed25519 public key from base64-encoded bytes."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_bytes = base64.b64decode(b64)
        return Ed25519PublicKey.from_public_bytes(key_bytes)

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        entry: Any,
        entry_id: Optional[str] = None,
    ) -> SnapshotEntry:
        """
        Register a memory entry as a trusted baseline in the live registry.

        Call this every time a memory entry passes analysis and is written to
        storage.  The live registry is what ``take_snapshot()`` captures.

        Args:
            entry: A ``MemoryEntry`` or any object with a ``.content`` attribute.
            entry_id: Stable identifier; derived from source_id or content if None.
        """
        content = getattr(entry, "content", str(entry))
        source_type = getattr(entry, "source_type", "unknown")
        source_id = getattr(entry, "source_id", "") or ""
        metadata = dict(getattr(entry, "metadata", {}))

        eid = entry_id or (f"src:{source_id}" if source_id else f"hash:{_sha256(content)[:16]}")

        se = SnapshotEntry(
            entry_id=eid,
            content_hash=_sha256(content),
            content=content,
            source_type=source_type,
            source_id=source_id,
            captured_ts=time.time(),
            metadata=metadata,
        )
        with self._lock:
            self._live[eid] = se
        logger.debug("Vault.register: %s hash=%s", eid, se.content_hash[:12])
        return se

    def unregister(self, entry_id: str) -> bool:
        """Remove an entry from the live registry (e.g. after intentional deletion)."""
        with self._lock:
            return self._live.pop(entry_id, None) is not None

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def take_snapshot(self, label: str = "") -> VaultSnapshot:
        """
        Take a signed snapshot of the entire live registry.

        Returns a ``VaultSnapshot`` with a deterministic root hash and an
        optional Ed25519 signature.  Raises no exceptions — if signing fails,
        the snapshot is returned unsigned.
        """
        with self._lock:
            entries = {eid: SnapshotEntry(**se.__dict__) for eid, se in self._live.items()}

        root = _root_hash(entries)
        sig = ""
        signed = False
        if self._signing_key is not None:
            sig = _sign(root, self._signing_key)
            signed = bool(sig)

        snap = VaultSnapshot(
            id=str(uuid.uuid4()),
            label=label or f"snapshot-{int(time.time())}",
            ts=time.time(),
            entry_count=len(entries),
            root_hash=root,
            entries=entries,
            signature=sig,
            signed=signed,
        )
        with self._lock:
            self._snapshots.append(snap)
            if len(self._snapshots) > self._max_snapshots:
                self._snapshots = self._snapshots[-self._max_snapshots:]

        self._persist_snapshot(snap)
        logger.info(
            "Vault snapshot: id=%s label=%r entries=%d root=%s signed=%s",
            snap.id[:8], snap.label, snap.entry_count, snap.root_hash[:16], snap.signed,
        )
        return snap

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_current(
        self, snapshot_id: Optional[str] = None
    ) -> VaultVerificationResult:
        """
        Compare the live registry against a snapshot.

        Args:
            snapshot_id: Snapshot to compare against. Uses the latest if None.

        Returns:
            VaultVerificationResult — check .is_valid and .violations.
        """
        snap = self._get_snapshot(snapshot_id)
        if snap is None:
            return VaultVerificationResult(
                snapshot_id=snapshot_id or "none",
                verified_at=time.time(),
                is_valid=True,
                signature_valid=None,
                violations=[],
                tampered_ids=[],
                root_hash_match=True,
            )

        with self._lock:
            live_entries = dict(self._live)

        tampered_ids = []
        violations = []
        for eid, snap_entry in snap.entries.items():
            live_entry = live_entries.get(eid)
            if live_entry is None:
                tampered_ids.append(eid)   # entry disappeared
                continue
            if live_entry.content_hash != snap_entry.content_hash:
                tampered_ids.append(eid)
                # Build IntegrityViolation-like object
                violations.append({
                    "entry_id": eid,
                    "expected_hash": snap_entry.content_hash,
                    "actual_hash": live_entry.content_hash,
                    "snapshot_ts": snap.ts,
                    "detected_ts": time.time(),
                    "content_at_snapshot": snap_entry.content,
                })

        # Recompute root from live to compare
        live_root = _root_hash(live_entries) if live_entries else _root_hash({})
        root_match = (live_root == snap.root_hash) and not tampered_ids

        # Verify signature if present
        sig_valid: Optional[bool] = None
        if snap.signed and snap.signature and self._public_key is not None:
            sig_valid = _verify_sig(snap.root_hash, snap.signature, self._public_key)

        is_valid = root_match and (sig_valid is not False) and not tampered_ids

        result = VaultVerificationResult(
            snapshot_id=snap.id,
            verified_at=time.time(),
            is_valid=is_valid,
            signature_valid=sig_valid,
            violations=violations,
            tampered_ids=tampered_ids,
            root_hash_match=root_match,
        )

        if not is_valid:
            logger.warning("VAULT INTEGRITY FAILURE: %s", result.summary())

        return result

    def verify_snapshot(self, snapshot_id: str) -> VaultVerificationResult:
        """
        Verify a snapshot's own internal integrity (signature + root hash consistency).

        Does not compare against live entries — use verify_current() for that.
        """
        snap = self._get_snapshot(snapshot_id)
        if snap is None:
            return VaultVerificationResult(
                snapshot_id=snapshot_id,
                verified_at=time.time(),
                is_valid=False,
                signature_valid=None,
                violations=[{"error": "snapshot not found"}],
                tampered_ids=[],
                root_hash_match=False,
            )

        # Recompute root from stored entries
        recomputed_root = _root_hash(snap.entries)
        root_match = recomputed_root == snap.root_hash

        sig_valid: Optional[bool] = None
        if snap.signed and snap.signature and self._public_key is not None:
            sig_valid = _verify_sig(snap.root_hash, snap.signature, self._public_key)

        is_valid = root_match and (sig_valid is not False)
        return VaultVerificationResult(
            snapshot_id=snap.id,
            verified_at=time.time(),
            is_valid=is_valid,
            signature_valid=sig_valid,
            violations=[] if is_valid else [{"error": "root hash mismatch or invalid signature"}],
            tampered_ids=[] if root_match else list(snap.entries.keys()),
            root_hash_match=root_match,
        )

    # ── Diff ──────────────────────────────────────────────────────────────────

    def diff(
        self,
        snapshot_a_id: Optional[str] = None,
        snapshot_b_id: Optional[str] = None,
    ) -> VaultDiff:
        """
        Compute the diff between two snapshots.

        If snapshot_b_id is None, compares snapshot_a against the **live registry**.
        If snapshot_a_id is None, uses the latest snapshot.

        This is the core of the "what was poisoned" answer.
        """
        snap_a = self._get_snapshot(snapshot_a_id)
        if snap_a is None:
            return VaultDiff(
                snapshot_a_id=snapshot_a_id or "none",
                snapshot_b_id=snapshot_b_id or "live",
            )

        if snapshot_b_id is None:
            # Compare against live
            with self._lock:
                entries_b = dict(self._live)
            b_id = "live"
        else:
            snap_b = self._get_snapshot(snapshot_b_id)
            if snap_b is None:
                return VaultDiff(snapshot_a_id=snap_a.id, snapshot_b_id=snapshot_b_id or "none")
            entries_b = snap_b.entries
            b_id = snap_b.id

        entries_a = snap_a.entries
        ids_a = set(entries_a)
        ids_b = set(entries_b)

        added = sorted(ids_b - ids_a)
        deleted = sorted(ids_a - ids_b)
        modified = []
        for eid in sorted(ids_a & ids_b):
            ea = entries_a[eid]
            eb = entries_b[eid]
            if ea.content_hash != eb.content_hash:
                modified.append(DiffEntry(
                    entry_id=eid,
                    hash_before=ea.content_hash,
                    hash_after=eb.content_hash,
                    content_before=ea.content,
                    content_after=eb.content,
                ))

        return VaultDiff(
            snapshot_a_id=snap_a.id,
            snapshot_b_id=b_id,
            added=added,
            deleted=deleted,
            modified=modified,
        )

    # ── Rollback ──────────────────────────────────────────────────────────────

    def rollback(self, snapshot_id: Optional[str] = None) -> RollbackPlan:
        """
        Build a rollback plan to restore the live registry to a snapshot.

        Does NOT modify any state — call ``apply_rollback(plan)`` after setting
        ``plan.confirmed = True`` and verifying the plan with the operator.

        Args:
            snapshot_id: Snapshot to restore to. Uses the latest if None.

        Returns:
            RollbackPlan with full diff and list of entries to restore.
        """
        snap = self._get_snapshot(snapshot_id)
        if snap is None:
            raise ValueError(f"Snapshot {snapshot_id!r} not found")

        delta = self.diff(snapshot_a_id=snap.id, snapshot_b_id=None)

        # Entries to restore: modified (use snapshot version) + deleted (reappear)
        entries_to_restore: List[SnapshotEntry] = []
        for de in delta.modified:
            entries_to_restore.append(snap.entries[de.entry_id])
        for eid in delta.deleted:
            entries_to_restore.append(snap.entries[eid])

        # Entries to delete: things in live that didn't exist in snapshot
        entry_ids_to_delete = list(delta.added)

        plan = RollbackPlan(
            target_snapshot_id=snap.id,
            diff=delta,
            entries_to_restore=entries_to_restore,
            entry_ids_to_delete=entry_ids_to_delete,
            confirmed=False,
        )
        logger.info(
            "Vault rollback plan: target=%s restore=%d delete=%d",
            snap.id[:8], len(entries_to_restore), len(entry_ids_to_delete),
        )
        return plan

    def apply_rollback(self, plan: RollbackPlan) -> List[SnapshotEntry]:
        """
        Apply a confirmed rollback plan to the live registry.

        Args:
            plan: A RollbackPlan with ``plan.confirmed = True``.

        Returns:
            List of SnapshotEntry objects that were restored (caller must write
            these back to their actual storage: vector store, database, etc.).

        Raises:
            RuntimeError: If plan.confirmed is False.
        """
        if not plan.confirmed:
            raise RuntimeError(
                "RollbackPlan is not confirmed. "
                "Set plan.confirmed = True after reviewing the plan summary."
            )

        with self._lock:
            # Restore modified + deleted entries
            for entry in plan.entries_to_restore:
                self._live[entry.entry_id] = entry

            # Remove entries that didn't exist in the target snapshot
            for eid in plan.entry_ids_to_delete:
                self._live.pop(eid, None)

        logger.info(
            "Vault rollback applied: restored=%d deleted=%d target_snapshot=%s",
            len(plan.entries_to_restore),
            len(plan.entry_ids_to_delete),
            plan.target_snapshot_id[:8],
        )
        return list(plan.entries_to_restore)

    # ── Snapshot management ───────────────────────────────────────────────────

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Return metadata (no entry content) for all stored snapshots."""
        with self._lock:
            return [
                {
                    "id": s.id,
                    "label": s.label,
                    "ts": s.ts,
                    "entry_count": s.entry_count,
                    "root_hash": s.root_hash,
                    "signed": s.signed,
                }
                for s in self._snapshots
            ]

    def get_snapshot(self, snapshot_id: str) -> Optional[VaultSnapshot]:
        """Return a specific snapshot by ID (None if not found)."""
        return self._get_snapshot(snapshot_id)

    @property
    def latest_snapshot(self) -> Optional[VaultSnapshot]:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    @property
    def live_entry_count(self) -> int:
        with self._lock:
            return len(self._live)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_snapshot(self, snapshot_id: Optional[str]) -> Optional[VaultSnapshot]:
        with self._lock:
            if not self._snapshots:
                return None
            if snapshot_id is None:
                return self._snapshots[-1]
            for s in reversed(self._snapshots):
                if s.id == snapshot_id or s.id.startswith(snapshot_id):
                    return s
        return None

    # ── Persistence (SQLite) ──────────────────────────────────────────────────

    def _init_db(self, db_path: str) -> None:
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS vault_snapshots (
                id         TEXT PRIMARY KEY,
                label      TEXT NOT NULL,
                ts         REAL NOT NULL,
                entry_count INTEGER NOT NULL,
                root_hash  TEXT NOT NULL,
                payload    TEXT NOT NULL,
                signature  TEXT NOT NULL DEFAULT '',
                signed     INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._db.commit()
        self._load_snapshots_from_db()

    def _persist_snapshot(self, snap: VaultSnapshot) -> None:
        if self._db is None:
            return
        try:
            payload = json.dumps({k: v.to_dict() for k, v in snap.entries.items()})
            self._db.execute(
                """INSERT OR REPLACE INTO vault_snapshots
                   (id, label, ts, entry_count, root_hash, payload, signature, signed)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (snap.id, snap.label, snap.ts, snap.entry_count,
                 snap.root_hash, payload, snap.signature, int(snap.signed)),
            )
            self._db.commit()
        except Exception as exc:
            logger.warning("Vault: failed to persist snapshot: %s", exc)

    def _load_snapshots_from_db(self) -> None:
        if self._db is None:
            return
        try:
            rows = self._db.execute(
                "SELECT * FROM vault_snapshots ORDER BY ts"
            ).fetchall()
            for row in rows:
                entries = {
                    k: SnapshotEntry.from_dict(v)
                    for k, v in json.loads(row["payload"]).items()
                }
                snap = VaultSnapshot(
                    id=row["id"],
                    label=row["label"],
                    ts=float(row["ts"]),
                    entry_count=int(row["entry_count"]),
                    root_hash=row["root_hash"],
                    entries=entries,
                    signature=row["signature"],
                    signed=bool(row["signed"]),
                )
                self._snapshots.append(snap)
        except Exception as exc:
            logger.warning("Vault: failed to load snapshots from DB: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Exports
# ─────────────────────────────────────────────────────────────────────────────

__all__ = [
    "MemoryVault",
    "VaultSnapshot",
    "SnapshotEntry",
    "VaultDiff",
    "DiffEntry",
    "RollbackPlan",
    "VaultVerificationResult",
]
