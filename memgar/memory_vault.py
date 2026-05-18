"""
MemoryVault - signed memory snapshots with diff and rollback.

Snapshots bind content, source/provenance metadata, and snapshot manifest fields
into integrity checks and Ed25519 signatures. This prevents attackers from
changing metadata or provenance while preserving content hashes.
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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SIGNATURE_VERSION = 2


@dataclass
class SnapshotEntry:
    entry_id: str
    content_hash: str
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

    def integrity_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "content_hash": self.content_hash,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SnapshotEntry":
        return cls(
            entry_id=data["entry_id"],
            content_hash=data["content_hash"],
            content=data["content"],
            source_type=data.get("source_type", "unknown"),
            source_id=data.get("source_id", ""),
            captured_ts=float(data.get("captured_ts", 0.0)),
            metadata=dict(data.get("metadata", {}) or {}),
        )


@dataclass
class VaultSnapshot:
    id: str
    label: str
    ts: float
    entry_count: int
    root_hash: str
    entries: Dict[str, SnapshotEntry]
    signature: str = ""
    signed: bool = False
    signature_version: int = SIGNATURE_VERSION
    merkle_root: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "ts": self.ts,
            "entry_count": self.entry_count,
            "root_hash": self.root_hash,
            "entries": {key: value.to_dict() for key, value in self.entries.items()},
            "signature": self.signature,
            "signed": self.signed,
            "signature_version": self.signature_version,
            "merkle_root": self.merkle_root,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultSnapshot":
        return cls(
            id=data["id"],
            label=data.get("label", ""),
            ts=float(data.get("ts", 0.0)),
            entry_count=int(data.get("entry_count", 0)),
            root_hash=data["root_hash"],
            entries={key: SnapshotEntry.from_dict(value) for key, value in data.get("entries", {}).items()},
            signature=data.get("signature", ""),
            signed=bool(data.get("signed", False)),
            signature_version=int(data.get("signature_version", 1)),
            merkle_root=data.get("merkle_root", ""),
        )

    def merkle_tree(self):
        """Build a `MerkleTree` over this snapshot's entries (lazy, no caching)."""
        from memgar.merkle import MerkleTree

        return MerkleTree(
            (eid, entry.content_hash) for eid, entry in self.entries.items()
        )

    def merkle_proof(self, entry_id: str):
        """Build an inclusion `MerkleProof` for `entry_id` in this snapshot.

        Raises KeyError if `entry_id` is not in the snapshot.
        """
        return self.merkle_tree().prove(entry_id)


@dataclass
class DiffEntry:
    entry_id: str
    hash_before: str
    hash_after: str
    content_before: str
    content_after: str

    def summary(self) -> str:
        before_words = len(self.content_before.split())
        after_words = len(self.content_after.split())
        return f"[MODIFIED] {self.entry_id} ({before_words}w -> {after_words}w, hash {self.hash_before[:8]}->{self.hash_after[:8]})"


@dataclass
class VaultDiff:
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
            return "No changes detected - memory state is identical."
        parts: List[str] = []
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
                    "entry_id": item.entry_id,
                    "hash_before": item.hash_before,
                    "hash_after": item.hash_after,
                }
                for item in self.modified
            ],
            "is_clean": self.is_clean,
            "total_changes": self.total_changes,
        }


@dataclass
class RollbackPlan:
    target_snapshot_id: str
    diff: VaultDiff
    entries_to_restore: List[SnapshotEntry]
    entry_ids_to_delete: List[str]
    confirmed: bool = False

    def summary(self) -> str:
        return "\n".join([
            f"Rollback plan -> snapshot {self.target_snapshot_id[:8]}",
            f"  Entries to restore : {len(self.entries_to_restore)}",
            f"  Entries to delete  : {len(self.entry_ids_to_delete)}",
            f"  Diff summary       : {self.diff.summary()}",
            f"  Status             : {'CONFIRMED' if self.confirmed else 'PENDING - call plan.confirmed = True to apply'}",
        ])


@dataclass
class VaultVerificationResult:
    snapshot_id: str
    verified_at: float
    is_valid: bool
    signature_valid: Optional[bool]
    violations: List[Any]
    tampered_ids: List[str]
    root_hash_match: bool

    def summary(self) -> str:
        if self.is_valid:
            return f"Vault OK - snapshot {self.snapshot_id[:8]} verified, no tampering."
        parts: List[str] = []
        if not self.root_hash_match:
            parts.append("root hash mismatch")
        if self.signature_valid is False:
            parts.append("signature invalid")
        if self.tampered_ids:
            parts.append(f"{len(self.tampered_ids)} tampered entries: {self.tampered_ids[:3]}")
        return f"Vault COMPROMISED - {'; '.join(parts)}"


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _entry_fingerprint(entry: SnapshotEntry) -> str:
    return _sha256(_canonical_json(entry.integrity_dict()))


def _root_hash(entries: Dict[str, SnapshotEntry]) -> str:
    sorted_fingerprints = "".join(
        f"{entry_id}:{_entry_fingerprint(entry)}"
        for entry_id, entry in sorted(entries.items())
    )
    return _sha256(sorted_fingerprints)


def _snapshot_signature_payload(snapshot: VaultSnapshot) -> str:
    return _canonical_json({
        "signature_version": snapshot.signature_version,
        "id": snapshot.id,
        "label": snapshot.label,
        "ts": snapshot.ts,
        "entry_count": snapshot.entry_count,
        "root_hash": snapshot.root_hash,
        "entries": {key: value.to_dict() for key, value in sorted(snapshot.entries.items())},
    })


def _sign(data: str, private_key: Any) -> str:
    try:
        sig_bytes = private_key.sign(data.encode("utf-8"))
        return base64.b64encode(sig_bytes).decode("ascii")
    except Exception as exc:
        logger.warning("Vault signing failed: %s", exc)
        return ""


def _verify_sig(data: str, signature_b64: str, public_key: Any) -> bool:
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, data.encode("utf-8"))
        return True
    except Exception:
        return False


class MemoryVault:
    def __init__(
        self,
        db_path: Optional[str] = None,
        signing_key: Optional[Any] = None,
        max_snapshots: int = 50,
        public_key: Optional[Any] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._signing_key = signing_key
        self._public_key = public_key
        self._max_snapshots = max_snapshots
        self._db: Optional[sqlite3.Connection] = None
        self._live: Dict[str, SnapshotEntry] = {}
        self._snapshots: List[VaultSnapshot] = []

        if self._public_key is None and signing_key is not None:
            try:
                self._public_key = signing_key.public_key()
            except Exception as exc:
                logger.warning("Could not derive public key from signing key: %s", exc)

        if db_path:
            self._init_db(db_path)

    @staticmethod
    def generate_signing_key() -> Tuple[Any, str]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        try:
            pub_bytes = public_key.public_bytes_raw()
        except AttributeError:
            from cryptography.hazmat.primitives import serialization
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        return private_key, base64.b64encode(pub_bytes).decode("ascii")

    @staticmethod
    def public_key_from_b64(b64: str) -> Any:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))

    def register(self, entry: Any, entry_id: Optional[str] = None) -> SnapshotEntry:
        content = getattr(entry, "content", str(entry))
        source_type = getattr(entry, "source_type", "unknown")
        source_id = getattr(entry, "source_id", "") or ""
        metadata = dict(getattr(entry, "metadata", {}) or {})
        stable_id = entry_id or (f"src:{source_id}" if source_id else f"hash:{_sha256(content)[:16]}")
        snapshot_entry = SnapshotEntry(
            entry_id=stable_id,
            content_hash=_sha256(content),
            content=content,
            source_type=source_type,
            source_id=source_id,
            captured_ts=time.time(),
            metadata=metadata,
        )
        with self._lock:
            self._live[stable_id] = snapshot_entry
        logger.debug("Vault.register: %s hash=%s", stable_id, snapshot_entry.content_hash[:12])
        return snapshot_entry

    def unregister(self, entry_id: str) -> bool:
        with self._lock:
            return self._live.pop(entry_id, None) is not None

    def take_snapshot(self, label: str = "") -> VaultSnapshot:
        from memgar.merkle import MerkleTree

        with self._lock:
            entries = {key: SnapshotEntry.from_dict(value.to_dict()) for key, value in self._live.items()}
        merkle_root = MerkleTree(
            (eid, entry.content_hash) for eid, entry in entries.items()
        ).root
        snapshot = VaultSnapshot(
            id=str(uuid.uuid4()),
            label=label or f"snapshot-{int(time.time())}",
            ts=time.time(),
            entry_count=len(entries),
            root_hash=_root_hash(entries),
            entries=entries,
            signature="",
            signed=False,
            signature_version=SIGNATURE_VERSION,
            merkle_root=merkle_root,
        )
        if self._signing_key is not None:
            signature = _sign(_snapshot_signature_payload(snapshot), self._signing_key)
            snapshot.signature = signature
            snapshot.signed = bool(signature)

        with self._lock:
            self._snapshots.append(snapshot)
            if len(self._snapshots) > self._max_snapshots:
                self._snapshots = self._snapshots[-self._max_snapshots:]
        self._persist_snapshot(snapshot)
        logger.info(
            "Vault snapshot: id=%s label=%r entries=%d root=%s signed=%s",
            snapshot.id[:8],
            snapshot.label,
            snapshot.entry_count,
            snapshot.root_hash[:16],
            snapshot.signed,
        )
        return snapshot

    def verify_current(self, snapshot_id: Optional[str] = None) -> VaultVerificationResult:
        snapshot = self._get_snapshot(snapshot_id)
        if snapshot is None:
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

        tampered_ids: List[str] = []
        violations: List[Any] = []
        for entry_id, snap_entry in snapshot.entries.items():
            live_entry = live_entries.get(entry_id)
            if live_entry is None:
                tampered_ids.append(entry_id)
                violations.append({"entry_id": entry_id, "error": "entry missing from live registry"})
                continue
            if _entry_fingerprint(live_entry) != _entry_fingerprint(snap_entry):
                tampered_ids.append(entry_id)
                violations.append({
                    "entry_id": entry_id,
                    "expected_hash": snap_entry.content_hash,
                    "actual_hash": live_entry.content_hash,
                    "snapshot_ts": snapshot.ts,
                    "detected_ts": time.time(),
                    "content_at_snapshot": snap_entry.content,
                })

        live_root = _root_hash(live_entries)
        root_match = live_root == snapshot.root_hash and not tampered_ids
        signature_valid = self._verify_snapshot_signature(snapshot)
        is_valid = root_match and signature_valid is not False and not tampered_ids
        result = VaultVerificationResult(
            snapshot_id=snapshot.id,
            verified_at=time.time(),
            is_valid=is_valid,
            signature_valid=signature_valid,
            violations=violations,
            tampered_ids=tampered_ids,
            root_hash_match=root_match,
        )
        if not result.is_valid:
            logger.warning("VAULT INTEGRITY FAILURE: %s", result.summary())
        return result

    def verify_snapshot(self, snapshot_id: str) -> VaultVerificationResult:
        snapshot = self._get_snapshot(snapshot_id)
        if snapshot is None:
            return VaultVerificationResult(
                snapshot_id=snapshot_id,
                verified_at=time.time(),
                is_valid=False,
                signature_valid=None,
                violations=[{"error": "snapshot not found"}],
                tampered_ids=[],
                root_hash_match=False,
            )
        recomputed_root = _root_hash(snapshot.entries)
        root_match = recomputed_root == snapshot.root_hash
        signature_valid = self._verify_snapshot_signature(snapshot)
        is_valid = root_match and signature_valid is not False
        return VaultVerificationResult(
            snapshot_id=snapshot.id,
            verified_at=time.time(),
            is_valid=is_valid,
            signature_valid=signature_valid,
            violations=[] if is_valid else [{"error": "root hash mismatch or invalid signature"}],
            tampered_ids=[] if root_match else list(snapshot.entries.keys()),
            root_hash_match=root_match,
        )

    def diff(self, snapshot_a_id: Optional[str] = None, snapshot_b_id: Optional[str] = None) -> VaultDiff:
        snap_a = self._get_snapshot(snapshot_a_id)
        if snap_a is None:
            return VaultDiff(snapshot_a_id=snapshot_a_id or "none", snapshot_b_id=snapshot_b_id or "live")
        if snapshot_b_id is None:
            with self._lock:
                entries_b = dict(self._live)
            b_id = "live"
        else:
            snap_b = self._get_snapshot(snapshot_b_id)
            if snap_b is None:
                return VaultDiff(snapshot_a_id=snap_a.id, snapshot_b_id=snapshot_b_id or "none")
            entries_b = snap_b.entries
            b_id = snap_b.id

        ids_a = set(snap_a.entries)
        ids_b = set(entries_b)
        modified: List[DiffEntry] = []
        for entry_id in sorted(ids_a & ids_b):
            before = snap_a.entries[entry_id]
            after = entries_b[entry_id]
            if _entry_fingerprint(before) != _entry_fingerprint(after):
                modified.append(DiffEntry(
                    entry_id=entry_id,
                    hash_before=before.content_hash,
                    hash_after=after.content_hash,
                    content_before=before.content,
                    content_after=after.content,
                ))
        return VaultDiff(
            snapshot_a_id=snap_a.id,
            snapshot_b_id=b_id,
            added=sorted(ids_b - ids_a),
            deleted=sorted(ids_a - ids_b),
            modified=modified,
        )

    def rollback(self, snapshot_id: Optional[str] = None) -> RollbackPlan:
        snapshot = self._get_snapshot(snapshot_id)
        if snapshot is None:
            raise ValueError(f"Snapshot {snapshot_id!r} not found")
        delta = self.diff(snapshot_a_id=snapshot.id, snapshot_b_id=None)
        entries_to_restore = [snapshot.entries[item.entry_id] for item in delta.modified]
        entries_to_restore.extend(snapshot.entries[entry_id] for entry_id in delta.deleted)
        return RollbackPlan(
            target_snapshot_id=snapshot.id,
            diff=delta,
            entries_to_restore=entries_to_restore,
            entry_ids_to_delete=list(delta.added),
            confirmed=False,
        )

    def apply_rollback(self, plan: RollbackPlan) -> List[SnapshotEntry]:
        if not plan.confirmed:
            raise RuntimeError("RollbackPlan is not confirmed. Set plan.confirmed = True after reviewing the plan summary.")
        with self._lock:
            for entry in plan.entries_to_restore:
                self._live[entry.entry_id] = SnapshotEntry.from_dict(entry.to_dict())
            for entry_id in plan.entry_ids_to_delete:
                self._live.pop(entry_id, None)
        logger.info(
            "Vault rollback applied: restored=%d deleted=%d target_snapshot=%s",
            len(plan.entries_to_restore),
            len(plan.entry_ids_to_delete),
            plan.target_snapshot_id[:8],
        )
        return list(plan.entries_to_restore)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": snapshot.id,
                    "label": snapshot.label,
                    "ts": snapshot.ts,
                    "entry_count": snapshot.entry_count,
                    "root_hash": snapshot.root_hash,
                    "signed": snapshot.signed,
                    "signature_version": snapshot.signature_version,
                }
                for snapshot in self._snapshots
            ]

    def get_snapshot(self, snapshot_id: str) -> Optional[VaultSnapshot]:
        return self._get_snapshot(snapshot_id)

    @property
    def latest_snapshot(self) -> Optional[VaultSnapshot]:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    @property
    def live_entry_count(self) -> int:
        with self._lock:
            return len(self._live)

    def _verify_snapshot_signature(self, snapshot: VaultSnapshot) -> Optional[bool]:
        if not snapshot.signed and not snapshot.signature:
            return None
        if not snapshot.signature or self._public_key is None:
            return False
        return _verify_sig(_snapshot_signature_payload(snapshot), snapshot.signature, self._public_key)

    def _get_snapshot(self, snapshot_id: Optional[str]) -> Optional[VaultSnapshot]:
        with self._lock:
            if not self._snapshots:
                return None
            if snapshot_id is None:
                return self._snapshots[-1]
            for snapshot in reversed(self._snapshots):
                if snapshot.id == snapshot_id or snapshot.id.startswith(snapshot_id):
                    return snapshot
        return None

    def _init_db(self, db_path: str) -> None:
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS vault_snapshots (
                id          TEXT PRIMARY KEY,
                label       TEXT NOT NULL,
                ts          REAL NOT NULL,
                entry_count INTEGER NOT NULL,
                root_hash   TEXT NOT NULL,
                payload     TEXT NOT NULL,
                signature   TEXT NOT NULL DEFAULT '',
                signed      INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._db.commit()
        self._load_snapshots_from_db()

    def _persist_snapshot(self, snapshot: VaultSnapshot) -> None:
        if self._db is None:
            return
        try:
            payload = json.dumps({key: value.to_dict() for key, value in snapshot.entries.items()}, sort_keys=True)
            self._db.execute(
                """INSERT OR REPLACE INTO vault_snapshots
                   (id, label, ts, entry_count, root_hash, payload, signature, signed)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    snapshot.id,
                    snapshot.label,
                    snapshot.ts,
                    snapshot.entry_count,
                    snapshot.root_hash,
                    payload,
                    snapshot.signature,
                    int(snapshot.signed),
                ),
            )
            self._db.commit()
        except Exception as exc:
            logger.warning("Vault: failed to persist snapshot: %s", exc)

    def _load_snapshots_from_db(self) -> None:
        if self._db is None:
            return
        try:
            rows = self._db.execute("SELECT * FROM vault_snapshots ORDER BY ts").fetchall()
            for row in rows:
                entries = {
                    key: SnapshotEntry.from_dict(value)
                    for key, value in json.loads(row["payload"]).items()
                }
                snapshot = VaultSnapshot(
                    id=row["id"],
                    label=row["label"],
                    ts=float(row["ts"]),
                    entry_count=int(row["entry_count"]),
                    root_hash=row["root_hash"],
                    entries=entries,
                    signature=row["signature"],
                    signed=bool(row["signed"]),
                    signature_version=SIGNATURE_VERSION,
                )
                self._snapshots.append(snapshot)
            if len(self._snapshots) > self._max_snapshots:
                self._snapshots = self._snapshots[-self._max_snapshots:]
        except Exception as exc:
            logger.warning("Vault: failed to load snapshots from DB: %s", exc)


__all__ = [
    "MemoryVault",
    "VaultSnapshot",
    "SnapshotEntry",
    "VaultDiff",
    "DiffEntry",
    "RollbackPlan",
    "VaultVerificationResult",
]
