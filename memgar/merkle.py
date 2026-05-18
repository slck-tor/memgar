"""Merkle tree for memory-vault integrity.

A flat content-hash root tells you "something changed in the vault" but
nothing about *what* — recompute every entry or accept a binary verdict.

A Merkle tree gives you:

  - **O(log N) inclusion proofs**: "entry X was in snapshot Y at time T"
    is provable with ~20 sibling hashes for a 1M-entry vault.
  - **Tampering localization**: a corrupted entry produces a different
    sibling-chain than a clean one, so a verifier can pinpoint the path
    of divergence instead of just flagging the whole snapshot.
  - **Selective disclosure**: prove an entry's presence to a third party
    (auditor, regulator, customer) without exposing the rest of the vault.

This module is pure-Python (`hashlib.sha256` only), self-contained, and
deterministic. It is consumed by `memgar.memory_vault.VaultSnapshot` for
the new `merkle_root` field and `merkle_proof(entry_id)` method.

Conventions
-----------

- Leaves are sorted by `entry_id` before hashing, so the same entries in
  any insertion order produce the same root.
- Leaf hash = `sha256(b"L:" || entry_id || b"|" || content_hash)`. The
  domain prefix `L:` prevents second-preimage attacks against internal
  nodes.
- Internal hash = `sha256(b"I:" || left || right)`. Same domain-prefix
  reasoning.
- Odd-leaf level: the last orphan node is duplicated (Bitcoin convention).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple


LEAF_PREFIX = b"L:"
INTERNAL_PREFIX = b"I:"


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(entry_id: str, content_hash: str) -> str:
    """Stable per-leaf hash with domain separation."""
    return _h(LEAF_PREFIX + entry_id.encode("utf-8") + b"|" + content_hash.encode("utf-8"))


def _internal_hash(left: str, right: str) -> str:
    return _h(INTERNAL_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


@dataclass
class MerkleProof:
    """An inclusion proof for a single leaf.

    Verifiable against a root hash with `verify_proof()`. The proof carries
    the leaf-hash itself (so the verifier can compute it from the entry +
    content) and the chain of sibling hashes from leaf to root, paired with
    a `position` bit telling the verifier whether the sibling sits to the
    left (`0`) or right (`1`) of the running hash at that level.
    """

    entry_id: str
    content_hash: str
    leaf_hash: str
    siblings: List[Tuple[int, str]] = field(default_factory=list)
    root: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "content_hash": self.content_hash,
            "leaf_hash": self.leaf_hash,
            "siblings": list(self.siblings),
            "root": self.root,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MerkleProof":
        return cls(
            entry_id=data["entry_id"],
            content_hash=data["content_hash"],
            leaf_hash=data["leaf_hash"],
            siblings=[tuple(s) for s in data["siblings"]],
            root=data["root"],
        )


def verify_proof(
    proof: MerkleProof,
    *,
    expected_entry_id: Optional[str] = None,
    expected_content_hash: Optional[str] = None,
    expected_root: Optional[str] = None,
) -> bool:
    """Verify an inclusion proof.

    Optional `expected_*` arguments bind the proof to a specific entry and
    root — recommended in any non-trivial verification context.
    """
    if expected_entry_id is not None and proof.entry_id != expected_entry_id:
        return False
    if expected_content_hash is not None and proof.content_hash != expected_content_hash:
        return False
    expected = leaf_hash(proof.entry_id, proof.content_hash)
    if expected != proof.leaf_hash:
        return False
    running = proof.leaf_hash
    for position, sibling in proof.siblings:
        if position == 0:  # sibling on the left
            running = _internal_hash(sibling, running)
        else:              # sibling on the right
            running = _internal_hash(running, sibling)
    if running != proof.root:
        return False
    if expected_root is not None and proof.root != expected_root:
        return False
    return True


class MerkleTree:
    """Deterministic Merkle tree over (entry_id, content_hash) leaves.

    Args:
        entries: an iterable of `(entry_id, content_hash)` pairs.

    Properties:
        root: hex digest of the tree root, or empty string for an empty tree.
        leaves: ordered list of (entry_id, content_hash) after sorting.
    """

    def __init__(self, entries: Iterable[Tuple[str, str]]) -> None:
        # Sort by entry_id for determinism. Duplicate entry_ids collapse to
        # the last value — matches dict semantics; vault entries are
        # already unique-by-id.
        unique: dict = {}
        for eid, ch in entries:
            unique[eid] = ch
        self._entries: List[Tuple[str, str]] = sorted(unique.items())
        self._levels: List[List[str]] = []
        self._build()

    def _build(self) -> None:
        if not self._entries:
            self._levels = [[]]
            return
        leaves = [leaf_hash(eid, ch) for eid, ch in self._entries]
        self._levels = [leaves]
        current = leaves
        while len(current) > 1:
            nxt: List[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(_internal_hash(left, right))
            self._levels.append(nxt)
            current = nxt

    @property
    def leaves(self) -> List[Tuple[str, str]]:
        return list(self._entries)

    @property
    def leaf_count(self) -> int:
        return len(self._entries)

    @property
    def root(self) -> str:
        if not self._entries:
            return ""
        return self._levels[-1][0]

    @property
    def depth(self) -> int:
        """Number of internal levels above the leaves (0 for empty/single-leaf trees)."""
        return max(0, len(self._levels) - 1)

    def _index_of(self, entry_id: str) -> int:
        for i, (eid, _) in enumerate(self._entries):
            if eid == entry_id:
                return i
        raise KeyError(f"entry_id {entry_id!r} not in tree")

    def prove(self, entry_id: str) -> MerkleProof:
        """Build an inclusion proof for `entry_id`. Raises KeyError if absent."""
        idx = self._index_of(entry_id)
        eid, ch = self._entries[idx]
        proof = MerkleProof(
            entry_id=eid,
            content_hash=ch,
            leaf_hash=self._levels[0][idx],
            root=self.root,
        )
        for level in self._levels[:-1]:
            sibling_idx = idx ^ 1  # XOR flips last bit to get the sibling
            if sibling_idx >= len(level):
                # Orphan node — sibling is the duplicated last leaf, i.e. self
                sibling = level[idx]
            else:
                sibling = level[sibling_idx]
            position = 0 if (idx & 1) == 1 else 1  # is sibling left (0) or right (1)?
            proof.siblings.append((position, sibling))
            idx //= 2
        return proof


__all__ = [
    "MerkleTree",
    "MerkleProof",
    "verify_proof",
    "leaf_hash",
]
