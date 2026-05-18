"""Tests for memgar.merkle — deterministic Merkle tree + inclusion proofs."""

from __future__ import annotations

import pytest

from memgar.merkle import (
    MerkleProof,
    MerkleTree,
    leaf_hash,
    verify_proof,
)


class TestLeafHash:
    def test_deterministic(self):
        a = leaf_hash("e1", "abc123")
        b = leaf_hash("e1", "abc123")
        assert a == b

    def test_different_id_different_hash(self):
        a = leaf_hash("e1", "abc123")
        b = leaf_hash("e2", "abc123")
        assert a != b

    def test_different_content_different_hash(self):
        a = leaf_hash("e1", "abc123")
        b = leaf_hash("e1", "abc124")
        assert a != b

    def test_collision_resistance_with_internal(self):
        """Leaf hash and an internal hash must not collide given identical
        bytes — the domain prefix prevents second-preimage attacks."""
        from memgar.merkle import _internal_hash
        a = leaf_hash("x", "y")
        b = _internal_hash(a, a)  # two valid hex hashes
        assert a != b


class TestMerkleTree:
    def test_empty_tree_has_empty_root(self):
        t = MerkleTree([])
        assert t.root == ""
        assert t.leaf_count == 0
        assert t.depth == 0

    def test_single_leaf_root_is_the_leaf_hash(self):
        t = MerkleTree([("e1", "ch1")])
        assert t.root == leaf_hash("e1", "ch1")
        assert t.depth == 0

    def test_two_leaves_make_one_internal_node(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        assert t.depth == 1
        assert t.leaf_count == 2
        assert t.root != ""

    def test_sort_independence(self):
        a = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3")])
        b = MerkleTree([("e3", "ch3"), ("e1", "ch1"), ("e2", "ch2")])
        assert a.root == b.root

    def test_root_changes_when_content_changes(self):
        a = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        b = MerkleTree([("e1", "ch1"), ("e2", "ch2-tampered")])
        assert a.root != b.root

    def test_root_changes_when_entry_added(self):
        a = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        b = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3")])
        assert a.root != b.root

    def test_root_changes_when_entry_removed(self):
        a = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3")])
        b = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        assert a.root != b.root

    def test_odd_leaf_count(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3")])
        assert t.root != ""
        # Last leaf is duplicated; tree still has a single root
        assert t.depth == 2

    def test_large_tree_thousand_leaves(self):
        entries = [(f"e{i}", f"ch{i}") for i in range(1000)]
        t = MerkleTree(entries)
        assert t.leaf_count == 1000
        # 2^10 = 1024 → depth 10
        assert t.depth == 10
        # Proof length scales with depth
        proof = t.prove("e500")
        assert len(proof.siblings) == 10

    def test_duplicate_entry_id_collapses(self):
        t = MerkleTree([("e1", "ch1"), ("e1", "ch1-newer"), ("e2", "ch2")])
        assert t.leaf_count == 2
        # Last value wins
        leaves = dict(t.leaves)
        assert leaves["e1"] == "ch1-newer"


class TestProofGeneration:
    def test_prove_returns_proof_with_correct_root(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3")])
        proof = t.prove("e2")
        assert proof.entry_id == "e2"
        assert proof.content_hash == "ch2"
        assert proof.root == t.root

    def test_prove_unknown_entry_raises(self):
        t = MerkleTree([("e1", "ch1")])
        with pytest.raises(KeyError):
            t.prove("missing")

    def test_proof_sibling_count_equals_depth(self):
        for n in (1, 2, 3, 7, 16, 17, 100):
            entries = [(f"e{i}", f"ch{i}") for i in range(n)]
            t = MerkleTree(entries)
            proof = t.prove("e0")
            assert len(proof.siblings) == t.depth


class TestVerify:
    def test_verify_proof_succeeds_for_valid_proof(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3"), ("e4", "ch4")])
        for eid in ("e1", "e2", "e3", "e4"):
            proof = t.prove(eid)
            assert verify_proof(proof) is True

    def test_verify_with_bound_entry_id_succeeds(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        proof = t.prove("e1")
        assert verify_proof(
            proof, expected_entry_id="e1", expected_content_hash="ch1",
            expected_root=t.root,
        ) is True

    def test_verify_with_wrong_expected_root_fails(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        proof = t.prove("e1")
        assert verify_proof(proof, expected_root="0" * 64) is False

    def test_verify_with_wrong_expected_entry_id_fails(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        proof = t.prove("e1")
        assert verify_proof(proof, expected_entry_id="e2") is False

    def test_verify_with_wrong_expected_content_hash_fails(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        proof = t.prove("e1")
        assert verify_proof(proof, expected_content_hash="tampered") is False

    def test_verify_with_tampered_sibling_fails(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3"), ("e4", "ch4")])
        proof = t.prove("e1")
        # Flip a bit in the first sibling
        position, sibling = proof.siblings[0]
        proof.siblings[0] = (position, "0" * 64)
        assert verify_proof(proof) is False

    def test_verify_with_flipped_position_fails(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2"), ("e3", "ch3"), ("e4", "ch4")])
        proof = t.prove("e1")
        position, sibling = proof.siblings[0]
        proof.siblings[0] = (1 - position, sibling)
        assert verify_proof(proof) is False

    def test_serialise_and_verify_roundtrip(self):
        t = MerkleTree([("e1", "ch1"), ("e2", "ch2")])
        proof = t.prove("e1")
        wire = proof.to_dict()
        rebuilt = MerkleProof.from_dict(wire)
        assert verify_proof(rebuilt) is True
        assert rebuilt.root == proof.root
