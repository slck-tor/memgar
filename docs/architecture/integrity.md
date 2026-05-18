# Memory integrity & forensics

Three independent capabilities that together turn memgar from a write-time
detector into a full memory-poisoning forensics platform.

## At a glance

| Capability | Module | What it gives you |
|---|---|---|
| Merkle-tree integrity | `memgar.merkle` | O(log N) inclusion proofs, tampering localization, selective disclosure |
| Cross-snapshot replay | `memgar.replay_forensics` | Provenance, lineage, cohorts, session timelines across vault snapshots |
| Embedding-space anomaly | `memgar.embedding_anomaly` | Outlier / density / cross-cluster-collision detection on RAG inserts |

---

## 1. Merkle-tree memory integrity

A flat content-hash root tells you "something changed in the vault." A
Merkle tree gives you three things flat hashes can't:

1. **O(log N) inclusion proofs.** Prove "entry X was in snapshot Y at
   time T" with ~20 sibling hashes for a 1M-entry vault.
2. **Tampering localization.** A corrupted entry produces a different
   sibling-chain than a clean one, so a verifier can pinpoint the path
   of divergence instead of just flagging the whole snapshot.
3. **Selective disclosure.** Prove an entry's presence to a third party
   (auditor, regulator, customer) without exposing the rest of the vault.

Every `MemoryVault.take_snapshot()` now also computes a `merkle_root`,
persisted alongside `root_hash`. You can build proofs on demand:

```python
from memgar.memory_vault import MemoryVault
from memgar.merkle import verify_proof

vault = MemoryVault(db_path="./vault.db")
# ... live work ...
snapshot = vault.take_snapshot(label="post-incident")

# Build an inclusion proof
proof = snapshot.merkle_proof("src:evil-doc")
print(proof.to_dict())
# {
#   "entry_id": "src:evil-doc",
#   "content_hash": "...",
#   "leaf_hash": "...",
#   "siblings": [(0, "..."), (1, "..."), ...],   # ~log2(N) entries
#   "root": "abc123..."
# }

# Verify externally — only needs the proof and the published root
assert verify_proof(
    proof,
    expected_entry_id="src:evil-doc",
    expected_content_hash="...",
    expected_root=snapshot.merkle_root,
)
```

### Conventions

- Leaves are **sorted by `entry_id`** before hashing — same entries in any
  insertion order produce the same root.
- Leaf hash = `sha256(b"L:" || entry_id || b"|" || content_hash)`. The
  domain prefix `L:` prevents second-preimage attacks against internal
  nodes.
- Internal hash = `sha256(b"I:" || left || right)`. Same domain-prefix
  reasoning.
- Odd-leaf level: the last orphan is duplicated (Bitcoin convention).

### Backward compatibility

Snapshots created before this feature have `merkle_root == ""`. Building a
proof against them works (the tree is computed on demand from the entries),
but they have no signed Merkle root to compare against, so external
verification falls back to the flat `root_hash`.

---

## 2. Cross-snapshot replay forensics

`ReplayForensics` is the answer to "**when did this poison first appear,
and what else did the same source write?**" — a question that takes hours
to answer manually but seconds with snapshot-walking.

```python
from memgar.memory_vault import MemoryVault
from memgar.replay_forensics import ReplayForensics

vault = MemoryVault(db_path="./vault.db")
forensics = ReplayForensics(vault._snapshots)

# 1. When was this entry first written? How long has it persisted?
appearance = forensics.first_appearance("src:evil-doc")
print(appearance.first_ts, appearance.last_ts, appearance.snapshots_seen)
# → first_ts=1779127740, last_ts=1779127780, snapshots_seen=4

# 2. Show the full mutation chain — every distinct content_hash
for mut in forensics.lineage("src:evil-doc"):
    glyph = "●" if mut.is_first else "~"
    print(f"{glyph} {mut.ts:.0f}  {mut.content_hash[:12]}  {mut.content_preview}")

# 3. What else did this source write? (cohort analysis)
cohort = forensics.cohort("evil-doc", attr="source_id")
for sibling in cohort:
    print(sibling.entry_id, sibling.first_seen_ts)

# 4. Substring hunt across history (hunting for known poison phrases)
hits = forensics.cross_snapshot_search("attacker@evil.com")

# 5. Per-source timeline (appear / mutate / disappear events)
timeline = forensics.session_timeline("evil-doc", attr="source_id")
```

### Operator CLI

Two new `memgar memory` subcommands wrap this for shell use:

```bash
# Trace one entry's provenance
memgar memory trace ./vault.db src:evil-doc
memgar memory trace ./vault.db src:evil-doc --json | jq

# Show every entry that shares an attribute
memgar memory cohort ./vault.db evil-doc --attr source_id
memgar memory cohort ./vault.db rag --attr source_type --json
```

Both follow the same exit-code contract as the other `memgar memory`
commands (`0` ok, `1` user/missing, `2` integrity issue).

---

## 3. Embedding-space anomaly detection

Pattern matching catches lexical attacks. Layer 1.5 SemanticGuard catches
paraphrased / obfuscated attacks. But **neither catches a poisoned RAG
chunk crafted to land near a sensitive cluster in embedding space** — the
attack family captured by the `VECNN-*` patterns from
[the kill chain](../threats/kill-chain.md).

`EmbeddingAnomalyDetector` is a stdlib-only outlier detector (no sklearn,
no scipy) that gives you three complementary signals:

1. **Centroid distance + z-score** — Per-cluster running mean + variance
   via Welford's online algorithm. A new vector with `z >= 3.0`
   (≈99.7% tail under Gaussian) is flagged `is_outlier=True`.

2. **k-NN density** — Mean cosine distance to the k nearest baseline
   vectors. If above a configured quantile (default 95th percentile of
   historical mean distances), `is_density_anomaly=True`.

3. **Cross-cluster collision** — Optional. If the vector's nearest
   neighbor in cluster A is closer than its nearest in declared cluster B,
   `cross_cluster_collision="A"`. Strong signal of `VECNN-001`
   nearest-neighbor injection.

```python
from memgar.embedding_anomaly import EmbeddingAnomalyDetector

detector = EmbeddingAnomalyDetector(
    z_threshold=3.0,
    k=5,
    density_quantile=0.95,
    min_observations=20,
)

# Build baseline from your normal vectors
for vec in normal_user_pref_vectors:
    detector.observe(vec, cluster="user-prefs")
for vec in normal_admin_vectors:
    detector.observe(vec, cluster="admin")

# Score a candidate before it lands in the vector store
verdict = detector.score(
    suspicious_vec,
    cluster="user-prefs",
    compare_clusters=["user-prefs", "admin"],
)
print(verdict.severity)              # none / low / medium / high
print(verdict.is_outlier)            # True if z >= z_threshold
print(verdict.cross_cluster_collision)  # "admin" if attack
print(verdict.explanation)
```

### Why "high" requires both centroid + density anomaly

A high z-score alone might be a legitimate edge case (rare query, new
topic). A high z-score *and* a sparse neighborhood means the vector has
no natural neighbors — the textbook signature of an injected outlier.

### Cross-cluster collision

This is the most discriminating signal. Honest vectors usually have their
nearest neighbors inside the cluster they were assigned to. An attack
vector crafted to "land near the admin cluster while declared as user
prefs" produces a clear cross-cluster collision verdict.

### Operational integration

Hook the detector into your write path:

```python
from memgar.embedding_anomaly import EmbeddingAnomalyDetector
from memgar.integrations import MemgarPineconeIndex, WritePolicy

detector = EmbeddingAnomalyDetector()
# ... build baseline over time ...

def on_block(record):
    siem.emit("memory.write.blocked", record.to_dict())

index = MemgarPineconeIndex(pc.Index("agent-memory"), write_policy=WritePolicy.BLOCK)

def secure_upsert(vectors):
    for v in vectors:
        verdict = detector.score(
            v["values"],
            cluster=v["metadata"].get("namespace", "default"),
        )
        if verdict.severity == "high":
            raise SecurityException(verdict.explanation)
    return index.upsert(vectors=vectors)
```

### What it doesn't replace

Embedding-space anomaly detection complements but does not replace:

- **Layer 1 pattern matching** — catches lexical signatures
- **Layer 1.5 SemanticGuard** — catches paraphrased / obfuscated text
- **Layer 4 BehavioralBaseline** — catches per-agent behavioral drift

A defense-in-depth pipeline uses all four. The embedding-anomaly detector
is the missing piece for `VECNN-*` attacks that bypass the first three by
operating in embedding space, not token space.

---

## See also

- [Memory poisoning kill chain](../threats/kill-chain.md) — TTP framework
  this defends against
- [Threat catalog](../threats/catalog.md) — `VECNN-*`, `XSESS-*`, `MAGENT-*`
  pattern families
- [Memory forensics CLI](../operations/forensics.md) — `memgar memory
  list / inspect / diff / verify / rollback / replay / trace / cohort`
