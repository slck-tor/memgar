# Memory Forensics CLI

`memgar memory` is the operator-facing toolkit for inspecting, diffing, verifying,
and rolling back `MemoryVault` snapshots. It exists because Python APIs aren't
what you reach for at 3am when an incident page goes off — you want a shell, a
JSON pipe, and an exit code.

All commands operate on a SQLite-backed vault DB (the file path the runtime
gave to `MemoryVault(db_path=...)`). Every command supports `--json` for
scripting.

---

## Commands

| Command | Purpose | Mutates state |
|---|---|---|
| [`list`](#list)      | List every snapshot | no |
| [`inspect`](#inspect) | Show one snapshot's contents | no |
| [`diff`](#diff)      | Compare two snapshots | no |
| [`verify`](#verify)  | Recompute root hash + check signature | no |
| [`rollback`](#rollback) | Build a rollback plan, optionally apply it | **yes (with `--apply`)** |
| [`replay`](#replay)  | Render snapshot timeline as a forensic trail | no |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success / integrity OK |
| 1 | User error (bad path, missing snapshot, bad arguments) |
| 2 | Integrity violation (root-hash or signature mismatch, non-clean diff) |

`diff` returning exit code 2 is by design: in an incident-response pipe like
`memgar memory diff vault.db pre post --json | jq ...`, the non-zero exit signals
"something changed" without you needing to parse the JSON.

---

## `list`

```bash
memgar memory list ./vault.db
memgar memory list ./vault.db --limit 10 --json
```

Prints the snapshot index — ID prefix, timestamp, entry count, signed/unsigned,
root-hash prefix, and label.

JSON output is an array of `{id, label, ts, ts_iso, entry_count, root_hash,
signed}` objects, in chronological order.

---

## `inspect`

```bash
memgar memory inspect ./vault.db --latest
memgar memory inspect ./vault.db 7a3f9b1c
memgar memory inspect ./vault.db 7a3f9b1c --full --json
```

Shows one snapshot's full contents: header metadata (label, timestamp,
root-hash, signature status) and the entry table (entry ID, source, content
hash, content preview).

- Snapshot can be referenced by full UUID or any prefix.
- `--full` shows complete content (default truncates to 80 chars).
- `--json` returns the snapshot + entries in machine-readable form for grep/jq.

---

## `diff`

```bash
memgar memory diff ./vault.db <SNAP_A>
memgar memory diff ./vault.db <SNAP_A> <SNAP_B>
memgar memory diff ./vault.db <SNAP_A> <SNAP_B> --json
```

Compares two snapshots and lists **added**, **deleted**, and **modified**
entries. If `SNAP_B` is omitted, the comparison target is the current live
vault state (whatever the runtime currently has in memory — only meaningful
if the runtime is in-process).

For modified entries, the diff includes `content_before` and `content_after`,
which is the forensic gold for "did an attacker overwrite a memory entry?".

Exit code 2 if the diff is non-empty.

---

## `verify`

```bash
memgar memory verify ./vault.db --latest
memgar memory verify ./vault.db 7a3f9b1c --public-key <b64>
memgar memory verify ./vault.db 7a3f9b1c --json
```

Recomputes the snapshot's root hash from its entries and compares it to the
recorded `root_hash`. If the snapshot is signed (`MemoryVault(signing_key=...)`)
and `--public-key` is provided, Ed25519 signature is also checked.

Exit code 2 if root hash mismatches or signature is invalid.

Use this on a snapshot you suspect has been tampered with on disk
(e.g. a `vault.db` pulled from a compromised host).

---

## `rollback`

```bash
# Plan only — show what would change, make no modifications
memgar memory rollback ./vault.db 7a3f9b1c

# Apply with interactive confirmation
memgar memory rollback ./vault.db 7a3f9b1c --apply

# Apply non-interactively (CI / runbook usage)
memgar memory rollback ./vault.db 7a3f9b1c --apply -y --json
```

Builds a `RollbackPlan` against the target snapshot and prints what would
change (entries to restore, entry IDs to delete). Without `--apply`, **no
modifications occur** — this is the safe default for runbook authoring.

When `--apply` is set, the rollback is committed to `_live` AND a new
snapshot labeled `rollback-to-<target_id>` is taken. The new snapshot is
persisted to SQLite, so subsequent `list` / `replay` invocations show the
rollback as a traceable forensic event.

---

## `replay`

```bash
memgar memory replay ./vault.db
memgar memory replay ./vault.db --since 2026-05-17T00:00:00Z
memgar memory replay ./vault.db --limit 10 --json
```

Renders the snapshot timeline as a forensic trail. Each row shows the
**inter-snapshot diff** — `+N` added, `-N` deleted, `~N` modified relative to
the immediately preceding snapshot.

This is the fastest way to answer "when did this poisoned entry first appear?":
walk the trail until you see `+1` or `~1` on the entry's ID, then `inspect` that
snapshot.

`--since` filters by ISO-8601 timestamp (UTC). `--limit` caps the rendered trail
to the last N snapshots.

---

## Incident-response runbook

A typical memory-poisoning investigation, end to end:

```bash
# 1. What snapshots exist?
memgar memory list ./vault.db --limit 20

# 2. What changed between the last-known-good snapshot and now?
memgar memory diff ./vault.db <good_id> --json | jq .modified

# 3. Did anything else move between those snapshots? (forensic context)
memgar memory replay ./vault.db --since 2026-05-17T10:00:00Z

# 4. Was the snapshot's own state tampered with on disk?
memgar memory verify ./vault.db <good_id> --public-key "$VAULT_PUB"

# 5. Restore — first as a plan
memgar memory rollback ./vault.db <good_id>

# 6. Then commit if the plan looks right
memgar memory rollback ./vault.db <good_id> --apply -y --json
```

Pipe the JSON outputs into your SIEM or ticketing system; the exit codes give
you a clean signal for automated pages.

---

## Python equivalents

Every CLI command is a thin wrapper around the public `MemoryVault` API. If
you'd rather drive it from Python (e.g. in a Jupyter incident notebook):

```python
from memgar.memory_vault import MemoryVault

vault = MemoryVault(db_path="./vault.db", public_key=public_key)

# list
for snap in vault._snapshots:
    print(snap.id, snap.label, snap.ts, snap.entry_count)

# inspect
snap = vault._get_snapshot("7a3f9b1c")          # by prefix
print(list(snap.entries.values()))

# diff
delta = vault.diff(snapshot_a_id="7a3f9b1c", snapshot_b_id="ec88a02f")
print(delta.added, delta.deleted, delta.modified)

# verify
result = vault.verify_snapshot("7a3f9b1c")
print(result.is_valid, result.root_hash_match, result.signature_valid)

# rollback
plan = vault.rollback(snapshot_id="7a3f9b1c")
plan.confirmed = True                            # required guardrail
vault.apply_rollback(plan)
```

The CLI shells out to exactly these calls.
