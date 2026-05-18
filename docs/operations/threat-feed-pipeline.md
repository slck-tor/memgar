# Threat feed publishing pipeline

The bundled `memgar/patterns.py` is the source of truth. The **threat feed**
is a SHA-256-hashed, Ed25519-signed snapshot of that source, published as a
GitHub Release asset and consumed by every installed memgar instance via
`memgar feed sync`.

This page is for the maintainer running the feed pipeline. End-user
consumption of the feed is documented in [Threat Feed](feed.md).

## Pipeline overview

```
┌─ developer pushes pattern changes to main ──────────────────────────────┐
│                                                                          │
│  memgar/patterns.py  (807 patterns, 14 categories)                      │
│                                                                          │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
                                   │ weekly cron (Mon 06:00 UTC)
                                   │ or manual workflow_dispatch
                                   ▼
┌─ .github/workflows/feed-publish.yml ────────────────────────────────────┐
│                                                                          │
│   1. compute next SemVer  ──►  scripts/feed_version.py                  │
│   2. sign bundle          ──►  scripts/publish_feed.py (Ed25519 PEM)    │
│   3. generate notes       ──►  scripts/feed_changelog.py (pattern diff) │
│   4. verify signature locally before publish                            │
│   5. GitHub Release       ──►  feed-v{version} tag + asset              │
│   6. commit feeds/memgar-feed.json.gz + CHANGELOG-FEED.md to main       │
│                                                                          │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
                                   ▼
┌─ end-user instance ─────────────────────────────────────────────────────┐
│                                                                          │
│   memgar feed sync                                                       │
│   └─► FeedLoader downloads feed-v{x}.json.gz                            │
│   └─► FeedVerifier checks Ed25519 signature against pinned public key   │
│   └─► FeedCache persists at ~/.cache/memgar/feeds/                      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## One-time setup

1. **Generate signing key pair** (off-CI, secure machine):

```bash
python scripts/publish_feed.py --generate-key feed_private.pem
# Prints the matching public key in base64.
# Paste that into memgar/feed/verifier.py::FEED_PUBLIC_KEY_B64
```

2. **Store private key as repo secret**:

```bash
base64 -w 0 feed_private.pem | gh secret set MEMGAR_FEED_PRIVATE_KEY_PEM
```

The private key never leaves the secret store; CI base64-decodes it into
`/tmp/feed_private.pem` for the duration of one job run.

3. **Rotate the public key** (only when private key is compromised):

   - Generate new pair
   - Bump major: `MEMGAR_MIN_VERSION` so clients running the old key
     are forced to upgrade
   - Update `FEED_PUBLIC_KEY_B64` in `memgar/feed/verifier.py`
   - Publish a new feed signed with the new key
   - Coordinate the rotation in a security advisory

## Manual publish

```bash
gh workflow run feed-publish.yml \
  -f version_bump=minor \
  -f release_notes="Adds 12 new MAGENT-* cross-tenant patterns"
```

The `version_bump` input is one of `patch`, `minor`, `major`. The
release_notes string is prepended to the auto-generated pattern delta
block in CHANGELOG-FEED.md.

## What the changelog looks like

`scripts/feed_changelog.py` computes the pattern-level delta between
the previous bundle and the current `patterns.py`:

```markdown
## [1.0.1] — 2026-05-18

Initial automated publish — 61 new XSESS/VECNN/MAGENT patterns from Tier 1

**Pattern total:** 807
**Delta since last release:** +55 added · -0 removed · ~6 modified

### Added
- `data`: 12
- `sleeper`: 12
- `exfiltration`: 9
- `behavior`: 9
- `manipulation`: 8
  - sample IDs: `EXFIL-012`, `EXFIL-013`, `INJ-001`, `INJ-002` …

### Modified
- `EXEC-001`, `EXEC-002`, `EXEC-003`, `EXFIL-011`

### Verify
\`\`\`bash
memgar feed sync                  # downloads + verifies v1.0.1
memgar feed verify                # re-check signature locally
\`\`\`
```

## Verification, end-to-end

Three places the signature is checked:

1. **In CI**, before the GitHub Release is created — workflow step
   `Verify bundle locally before publish`. If the local
   `FeedVerifier().verify(...)` returns `False`, the workflow fails and
   no release is created.

2. **On the client**, every `memgar feed sync` call — `FeedVerifier` in
   `memgar/feed/verifier.py` checks the asset's signature against the
   pinned public key before passing patterns to the analyzer.

3. **In `memgar feed verify`** — operator can re-check the local
   cached bundle on demand.

If any check fails the client raises `FeedSignatureError` and falls
back to the bundled `PATTERNS` list. Analyzer keeps working; the user
just doesn't get the new patterns from the failed feed.

## Operational disciplines

| Discipline | Cadence | Why |
|---|---|---|
| Weekly feed publish (auto) | Mon 06:00 UTC | Keeps installed instances ≤ 7 days behind main |
| Off-cycle publish on critical pattern adds | as needed | Zero-day signatures shouldn't wait |
| CHANGELOG-FEED.md commit | every publish | Public audit trail of every release |
| Old release retention | keep all | Customers may pin to specific versions |
| Key rotation | every 12 months or on compromise | Standard signing-key hygiene |

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| Workflow fails on "secret not set" | `MEMGAR_FEED_PRIVATE_KEY_PEM` unset | Set via `gh secret set` |
| Local verify fails | Private/public key mismatch | Roll back, regenerate pair |
| Clients report `FeedSignatureError` | Public key in `verifier.py` doesn't match release | Match the pair or roll the key |
| Workflow runs but no Release | Missing `contents: write` permission | Check workflow `permissions:` block |
| Bundle suddenly 10× larger | Accidental pattern dedup failure | Re-run with `--validate` flag (planned) |
