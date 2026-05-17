# Threat feed

Memgar ships a signed threat-intelligence bundle (`memgar-feed.json.gz`)
published to GitHub Releases. Every memgar process pulls the latest bundle
at startup, verifies the Ed25519 signature, and merges new patterns into
the in-memory pattern set without a code release.

## Verification

```python
from memgar.feed import FeedLoader

loader = FeedLoader()
print(loader.health())
```

```python
{
  "status": "ok",
  "repo": "slcxtor/memgar",
  "last_outcome": "loaded",
  "last_attempt_at": "2026-05-17T13:00:00Z",
  "last_bundle_version": "1.2.0",
  "last_pattern_count": 770,
  "used_fallback_url": False,
  "fix_hint": None,
}
```

If verification fails, memgar **does not load** the bundle. Operators see a
single WARNING + the health status flips to `degraded`.

## Cache

| Setting | Default | Notes |
|---|---|---|
| Cache root | `~/.cache/memgar/feeds/` | Override with `MEMGAR_CACHE_DIR` |
| Max age | 7 days | Override with `MEMGAR_FEED_MAX_AGE_DAYS` |
| Max compressed | 20 MB | gzip bomb defense |
| Max decompressed | 100 MB | gzip bomb defense |

## CLI

```bash
memgar feed sync          # force re-pull
memgar feed status        # show last_outcome + version
memgar feed verify        # signature check on cached bundle
```

## Publishing a new bundle (maintainers)

```bash
python scripts/publish_feed.py \
    --private-key-file feed_private.pem \
    --feed-version 1.3.0
```

This:

1. Walks `memgar/patterns.py` + augments from `ml/data/feed_extensions.json`.
2. Builds the bundle, computes SHA-256, signs with the private key.
3. Uploads to GitHub Release `feed-v1.3.0` with the signed `.json.gz`.

The CI workflow `publish-feed.yml` runs this on tagged releases.

## Public key

The Ed25519 verifier is hardcoded at `memgar/feed/verifier.py:FEED_PUBLIC_KEY_B64`
(generated 2026-04-26). Rotating requires:

1. Generating a new keypair with the CLI: `memgar feed keygen --out feed_private.pem`
2. Updating `FEED_PUBLIC_KEY_B64` in source.
3. Re-publishing the next bundle with the new private key.
4. Cutting a memgar release so deployed instances pick up the new pubkey.

This is intentional — auto-rotating pubkeys would let a feed compromise
extend into a supply-chain compromise.

## Security model

| Threat | Mitigation |
|---|---|
| Tampered bundle in transit | Ed25519 signature verified before caching |
| Stale bundle | `max_age_days` triggers re-pull |
| Gzip bomb | 20MB compressed / 100MB decompressed hard limits |
| SSRF | `_ALLOWED_HOSTS` restricts to `github.com` / `*.githubusercontent.com` |
| Pickle RCE | Bundle is JSON; no pickle, no eval, no exec |
| Feed maintainer takeover | Public key rotation requires source change + release |
