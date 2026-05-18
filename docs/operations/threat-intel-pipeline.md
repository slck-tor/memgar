# Threat intelligence sync pipeline

`memgar/patterns.py` is the source of truth — and we keep it growing by
**actively sourcing** from external threat-intel feeds, not by sitting
on a static library. This page describes the sync pipeline, the
sources, and the curator workflow.

For end-user feed distribution (publishing the signed bundle to
clients) see [Threat Feed Pipeline](threat-feed-pipeline.md).

## Sources

Five sources, polled weekly by `.github/workflows/threat-intel-sync.yml`:

| Source | Module | Frequency | Yield (est./yr) | Why |
|---|---|---|---|---|
| **MITRE ATT&CK** Enterprise | `sync_mitre.py` | quarterly upstream | 5–15 new techniques | Authority, public, well-structured STIX |
| **NVD CVE** | `sync_cves.py` | daily upstream | 10–30 AI-tagged | Credibility + traceability, NIST-stamped |
| **OWASP ASI / Top-10-LLM** | `sync_owasp.py` | 2–5 releases | Category-level | Sector standard, authoritative definitions |
| **Public jailbreak repos** | `sync_jailbreak_repos.py` | continuous | 50–200 samples | Community signal, noisiest channel |
| **HuggingFace gated datasets** | `sync_huggingface_datasets.py` | weekly | Hundreds | Corpus expansion (WildJailbreak, JBB, etc.) |

Each script reads its upstream, normalises to a common `Candidate`
record (`scripts/intel/common.py::Candidate`), dedupes against
fingerprints already seen, and writes to a per-source JSONL file under
`proposed_patterns/`.

## Pipeline flow

```
external sources                   CI (Thu 04:00 UTC)               human curator (you)
─────────────────                  ──────────────────                ───────────────────
mitre/cti GitHub repo
  → JSON                  ──┐
NIST NVD REST API           │
  → JSON                    │       sync_mitre.py
OWASP releases (gh API)     ├─►     sync_cves.py            ─► proposed_patterns/*.jsonl
public jailbreak repos      │       sync_owasp.py                   │
HuggingFace datasets-server │       sync_jailbreak_repos.py         │
  → JSON                  ──┘       sync_huggingface.py             │
                                                                    ▼
                                    create-pull-request action ─► curator PR
                                                                    │
                                                                    ▼
                                                          curate.py (interactive /
                                                          batch / stats)
                                                                    │
                                                                    ▼
                                                          proposed_patterns/
                                                              accepted.jsonl
                                                                    │
                                                                    ▼
                                                          curator manually drafts
                                                          regex/keywords/examples
                                                          → memgar/patterns.py
                                                                    │
                                                                    ▼
                                                          next Mon 06:00 UTC:
                                                          feed-publish workflow
                                                          ships them as feed-v.*
```

## Cadence

| Day  | Action |
|---|---|
| Thu 04:00 UTC | `threat-intel-sync.yml` cron — pull all sources, open PR |
| Thu–Sun | Curator (you) reviews PR, runs `curate.py` over candidates |
| Mon 06:00 UTC | `feed-publish.yml` cron — bundles current `patterns.py` and publishes new signed feed |

This 4-day gap between sync and publish is deliberate: gives the
curator a working week to make judgement calls without rushing.

## Curator workflow

```bash
# 1. Overview — see what the sync produced
python scripts/intel/curate.py --stats

# 2. Walk every candidate interactively (a/r/s/q per item)
python scripts/intel/curate.py

# 3. Bulk-accept a known-good source (e.g. authoritative MITRE)
python scripts/intel/curate.py --auto-accept-source mitre_attack

# 4. After curation, review accepted.jsonl
cat proposed_patterns/accepted.jsonl | jq -r .name

# 5. Manually draft patterns from accepted entries
$EDITOR memgar/patterns.py
# (add regex, keywords, examples, citing the source_url)

# 6. Verify the new patterns load and detection works
python -m pytest tests/test_analyzer.py tests/test_intel_sync.py -q
```

The curator step is **deliberately manual**. Auto-promoting community
samples to live patterns risks FP inflation; the bar to add a regex
to `patterns.py` should always be a human's "yes, this matches a real
attack class".

## Filter rules per source

### MITRE
- Technique ID must start with one of:
  `T1027 T1059 T1078 T1080 T1190 T1199 T1530 T1546 T1547 T1556 T1557 T1565 T1570 T1657`
- Description must hit the `AI_RELEVANT_KEYWORDS` regex
  (`llm|gpt|claude|memory poisoning|jailbreak|rag|…`)
- Technique ID must NOT already appear as `mitre_attack=...` in
  `memgar/patterns.py` (avoids re-proposing what's covered)

### CVE
- Published in the last `--lookback-days` (default 30)
- CVSS v3 base score ≥ `--min-cvss` (default 4.0)
- Description must hit `AI_RELEVANT_KEYWORDS`
- Severity guess prefers CVSS-reported, falls back to keyword heuristic

### OWASP
- Any new release tag from the LLM Top 10 GitHub repo
- All releases pass through to the curator queue (low volume)

### Jailbreak repos
- Hand-curated source list in `sync_jailbreak_repos.py::SOURCES`
- Adding a new source = manual decision (review the repo's licence
  and signal quality first)
- Per-source cap of 50 samples per run to keep curator queue bounded
- Each sample passes through `_category_for()` to guess the right
  ThreatCategory

### HuggingFace
- Hand-curated dataset list in `sync_huggingface_datasets.py::DATASETS`
- Gated datasets require `HF_TOKEN` env var or `--hf-token`
- Per-dataset cap of 100 rows per run

## Operational disciplines

| Discipline | Cadence | Why |
|---|---|---|
| Curator review of weekly PR | every Thu–Sun | Catches new attack vectors fast |
| Manual pattern drafting | as accepted entries accumulate | The bar stays high; no auto-promote |
| Source-list audit | quarterly | Drop dead repos; add new sources |
| `proposed_patterns/rejected.jsonl` review | quarterly | Look for FN trends — what did we say no to that we shouldn't? |
| Source fingerprint cleanup | when JSONLs exceed ~5 MB | Truncate seen-list to prevent unbounded growth |

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| Sync workflow fails on rate-limit | NVD or GitHub API quota | Add `NVD_API_KEY` / `GITHUB_TOKEN` secrets |
| 0 candidates from a source | Upstream URL changed | Update the `raw_url` in the relevant script |
| Curator PR not opened | `peter-evans/create-pull-request` action permission | Check `permissions:` in workflow YAML |
| Same candidate appears every week | Fingerprint isn't stable | Bug in `Candidate.__post_init__` |
| Gated HF dataset returns 401 | `HF_TOKEN` invalid or revoked | Rotate token, set as repo secret |

## Local testing

Each script has a `--cached-json` flag for offline testing:

```bash
# Test the MITRE sync against a snapshot
wget -O /tmp/mitre.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python scripts/intel/sync_mitre.py --cached-json /tmp/mitre.json --dry-run

# Test CVE sync against an NVD page snapshot
curl -o /tmp/cve.json "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=llm&resultsPerPage=20"
python scripts/intel/sync_cves.py --cached-json /tmp/cve.json --dry-run
```

`--dry-run` skips the JSONL write and just prints the first 5 matches —
useful when verifying a source after upstream format changes.

## Why this matters

A static `patterns.py` ages. A live feed ages with the field. Memgar's
moat isn't the 807 patterns it ships today; it's the operational
discipline that keeps that number current with what attackers
actually do this month.
