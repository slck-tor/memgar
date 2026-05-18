"""Threat-intelligence sync scripts — shared models and helpers.

Five sources, each with its own `sync_*.py` script that emits a stream
of `Candidate` records into `proposed_patterns/` for human review:

  sync_mitre.py        MITRE ATT&CK Enterprise (mitre/cti GitHub repo)
  sync_cves.py         NVD REST API (LLM/AI-tagged CVEs, last 30 days)
  sync_owasp.py        OWASP ASI / Top-10-for-LLM GitHub releases
  sync_jailbreak_repos.py     4 public jailbreak corpus repos
  sync_huggingface_datasets.py     Gated HF datasets (WildJailbreak, JBB)

All scripts use the same:
  - `Candidate` dataclass for proposed-pattern records
  - `write_candidates(...)` JSON-Lines output
  - `request_get(...)` polite-rate-limit HTTP helper
  - `existing_pattern_ids()` to avoid proposing duplicates of what's
    already in `memgar/patterns.py`

The orchestrator `.github/workflows/threat-intel-sync.yml` runs all
five on a schedule, collects the candidate JSONLs, and opens a single
aggregate PR labelled `threat-intel-proposal` for curator review.
"""

from __future__ import annotations

from .common import (
    Candidate,
    CandidateSource,
    write_candidates,
    request_get,
    existing_pattern_ids,
    normalize_text,
    is_ai_relevant,
)

__all__ = [
    "Candidate",
    "CandidateSource",
    "write_candidates",
    "request_get",
    "existing_pattern_ids",
    "normalize_text",
    "is_ai_relevant",
]
