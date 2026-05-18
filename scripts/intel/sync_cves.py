"""Sync recent NVD CVEs whose descriptions match AI/LLM threat keywords.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0 (NIST NVD REST API)

Filters:
  - `pubStartDate` = today − 30 days
  - Description matches the `is_ai_relevant()` keyword set
  - CVSS v3 score ≥ 4.0 (medium+) to skip noise

Output JSONL has one Candidate per matching CVE. The curator decides
which deserve a memgar pattern (most don't — many AI CVEs are about
specific vendor model bugs that aren't pattern-matchable).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import (
    Candidate, CandidateSource, guess_severity, is_ai_relevant,
    normalize_text, read_seen_fingerprints, request_get, write_candidates,
)

logger = logging.getLogger("memgar.intel.cve")


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_LOOKBACK_DAYS = 30
DEFAULT_MIN_CVSS = 4.0


def _build_url(start: datetime, end: datetime, start_index: int) -> str:
    return (
        f"{NVD_API}?"
        f"pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&resultsPerPage=200&startIndex={start_index}"
    )


def _cve_to_candidate(cve_entry: dict, min_cvss: float) -> Optional[Candidate]:
    cve = cve_entry.get("cve", {})
    cve_id = cve.get("id", "")
    descs = cve.get("descriptions", []) or []
    text = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
    if not text or not is_ai_relevant(text):
        return None

    # Get CVSS v3 base score from metrics
    metrics = cve.get("metrics", {})
    score = 0.0
    severity_word = "low"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            severity_word = data.get("baseSeverity", "").lower() or severity_word
            break
    if score < min_cvss:
        return None

    # Severity guess: prefer CVSS-reported, fall back to keyword heuristic
    sev = severity_word if severity_word in {"low", "medium", "high", "critical"} \
        else guess_severity(text)

    return Candidate(
        source=CandidateSource.NVD_CVE,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source_id=cve_id,
        proposed_id=f"CVE-{cve_id.replace('CVE-', '')}",
        name=f"{cve_id} — {text[:80].strip()}",
        description=normalize_text(text, max_len=350),
        severity_guess=sev,
        category_guess="injection",  # default; curator usually overrides
        keywords=[],
        examples=[],
        regex_proposals=[],
        sample_text=normalize_text(text, max_len=500),
    )


def sync_cves(
    *,
    output_path: Path = Path("proposed_patterns/cve.jsonl"),
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    min_cvss: float = DEFAULT_MIN_CVSS,
    dry_run: bool = False,
    cached_json: Optional[Path] = None,
    nvd_api_key: Optional[str] = None,
) -> int:
    """Run one CVE sync pass. Returns count of new candidates written."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)

    headers = {"apiKey": nvd_api_key} if nvd_api_key else None
    seen = read_seen_fingerprints(output_path)
    candidates: List[Candidate] = []

    if cached_json:
        logger.info("Reading cached NVD JSON from %s", cached_json)
        pages = [json.loads(cached_json.read_text())]
    else:
        pages = []
        start_index = 0
        while True:
            url = _build_url(start, end, start_index)
            logger.info("Fetching %s", url)
            raw = request_get(url, headers=headers)
            page = json.loads(raw)
            pages.append(page)
            total = int(page.get("totalResults", 0))
            per = int(page.get("resultsPerPage", 0))
            start_index += per
            if start_index >= total or per == 0:
                break

    for page in pages:
        for entry in page.get("vulnerabilities", []) or []:
            cand = _cve_to_candidate(entry, min_cvss=min_cvss)
            if cand is None:
                continue
            candidates.append(cand)

    new_count = len([c for c in candidates if c.fingerprint not in seen])
    logger.info("Matched %d AI-relevant CVEs, %d new after dedup",
                len(candidates), new_count)

    if dry_run:
        for c in candidates[:5]:
            logger.info(" • %s [%s] — %s", c.source_id, c.severity_guess, c.name)
        return len(candidates)

    return write_candidates(candidates, output_path, seen_fingerprints=seen)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("proposed_patterns/cve.jsonl"))
    p.add_argument("--lookback-days", type=int, default=DEFAULT_LOOKBACK_DAYS)
    p.add_argument("--min-cvss", type=float, default=DEFAULT_MIN_CVSS)
    p.add_argument("--cached-json", type=Path, default=None,
                   help="Local NVD JSON file (offline / CI cache)")
    p.add_argument("--api-key", default=None,
                   help="NVD API key (raises rate limit from 5 → 50 req/30s)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    count = sync_cves(
        output_path=args.output,
        lookback_days=args.lookback_days,
        min_cvss=args.min_cvss,
        dry_run=args.dry_run,
        cached_json=args.cached_json,
        nvd_api_key=args.api_key,
    )
    print(f"cve sync: {count} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
