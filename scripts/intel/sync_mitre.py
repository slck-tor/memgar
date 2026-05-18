"""Sync MITRE ATT&CK Enterprise techniques relevant to AI/LLM agents.

Source: https://github.com/mitre/cti — STIX/TAXII JSON, updated quarterly.
We pull the latest `enterprise-attack.json`, filter to techniques whose
name/description matches the AI-relevance keyword set, and emit a
`Candidate` for each one whose ID isn't already mapped to a memgar
pattern.

Curator workflow:
  1. CI runs this script weekly.
  2. New candidates land in `proposed_patterns/mitre.jsonl`.
  3. Curator (you) reviews, accepts useful ones into `memgar/patterns.py`
     (typically by adding `mitre_attack="T1565.001"` to existing patterns
     or creating new MITRE-named patterns where coverage is missing).

The "ID already in patterns.py" check uses `mitre_attack=` strings, so
patterns that already cite the technique are skipped — avoids spam.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

# Make `from scripts.intel.common import *` work when run as a script
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.intel.common import (
    Candidate, CandidateSource, existing_pattern_ids, guess_severity,
    normalize_text, read_seen_fingerprints, request_get, write_candidates,
)

logger = logging.getLogger("memgar.intel.mitre")


MITRE_ENTERPRISE_JSON = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# Sub-tree of MITRE that's plausibly relevant to AI agents. We start
# narrow and only flag techniques whose description ALSO matches the
# AI-relevance keyword filter — keeps false positives down.
AI_TECHNIQUE_PREFIXES = (
    "T1027",   # Obfuscated Files or Information
    "T1059",   # Command and Scripting Interpreter
    "T1078",   # Valid Accounts
    "T1080",   # Taint Shared Content
    "T1190",   # Exploit Public-Facing Application
    "T1199",   # Trusted Relationship
    "T1530",   # Data from Cloud Storage Object
    "T1546",   # Event Triggered Execution
    "T1547",   # Boot or Logon Autostart Execution
    "T1556",   # Modify Authentication Process
    "T1557",   # Adversary-in-the-Middle
    "T1565",   # Data Manipulation
    "T1570",   # Lateral Tool Transfer
    "T1657",   # Financial Theft
)


def _existing_mitre_refs(patterns_file: Path) -> Set[str]:
    """Read `mitre_attack="T1565.001"` style refs already in patterns.py."""
    if not patterns_file.exists():
        return set()
    text = patterns_file.read_text(encoding="utf-8")
    return set(re.findall(r'mitre_attack=["\']?(T\d{4}(?:\.\d{3})?)["\']?', text))


def _technique_to_candidate(tech: dict) -> Optional[Candidate]:
    """Map a MITRE technique object to a memgar Candidate, or None."""
    name = tech.get("name", "")
    description = tech.get("description", "")
    external = tech.get("external_references", []) or []
    tech_id = None
    url = ""
    for ref in external:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
            tech_id = ref["external_id"]
            url = ref.get("url", "")
            break
    if not tech_id:
        return None
    if not any(tech_id.startswith(prefix) for prefix in AI_TECHNIQUE_PREFIXES):
        return None
    haystack = f"{name}\n{description}"
    # Use AI relevance OR explicit cyber-physical / supply-chain category hint
    from scripts.intel.common import is_ai_relevant
    if not is_ai_relevant(haystack):
        return None
    severity = guess_severity(haystack)
    return Candidate(
        source=CandidateSource.MITRE_ATTACK,
        source_url=url,
        source_id=tech_id,
        proposed_id=f"MITRE-{tech_id}",
        name=name[:120],
        description=normalize_text(description, max_len=280),
        severity_guess=severity,
        category_guess=_category_from_technique(tech_id),
        mitre_attack=tech_id,
        keywords=[],
        examples=[],
        regex_proposals=[],
        sample_text=normalize_text(description, max_len=400),
    )


def _category_from_technique(tech_id: str) -> str:
    """Best-guess `ThreatCategory.value` from a technique ID prefix."""
    mapping = {
        "T1565": "manipulation",   # Data Manipulation
        "T1080": "behavior",       # Taint Shared Content
        "T1546": "sleeper",        # Event Triggered Execution
        "T1547": "sleeper",        # Boot/Logon Autostart
        "T1078": "privilege",      # Valid Accounts
        "T1530": "exfiltration",   # Data from Cloud Storage
        "T1057": "execution",
        "T1059": "execution",
        "T1027": "evasion",        # Obfuscated Files
        "T1199": "social",         # Trusted Relationship
        "T1570": "behavior",       # Lateral Tool Transfer
        "T1657": "financial",
        "T1556": "credential",
        "T1190": "injection",
    }
    return mapping.get(tech_id[:5], "behavior")


def sync_mitre(
    *,
    output_path: Path = Path("proposed_patterns/mitre.jsonl"),
    patterns_file: Path = Path("memgar/patterns.py"),
    dry_run: bool = False,
    cached_json: Optional[Path] = None,
) -> int:
    """Run one full MITRE sync pass. Returns count of new candidates."""
    if cached_json:
        logger.info("Reading cached enterprise-attack.json from %s", cached_json)
        raw = cached_json.read_bytes()
    else:
        logger.info("Fetching %s", MITRE_ENTERPRISE_JSON)
        raw = request_get(MITRE_ENTERPRISE_JSON)
    bundle = json.loads(raw)

    objects = bundle.get("objects", []) or []
    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern" and not o.get("revoked")
    ]
    logger.info("Loaded %d techniques", len(techniques))

    existing_refs = _existing_mitre_refs(patterns_file)
    seen_fps = read_seen_fingerprints(output_path)

    candidates: List[Candidate] = []
    for tech in techniques:
        cand = _technique_to_candidate(tech)
        if cand is None:
            continue
        if cand.mitre_attack in existing_refs:
            continue
        candidates.append(cand)

    logger.info(
        "Found %d AI-relevant techniques, %d new after dedup",
        len(candidates),
        len([c for c in candidates if c.fingerprint not in seen_fps]),
    )

    if dry_run:
        for c in candidates[:5]:
            logger.info(" • %s — %s [%s]", c.proposed_id, c.name, c.severity_guess)
        return len(candidates)

    return write_candidates(candidates, output_path, seen_fingerprints=seen_fps)


# ─── CLI ──────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("proposed_patterns/mitre.jsonl"))
    parser.add_argument("--patterns-file", type=Path, default=Path("memgar/patterns.py"))
    parser.add_argument("--cached-json", type=Path, default=None,
                        help="Use this local file instead of fetching (offline / CI cache)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    count = sync_mitre(
        output_path=args.output,
        patterns_file=args.patterns_file,
        cached_json=args.cached_json,
        dry_run=args.dry_run,
    )
    print(f"mitre sync: {count} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
