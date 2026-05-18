"""Shared utilities for all threat-intel sync scripts."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

logger = logging.getLogger("memgar.intel")


# ─── AI-relevance filter ──────────────────────────────────────────────


AI_RELEVANT_KEYWORDS = re.compile(
    r"(?<!\w)("
    r"llm|gpt|claude|gemini|mistral|llama|"
    r"prompt[\s-]?inject\w*|memory[\s-]?poison\w*|jailbreak\w*|"
    r"agent[\s-]?security|rag|vector[\s-]?(db|database|store)|"
    r"embedding[\s-]?attack\w*|tool[\s-]?(use|call)[\s-]?attack\w*|"
    r"semantic[\s-]?attack\w*|owasp[\s-]?llm|asi-?06|"
    r"large[\s-]?language[\s-]?model|generative[\s-]?ai"
    r")(?!\w)",
    re.IGNORECASE,
)


def is_ai_relevant(text: str) -> bool:
    """Quick keyword filter — true if text looks AI-security related."""
    return bool(AI_RELEVANT_KEYWORDS.search(text or ""))


# ─── Candidate model ──────────────────────────────────────────────────


class CandidateSource(str, Enum):
    MITRE_ATTACK = "mitre_attack"
    NVD_CVE = "nvd_cve"
    OWASP_ASI = "owasp_asi"
    JAILBREAK_REPO = "jailbreak_repo"
    HUGGINGFACE = "huggingface"


@dataclass
class Candidate:
    """A proposed-pattern record produced by a sync script.

    Curator (human) reviews these, may edit the suggested regex /
    keywords / examples, then accepts → manually moves the entry
    into `memgar/patterns.py`.

    The aim is to give the curator enough context to make a 30-second
    decision: source URL, source identifier (CVE / technique ID /
    paper title), severity guess, the actual offending sample text.
    """

    source: CandidateSource
    source_url: str
    source_id: str
    proposed_id: str
    name: str
    description: str
    severity_guess: str               # "low" | "medium" | "high" | "critical"
    category_guess: str               # ThreatCategory enum value
    mitre_attack: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    regex_proposals: List[str] = field(default_factory=list)
    sample_text: str = ""             # original raw sample (truncated)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fingerprint: str = ""             # sha256(source_id+name) — dedup key

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = hashlib.sha256(
                f"{self.source.value}:{self.source_id}:{self.name}".encode("utf-8")
            ).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = self.source.value
        return d


# ─── I/O ──────────────────────────────────────────────────────────────


def write_candidates(
    candidates: Iterable[Candidate],
    output_path: Path,
    *,
    seen_fingerprints: Optional[Set[str]] = None,
) -> int:
    """Write candidates to a JSONL file. Skips fingerprints already seen.

    Returns the count of new candidates actually written. The caller
    typically maintains `seen_fingerprints` across runs to keep the
    review queue bounded.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    seen = set(seen_fingerprints or [])
    written = 0
    mode = "a" if output_path.exists() else "w"
    with output_path.open(mode, encoding="utf-8") as fh:
        for cand in candidates:
            if cand.fingerprint in seen:
                continue
            fh.write(json.dumps(cand.to_dict(), ensure_ascii=False) + "\n")
            seen.add(cand.fingerprint)
            written += 1
    logger.info("Wrote %d new candidates to %s (skipped %d dups)",
                written, output_path, len(seen) - written)
    return written


def read_seen_fingerprints(output_path: Path) -> Set[str]:
    """Read fingerprints already present in `output_path` (idempotency)."""
    if not output_path.exists():
        return set()
    out: Set[str] = set()
    with output_path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                row = json.loads(line)
                if "fingerprint" in row:
                    out.add(row["fingerprint"])
            except json.JSONDecodeError:
                pass
    return out


# ─── Polite HTTP ──────────────────────────────────────────────────────


def request_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
    retries: int = 3,
    backoff: float = 1.5,
) -> bytes:
    """GET with retry + exponential backoff, polite User-Agent."""
    base_headers = {
        "User-Agent": "memgar-threat-intel-sync/0.1 (https://memgar.com)",
        "Accept": "application/json,application/xml,text/plain,*/*",
    }
    base_headers.update(headers or {})
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=base_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
                if url.endswith(".gz"):
                    return gzip.decompress(payload)
                return payload
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504):
                last_exc = exc
                sleep_s = backoff ** attempt + 1
                logger.warning(
                    "HTTP %d on %s (try %d/%d) — sleeping %.1fs",
                    exc.code, url, attempt + 1, retries, sleep_s,
                )
                time.sleep(sleep_s)
                continue
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(backoff ** attempt)
    if last_exc:
        raise last_exc
    raise RuntimeError(f"request_get exhausted retries for {url}")


# ─── Text helpers ─────────────────────────────────────────────────────


def normalize_text(text: str, *, max_len: int = 500) -> str:
    """Trim, collapse whitespace, truncate, strip control chars."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


# ─── Existing-pattern lookup ──────────────────────────────────────────


_PATTERN_FILE = Path("memgar/patterns.py")


def existing_pattern_ids(patterns_file: Path = _PATTERN_FILE) -> Set[str]:
    """Return the set of pattern IDs already in `memgar/patterns.py`.

    Used by sync scripts to avoid proposing duplicates of known patterns.
    """
    if not patterns_file.exists():
        return set()
    spec = importlib.util.spec_from_file_location("_patterns_module", patterns_file)
    if spec is None or spec.loader is None:
        return set()
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return {p.id for p in mod.PATTERNS}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Cannot import patterns: %s", exc)
        return set()


# ─── Severity heuristic ───────────────────────────────────────────────


def guess_severity(text: str) -> str:
    """Best-effort severity from a CVE/technique description."""
    lower = (text or "").lower()
    critical_signals = ("rce", "remote code", "arbitrary code execution",
                        "exfiltration", "privilege escalation",
                        "data manipulation")
    high_signals = ("injection", "bypass", "tamper", "poisoning")
    medium_signals = ("disclosure", "information leak", "obfuscation")
    if any(s in lower for s in critical_signals):
        return "critical"
    if any(s in lower for s in high_signals):
        return "high"
    if any(s in lower for s in medium_signals):
        return "medium"
    return "low"


__all__ = [
    "Candidate",
    "CandidateSource",
    "write_candidates",
    "read_seen_fingerprints",
    "request_get",
    "normalize_text",
    "is_ai_relevant",
    "existing_pattern_ids",
    "guess_severity",
    "AI_RELEVANT_KEYWORDS",
]
