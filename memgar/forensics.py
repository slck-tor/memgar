"""
Memgar Memory Forensics Engine
================================

Incident response and forensic analysis for already-poisoned AI agent memory stores.

While Memgar's core layers prevent threats from entering memory in real-time,
the Forensics Engine answers a different question:

    "My agent has been running unprotected — what damage has been done?"

Key capabilities:

    MemoryForensicsEngine   — Deep scan of existing memory stores with timeline
    ForensicEntry           — Individual memory entry with full forensic metadata
    PoisonTimeline          — Chronological reconstruction of the poisoning chain
    ForensicReport          — Complete incident report (JSON + HTML)
    MemoryCleanser          — Safe in-place cleaning of poisoned entries
    SkillFileScanner        — Scan MEMORY.md / skills / plugin files for backdoors

CLI usage::

    memgar forensics scan ./memory_store/
    memgar forensics scan ./agent_memory.json --clean --output report.html
    memgar forensics timeline ./memories/ --since 2026-03-01
    memgar forensics skill ./skills/my_skill/
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from memgar.analyzer import Analyzer
from memgar.models import AnalysisResult, Decision, MemoryEntry, Severity


# ---------------------------------------------------------------------------
# Enums & Data Models
# ---------------------------------------------------------------------------


class PoisonSeverity(str, Enum):
    CRITICAL = "critical"   # Active backdoor / credential theft / data exfil
    HIGH = "high"           # Behavior manipulation / privilege escalation
    MEDIUM = "medium"       # Suspicious sleeper / evasion pattern
    LOW = "low"             # Minor anomaly, possible false positive
    CLEAN = "clean"         # No threats found


class EntrySource(str, Enum):
    JSON = "json"
    SQLITE = "sqlite"
    MARKDOWN = "markdown"
    TEXT = "text"
    SKILL_FILE = "skill_file"
    UNKNOWN = "unknown"


@dataclass
class ForensicEntry:
    """
    A single memory entry with full forensic metadata.

    Includes the original content, analysis result, a hash fingerprint,
    inferred timestamp, and cleaned version (if applicable).
    """
    index: int                          # Position in the source store
    content: str                        # Original raw content
    source_file: str                    # File path this came from
    source_type: EntrySource            # JSON / SQLite / Markdown / etc.
    content_hash: str                   # SHA-256 of raw content
    analysis: AnalysisResult            # Full Memgar analysis result
    poison_severity: PoisonSeverity     # Derived severity
    inferred_timestamp: Optional[str]   # From metadata, if available
    raw_metadata: Dict[str, Any]        # Full original metadata dict
    cleaned_content: Optional[str]      # Sanitized version (if clean=True)
    is_cleaned: bool = False

    @property
    def is_poisoned(self) -> bool:
        return self.poison_severity not in (PoisonSeverity.CLEAN, PoisonSeverity.LOW)

    @property
    def threat_ids(self) -> List[str]:
        return [t.threat.id for t in self.analysis.threats]

    @property
    def threat_names(self) -> List[str]:
        return [t.threat.name for t in self.analysis.threats]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "source_file": self.source_file,
            "source_type": self.source_type.value,
            "content_hash": self.content_hash,
            "inferred_timestamp": self.inferred_timestamp,
            "poison_severity": self.poison_severity.value,
            "risk_score": self.analysis.risk_score,
            "decision": self.analysis.decision.value,
            "threat_count": len(self.analysis.threats),
            "threat_ids": self.threat_ids,
            "threat_names": self.threat_names,
            "content_preview": self.content[:200] + ("..." if len(self.content) > 200 else ""),
            "is_cleaned": self.is_cleaned,
            "cleaned_preview": (
                self.cleaned_content[:200] if self.cleaned_content else None
            ),
        }


@dataclass
class PoisonEvent:
    """A single event on the poisoning timeline."""
    timestamp: Optional[str]            # ISO timestamp or None if unknown
    entry_index: int
    source_file: str
    poison_severity: PoisonSeverity
    threat_names: List[str]
    risk_score: int
    content_preview: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp or "unknown",
            "entry_index": self.entry_index,
            "source_file": self.source_file,
            "poison_severity": self.poison_severity.value,
            "threat_names": self.threat_names,
            "risk_score": self.risk_score,
            "content_preview": self.content_preview,
        }


@dataclass
class ForensicReport:
    """
    Complete forensic investigation report.

    Contains summary statistics, all forensic entries, the poisoning timeline,
    and recommendations for remediation.
    """
    scan_id: str
    scan_started_at: str
    scan_completed_at: str
    scan_duration_ms: float
    target_path: str

    # Counts
    total_entries: int = 0
    clean_entries: int = 0
    poisoned_entries: int = 0
    cleaned_entries: int = 0

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Unique threat categories found
    threat_categories: List[str] = field(default_factory=list)
    threat_ids_found: List[str] = field(default_factory=list)

    # All entries and timeline
    entries: List[ForensicEntry] = field(default_factory=list)
    poisoned_entries_list: List[ForensicEntry] = field(default_factory=list)
    timeline: List[PoisonEvent] = field(default_factory=list)

    # Remediation
    recommendations: List[str] = field(default_factory=list)

    @property
    def is_compromised(self) -> bool:
        return self.poisoned_entries > 0

    @property
    def compromise_rate(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return round(self.poisoned_entries / self.total_entries * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_started_at": self.scan_started_at,
            "scan_completed_at": self.scan_completed_at,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "target_path": self.target_path,
            "summary": {
                "total_entries": self.total_entries,
                "clean_entries": self.clean_entries,
                "poisoned_entries": self.poisoned_entries,
                "cleaned_entries": self.cleaned_entries,
                "compromise_rate_pct": self.compromise_rate,
                "is_compromised": self.is_compromised,
                "severity_breakdown": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                },
            },
            "threat_categories": self.threat_categories,
            "threat_ids_found": self.threat_ids_found,
            "timeline": [e.to_dict() for e in self.timeline],
            "poisoned_entries": [e.to_dict() for e in self.poisoned_entries_list],
            "recommendations": self.recommendations,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TIMESTAMP_KEYS = (
    "timestamp", "created_at", "updated_at", "time", "date",
    "created", "modified", "ts", "datetime",
)

_CONTENT_KEYS = (
    "content", "text", "message", "value", "memory",
    "data", "body", "input", "output", "response",
)

_TS_PATTERNS = [
    # ISO 8601 variants
    re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"),
    # Unix timestamps (10 or 13 digits)
    re.compile(r"\b(1[6-9]\d{8}|1[6-9]\d{11})\b"),
]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _extract_timestamp(obj: Any) -> Optional[str]:
    """Try to find a timestamp in a dict or string."""
    if isinstance(obj, dict):
        for key in _TIMESTAMP_KEYS:
            val = obj.get(key)
            if val:
                ts = _parse_timestamp(val)
                if ts:
                    return ts
    if isinstance(obj, str):
        for pat in _TS_PATTERNS:
            m = pat.search(obj)
            if m:
                return _parse_timestamp(m.group(1))
    return None


def _parse_timestamp(val: Any) -> Optional[str]:
    """Normalize a timestamp value to ISO string."""
    if isinstance(val, (int, float)):
        # Unix timestamp in seconds or ms
        ts = val / 1000 if val > 1e10 else val
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(val, str):
        val = val.strip()
        # Try ISO parse
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        # Try unix-in-string
        if val.isdigit() and len(val) in (10, 13):
            return _parse_timestamp(int(val))
    return None


def _extract_content(obj: Any) -> str:
    """Extract text content from various entry formats."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for key in _CONTENT_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val
        # Fallback: serialize the whole dict
        return json.dumps(obj, ensure_ascii=False)
    return str(obj)


def _derive_severity(result: AnalysisResult) -> PoisonSeverity:
    if result.decision == Decision.ALLOW and not result.threats:
        return PoisonSeverity.CLEAN
    score = result.risk_score
    if score >= 80:
        return PoisonSeverity.CRITICAL
    if score >= 60:
        return PoisonSeverity.HIGH
    if score >= 35:
        return PoisonSeverity.MEDIUM
    return PoisonSeverity.LOW


def _generate_scan_id() -> str:
    ts = int(time.time() * 1000)
    return f"FRS-{ts:x}".upper()


# ---------------------------------------------------------------------------
# Memory Cleanser
# ---------------------------------------------------------------------------

class MemoryCleanser:
    """
    Safely removes or neutralizes poisoned content from memory entries.

    The cleanser operates in two modes:
    - ``redact``: Replace threat payload with a redaction marker
    - ``strip``:  Remove the entire entry
    """

    REDACT_MARKER = "[MEMGAR-REDACTED: threat payload removed]"

    def __init__(self, mode: str = "redact") -> None:
        if mode not in ("redact", "strip"):
            raise ValueError("mode must be 'redact' or 'strip'")
        self.mode = mode
        self._redaction_patterns = self._build_patterns()

    def _build_patterns(self) -> List[re.Pattern]:
        """Build regex patterns for common threat payloads."""
        return [
            # Instruction blocks in various delimiters
            re.compile(
                r"(?i)\[(?:SYSTEM|INST|IGNORE|OVERRIDE|ADMIN)[^\]]*\].*?(?:\[/[^\]]+\]|$)",
                re.DOTALL,
            ),
            re.compile(
                r"(?i)<(?:system|inst|override|ignore)[^>]*>.*?</(?:system|inst|override|ignore)>",
                re.DOTALL,
            ),
            # Hidden unicode zero-width chars blocks
            re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]+"),
            # Explicit injection attempts
            re.compile(
                r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?.*?(?:\.|$)",
                re.MULTILINE,
            ),
            re.compile(
                r"(?i)(?:new|updated?)\s+(?:system\s+)?prompt\s*:.*?(?:\n\n|\Z)",
                re.DOTALL,
            ),
        ]

    def clean(self, content: str) -> str:
        """Return cleaned version of content."""
        if self.mode == "strip":
            return ""
        cleaned = content
        for pat in self._redaction_patterns:
            cleaned = pat.sub(self.REDACT_MARKER, cleaned)
        return cleaned.strip()

    def clean_entry(self, entry: ForensicEntry) -> ForensicEntry:
        """Return a new ForensicEntry with cleaned content."""
        cleaned = self.clean(entry.content)
        entry.cleaned_content = cleaned
        entry.is_cleaned = True
        return entry


# ---------------------------------------------------------------------------
# Skill / Plugin File Scanner
# ---------------------------------------------------------------------------

class SkillFileScanner:
    """
    Scans AI agent skill files, MEMORY.md files, and plugin directories
    for backdoored content that persists even after a malicious skill is removed.

    Targets:
        - MEMORY.md / memory.md / AGENT_MEMORY.md
        - .prompt / .system / .instructions files
        - pyproject.toml / package.json descriptions (supply chain)
        - Any file in a skill/plugin directory
    """

    SKILL_EXTENSIONS = {
        ".md", ".txt", ".prompt", ".system", ".instructions",
        ".yaml", ".yml", ".toml", ".json",
    }

    MEMORY_FILENAMES = {
        "memory.md", "memory.txt", "agent_memory.md",
        "agent_memory.txt", "context.md", "instructions.md",
        "system_prompt.md", "system_prompt.txt",
    }

    def __init__(self, analyzer: Optional[Analyzer] = None) -> None:
        self._analyzer = analyzer or Analyzer()

    def scan_path(self, path: str) -> List[ForensicEntry]:
        """Scan a file or directory for skill backdoors."""
        p = Path(path)
        entries = []
        if p.is_file():
            entries.extend(self._scan_file(p))
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in self.SKILL_EXTENSIONS:
                    entries.extend(self._scan_file(f))
        return entries

    def _scan_file(self, path: Path) -> List[ForensicEntry]:
        results = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return results

        is_memory_file = path.name.lower() in self.MEMORY_FILENAMES

        # Split markdown into sections for finer granularity
        if path.suffix.lower() == ".md":
            sections = re.split(r"(?m)^#{1,3} ", content)
            for i, section in enumerate(sections):
                if not section.strip():
                    continue
                result = self._analyze(section.strip(), str(path))
                severity = _derive_severity(result)
                # For memory files, lower the threshold
                if is_memory_file and severity == PoisonSeverity.LOW:
                    severity = PoisonSeverity.MEDIUM
                results.append(
                    ForensicEntry(
                        index=i,
                        content=section.strip(),
                        source_file=str(path),
                        source_type=EntrySource.SKILL_FILE,
                        content_hash=_sha256(section),
                        analysis=result,
                        poison_severity=severity,
                        inferred_timestamp=None,
                        raw_metadata={"is_memory_file": is_memory_file},
                        cleaned_content=None,
                    )
                )
        else:
            result = self._analyze(content, str(path))
            results.append(
                ForensicEntry(
                    index=0,
                    content=content,
                    source_file=str(path),
                    source_type=EntrySource.SKILL_FILE,
                    content_hash=_sha256(content),
                    analysis=result,
                    poison_severity=_derive_severity(result),
                    inferred_timestamp=None,
                    raw_metadata={"is_memory_file": is_memory_file},
                    cleaned_content=None,
                )
            )
        return results

    def _analyze(self, content: str, source: str) -> AnalysisResult:
        entry = MemoryEntry(content=content, source_type=source)
        return self._analyzer.analyze(entry)


# ---------------------------------------------------------------------------
# Core: Memory Forensics Engine
# ---------------------------------------------------------------------------

class MemoryForensicsEngine:
    """
    Incident response engine for already-poisoned AI agent memory stores.

    Performs a deep forensic scan of a memory store (file or directory),
    reconstructs the poisoning timeline, and optionally cleans entries in-place.

    Usage::

        engine = MemoryForensicsEngine()
        report = engine.scan("./agent_memory/", clean=True)
        print(report.to_json())
        engine.export_report(report, "./forensics_report.html")

    Args:
        analyzer:    Shared Analyzer instance.
        clean_mode:  "redact" (default) or "strip" — how to clean poisoned entries.
        min_severity: Minimum PoisonSeverity to include in poisoned list.
                      Defaults to MEDIUM (skip LOW/noise).
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        clean_mode: str = "redact",
        min_severity: PoisonSeverity = PoisonSeverity.MEDIUM,
    ) -> None:
        self._analyzer = analyzer or Analyzer()
        self._cleanser = MemoryCleanser(mode=clean_mode)
        self._min_severity = min_severity
        self._skill_scanner = SkillFileScanner(analyzer=self._analyzer)

    # ---- Public API --------------------------------------------------------

    def scan(
        self,
        path: str,
        clean: bool = False,
        since: Optional[str] = None,
        recursive: bool = True,
    ) -> ForensicReport:
        """
        Scan a memory store path and return a full forensic report.

        Args:
            path:      File or directory to scan.
            clean:     If True, generate cleaned versions of poisoned entries.
            since:     ISO date string — only report entries after this time.
            recursive: Scan subdirectories (default True).

        Returns:
            ForensicReport with complete analysis.
        """
        t0 = time.perf_counter()
        scan_id = _generate_scan_id()
        started_at = datetime.now(tz=timezone.utc).isoformat()

        p = Path(path)
        all_entries: List[ForensicEntry] = []

        if p.is_file():
            all_entries = list(self._scan_file(p))
        elif p.is_dir():
            glob = p.rglob("*") if recursive else p.glob("*")
            for f in sorted(glob):
                if f.is_file():
                    all_entries.extend(self._scan_file(f))
        else:
            raise FileNotFoundError(f"Path not found: {path}")

        # Apply since filter
        if since:
            since_dt = _parse_timestamp(since)
            if since_dt:
                all_entries = [
                    e for e in all_entries
                    if e.inferred_timestamp is None or e.inferred_timestamp >= since_dt
                ]

        # Clean if requested
        if clean:
            for entry in all_entries:
                if entry.is_poisoned:
                    self._cleanser.clean_entry(entry)

        # Build report
        report = self._build_report(
            scan_id=scan_id,
            started_at=started_at,
            target_path=path,
            entries=all_entries,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
        return report

    def scan_skill(self, path: str) -> ForensicReport:
        """
        Specialized scan for AI agent skill / plugin directories.

        Targets MEMORY.md, .prompt, .instructions, and config files.
        """
        t0 = time.perf_counter()
        scan_id = _generate_scan_id()
        started_at = datetime.now(tz=timezone.utc).isoformat()

        all_entries = self._skill_scanner.scan_path(path)

        report = self._build_report(
            scan_id=scan_id,
            started_at=started_at,
            target_path=path,
            entries=all_entries,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
        return report

    def write_clean_store(
        self,
        report: ForensicReport,
        output_path: str,
    ) -> int:
        """
        Write a cleaned copy of all JSON entries to output_path.

        Only works for JSON-sourced stores. Returns number of entries written.
        """
        out = Path(output_path)
        cleaned_entries = []
        for entry in report.entries:
            if entry.source_type != EntrySource.JSON:
                continue
            content = entry.cleaned_content if entry.is_cleaned else entry.content
            obj = json.loads(entry.raw_metadata.get("_raw_json", json.dumps({"content": content})))
            if entry.is_cleaned:
                obj["content"] = content
                obj["memgar_cleaned"] = True
                obj["memgar_scan_id"] = report.scan_id
            cleaned_entries.append(obj)
        out.write_text(json.dumps(cleaned_entries, indent=2, ensure_ascii=False), encoding="utf-8")
        return len(cleaned_entries)

    def export_report(self, report: ForensicReport, output_path: str) -> None:
        """Export report as HTML or JSON based on file extension."""
        p = Path(output_path)
        if p.suffix.lower() == ".html":
            p.write_text(self._render_html(report), encoding="utf-8")
        else:
            p.write_text(report.to_json(), encoding="utf-8")

    # ---- File readers ------------------------------------------------------

    def _scan_file(self, path: Path) -> Iterator[ForensicEntry]:
        ext = path.suffix.lower()
        try:
            if ext == ".json":
                yield from self._read_json(path)
            elif ext in (".db", ".sqlite", ".sqlite3"):
                yield from self._read_sqlite(path)
            elif ext in (".md", ".markdown"):
                yield from self._read_markdown(path)
            else:
                yield from self._read_text(path)
        except Exception:
            # Silently skip unreadable files
            pass

    def _read_json(self, path: Path) -> Iterator[ForensicEntry]:
        raw = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return
        for i, obj in enumerate(data):
            content = _extract_content(obj)
            if not content.strip():
                continue
            ts = _extract_timestamp(obj)
            result = self._analyze(content, str(path))
            yield ForensicEntry(
                index=i,
                content=content,
                source_file=str(path),
                source_type=EntrySource.JSON,
                content_hash=_sha256(content),
                analysis=result,
                poison_severity=_derive_severity(result),
                inferred_timestamp=ts,
                raw_metadata={**obj, "_raw_json": json.dumps(obj)} if isinstance(obj, dict) else {"_raw_json": json.dumps({"content": content})},
                cleaned_content=None,
            )

    def _read_sqlite(self, path: Path) -> Iterator[ForensicEntry]:
        try:
            conn = sqlite3.connect(str(path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
        except sqlite3.Error:
            return

        # Find tables with text columns
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        index = 0
        for table in tables:
            try:
                # Get column names safely
                cursor.execute(f"PRAGMA table_info(\"{table}\")")  # noqa: S608
                cols = [row[1] for row in cursor.fetchall()]
                text_cols = [c for c in cols if any(kw in c.lower() for kw in _CONTENT_KEYS)]
                if not text_cols:
                    text_cols = cols[:3]  # fallback: first 3 columns

                cursor.execute(f"SELECT * FROM \"{table}\" LIMIT 10000")  # noqa: S608
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    content = _extract_content(row_dict)
                    if not content.strip():
                        continue
                    ts = _extract_timestamp(row_dict)
                    result = self._analyze(content, str(path))
                    yield ForensicEntry(
                        index=index,
                        content=content,
                        source_file=f"{path}::{table}",
                        source_type=EntrySource.SQLITE,
                        content_hash=_sha256(content),
                        analysis=result,
                        poison_severity=_derive_severity(result),
                        inferred_timestamp=ts,
                        raw_metadata=row_dict,
                        cleaned_content=None,
                    )
                    index += 1
            except sqlite3.Error:
                continue

        conn.close()

    def _read_markdown(self, path: Path) -> Iterator[ForensicEntry]:
        raw = path.read_text(encoding="utf-8", errors="replace")
        # Split on headings and code blocks as logical units
        sections = re.split(r"(?m)^#{1,3} |\n---\n|\n\*\*\*\n", raw)
        for i, section in enumerate(sections):
            content = section.strip()
            if not content:
                continue
            ts = _extract_timestamp(content)
            result = self._analyze(content, str(path))
            yield ForensicEntry(
                index=i,
                content=content,
                source_file=str(path),
                source_type=EntrySource.MARKDOWN,
                content_hash=_sha256(content),
                analysis=result,
                poison_severity=_derive_severity(result),
                inferred_timestamp=ts,
                raw_metadata={},
                cleaned_content=None,
            )

    def _read_text(self, path: Path) -> Iterator[ForensicEntry]:
        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for i, line in enumerate(lines):
            # Try JSON objects on single lines
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    content = _extract_content(obj)
                    ts = _extract_timestamp(obj)
                    result = self._analyze(content, str(path))
                    yield ForensicEntry(
                        index=i,
                        content=content,
                        source_file=str(path),
                        source_type=EntrySource.JSON,
                        content_hash=_sha256(content),
                        analysis=result,
                        poison_severity=_derive_severity(result),
                        inferred_timestamp=ts,
                        raw_metadata=obj,
                        cleaned_content=None,
                    )
                    continue
                except json.JSONDecodeError:
                    pass
            result = self._analyze(line, str(path))
            yield ForensicEntry(
                index=i,
                content=line,
                source_file=str(path),
                source_type=EntrySource.TEXT,
                content_hash=_sha256(line),
                analysis=result,
                poison_severity=_derive_severity(result),
                inferred_timestamp=_extract_timestamp(line),
                raw_metadata={},
                cleaned_content=None,
            )

    # ---- Analysis ----------------------------------------------------------

    def _analyze(self, content: str, source: str) -> AnalysisResult:
        entry = MemoryEntry(content=content, source_type=source)
        return self._analyzer.analyze(entry)

    # ---- Report builder ----------------------------------------------------

    def _build_report(
        self,
        scan_id: str,
        started_at: str,
        target_path: str,
        entries: List[ForensicEntry],
        duration_ms: float,
    ) -> ForensicReport:
        report = ForensicReport(
            scan_id=scan_id,
            scan_started_at=started_at,
            scan_completed_at=datetime.now(tz=timezone.utc).isoformat(),
            scan_duration_ms=duration_ms,
            target_path=target_path,
            entries=entries,
        )

        threat_ids: set = set()
        categories: set = set()

        for entry in entries:
            report.total_entries += 1

            sev = entry.poison_severity
            if sev == PoisonSeverity.CLEAN:
                report.clean_entries += 1
            else:
                # Count as poisoned only if >= min_severity threshold
                sev_order = [PoisonSeverity.LOW, PoisonSeverity.MEDIUM, PoisonSeverity.HIGH, PoisonSeverity.CRITICAL]
                if sev_order.index(sev) >= sev_order.index(self._min_severity):
                    report.poisoned_entries += 1
                    report.poisoned_entries_list.append(entry)

                    if sev == PoisonSeverity.CRITICAL:
                        report.critical_count += 1
                    elif sev == PoisonSeverity.HIGH:
                        report.high_count += 1
                    elif sev == PoisonSeverity.MEDIUM:
                        report.medium_count += 1
                    elif sev == PoisonSeverity.LOW:
                        report.low_count += 1

                    # Timeline event
                    report.timeline.append(PoisonEvent(
                        timestamp=entry.inferred_timestamp,
                        entry_index=entry.index,
                        source_file=entry.source_file,
                        poison_severity=sev,
                        threat_names=entry.threat_names,
                        risk_score=entry.analysis.risk_score,
                        content_preview=entry.content[:150],
                    ))

                    # Threat metadata
                    for t in entry.analysis.threats:
                        threat_ids.add(t.threat.id)
                        categories.add(t.threat.category.value)

            if entry.is_cleaned:
                report.cleaned_entries += 1

        # Sort timeline by timestamp (unknowns at end)
        report.timeline.sort(
            key=lambda e: (e.timestamp is None, e.timestamp or "")
        )

        report.threat_ids_found = sorted(threat_ids)
        report.threat_categories = sorted(categories)
        report.recommendations = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report: ForensicReport) -> List[str]:
        recs = []
        if not report.is_compromised:
            recs.append("✅ No significant threats found. Continue monitoring with memgar watch.")
            return recs

        recs.append(
            f"🚨 CRITICAL: {report.poisoned_entries} poisoned entries found "
            f"({report.compromise_rate}% of memory store)."
        )

        if report.critical_count > 0:
            recs.append(
                f"⛔ {report.critical_count} CRITICAL entries detected. "
                "Treat your agent as fully compromised. Rotate all credentials immediately."
            )
        if report.high_count > 0:
            recs.append(
                f"🔴 {report.high_count} HIGH severity entries. "
                "Review agent actions taken in the last 30 days for unauthorized behavior."
            )
        if "financial" in report.threat_categories:
            recs.append(
                "💸 Financial threat patterns found. "
                "Audit all payment/transfer operations performed by this agent."
            )
        if "credential" in report.threat_categories:
            recs.append(
                "🔑 Credential theft patterns found. "
                "Rotate API keys, tokens, and passwords accessible to this agent."
            )
        if "exfiltration" in report.threat_categories:
            recs.append(
                "📤 Data exfiltration patterns found. "
                "Review outbound network activity and data access logs."
            )
        if "sleeper" in report.threat_categories:
            recs.append(
                "💤 Sleeper/delayed payload patterns found. "
                "Even after cleaning, monitor for delayed activation over the next 7 days."
            )
        recs.append(
            "🧹 Run `memgar forensics scan <path> --clean` to generate sanitized replacements."
        )
        recs.append(
            "🛡️ Add Memgar to your agent pipeline to prevent future poisoning: "
            "`from memgar.frameworks import MemgarSecurityRunnable`"
        )
        return recs

    # ---- HTML Report -------------------------------------------------------

    def _render_html(self, report: ForensicReport) -> str:
        sev_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#84cc16",
            "clean": "#22c55e",
        }

        # Build timeline rows
        timeline_rows = ""
        for event in report.timeline:
            color = sev_colors.get(event.poison_severity.value, "#888")
            preview = event.content_preview.replace("<", "&lt;").replace(">", "&gt;")
            names = ", ".join(event.threat_names[:3])
            timeline_rows += f"""
            <tr>
                <td class="ts">{event.timestamp or "unknown"}</td>
                <td><span class="badge" style="background:{color}">{event.poison_severity.value.upper()}</span></td>
                <td>{event.source_file.split("/")[-1]}</td>
                <td class="threat-names">{names}</td>
                <td class="score">{event.risk_score}</td>
                <td class="preview">{preview[:100]}{"..." if len(preview) > 100 else ""}</td>
            </tr>"""

        # Poisoned entries detail
        detail_cards = ""
        for entry in report.poisoned_entries_list[:50]:  # cap at 50
            color = sev_colors.get(entry.poison_severity.value, "#888")
            content_escaped = entry.content[:500].replace("<", "&lt;").replace(">", "&gt;")
            cleaned_section = ""
            if entry.is_cleaned and entry.cleaned_content:
                c = entry.cleaned_content[:300].replace("<", "&lt;").replace(">", "&gt;")
                cleaned_section = f"""
                <div class="cleaned-block">
                    <div class="cleaned-label">🧹 Cleaned Content</div>
                    <pre class="code">{c}</pre>
                </div>"""
            threat_badges = " ".join(
                f'<span class="threat-badge">{n}</span>' for n in entry.threat_names[:4]
            )
            detail_cards += f"""
            <div class="entry-card" style="border-left: 4px solid {color}">
                <div class="entry-header">
                    <span class="badge" style="background:{color}">{entry.poison_severity.value.upper()}</span>
                    <span class="entry-meta">Entry #{entry.index} · {entry.source_file.split("/")[-1]} · Score {entry.analysis.risk_score}/100</span>
                </div>
                <div class="threat-row">{threat_badges}</div>
                <pre class="code">{content_escaped}{"..." if len(entry.content) > 500 else ""}</pre>
                {cleaned_section}
            </div>"""

        recs_html = "".join(f"<li>{r}</li>" for r in report.recommendations)

        status_color = "#ef4444" if report.is_compromised else "#22c55e"
        status_label = "🚨 COMPROMISED" if report.is_compromised else "✅ CLEAN"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Memgar Forensic Report — {report.scan_id}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #263147;
    --border: #334155; --text: #e2e8f0; --dim: #94a3b8;
    --accent: #6366f1; --font: 'Segoe UI', system-ui, sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  .header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 2rem; }}
  .logo {{ font-size: 2.5rem; }}
  h1 {{ font-size: 1.8rem; font-weight: 700; }}
  .subtitle {{ color: var(--dim); font-size: 0.9rem; }}
  .status-banner {{
    background: var(--surface); border: 2px solid {status_color};
    border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem;
    display: flex; align-items: center; gap: 1rem;
  }}
  .status-label {{ font-size: 1.4rem; font-weight: 800; color: {status_color}; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; }}
  .stat-number {{ font-size: 2rem; font-weight: 800; }}
  .stat-label {{ color: var(--dim); font-size: 0.8rem; margin-top: 0.3rem; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .section h2 {{ font-size: 1.1rem; margin-bottom: 1rem; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.6rem 0.8rem; color: var(--dim); border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: var(--surface2); }}
  .ts {{ white-space: nowrap; color: var(--dim); font-size: 0.78rem; }}
  .score {{ font-weight: 700; color: #f97316; }}
  .preview {{ color: var(--dim); font-size: 0.8rem; max-width: 300px; word-break: break-all; }}
  .threat-names {{ font-size: 0.8rem; color: #a78bfa; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.72rem; font-weight: 700; color: #fff; }}
  .entry-card {{ background: var(--surface2); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
  .entry-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.6rem; }}
  .entry-meta {{ color: var(--dim); font-size: 0.82rem; }}
  .threat-row {{ margin-bottom: 0.6rem; }}
  .threat-badge {{ background: #312e81; color: #a5b4fc; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin-right: 0.3rem; }}
  .code {{ background: #0a101e; border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem; font-size: 0.8rem; font-family: monospace; white-space: pre-wrap; word-break: break-word; margin-top: 0.5rem; color: #94a3b8; }}
  .cleaned-block {{ margin-top: 0.6rem; }}
  .cleaned-label {{ color: #22c55e; font-size: 0.8rem; font-weight: 600; margin-bottom: 0.3rem; }}
  ul.recs {{ list-style: none; }}
  ul.recs li {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.85rem; }}
  .meta-item {{ color: var(--dim); }}
  .meta-val {{ color: var(--text); }}
</style>
</head>
<body>

<div class="header">
  <div class="logo">🔬</div>
  <div>
    <h1>Memgar Forensic Report</h1>
    <div class="subtitle">Memory Poisoning Incident Analysis · Scan ID: {report.scan_id}</div>
  </div>
</div>

<div class="status-banner">
  <div class="status-label">{status_label}</div>
  <div style="color:var(--dim); font-size:0.9rem">
    {report.poisoned_entries} poisoned entries found out of {report.total_entries} total
    ({report.compromise_rate}% compromise rate)
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-number">{report.total_entries}</div>
    <div class="stat-label">Total Entries</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#ef4444">{report.poisoned_entries}</div>
    <div class="stat-label">Poisoned</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#22c55e">{report.clean_entries}</div>
    <div class="stat-label">Clean</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#22c55e">{report.cleaned_entries}</div>
    <div class="stat-label">Cleaned</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#ef4444">{report.critical_count}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#f97316">{report.high_count}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#eab308">{report.medium_count}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{round(report.scan_duration_ms)}ms</div>
    <div class="stat-label">Scan Time</div>
  </div>
</div>

<div class="section">
  <h2>📋 Scan Metadata</h2>
  <div class="meta-grid">
    <div class="meta-item">Target Path</div><div class="meta-val">{report.target_path}</div>
    <div class="meta-item">Started At</div><div class="meta-val">{report.scan_started_at}</div>
    <div class="meta-item">Completed At</div><div class="meta-val">{report.scan_completed_at}</div>
    <div class="meta-item">Threat Categories</div><div class="meta-val">{", ".join(report.threat_categories) or "none"}</div>
    <div class="meta-item">Unique Threat IDs</div><div class="meta-val">{len(report.threat_ids_found)}</div>
  </div>
</div>

<div class="section">
  <h2>⏱️ Poisoning Timeline</h2>
  {"<p style='color:var(--dim)'>No poisoned entries found.</p>" if not report.timeline else f'''
  <table>
    <thead><tr>
      <th>Timestamp</th><th>Severity</th><th>File</th>
      <th>Threats</th><th>Score</th><th>Preview</th>
    </tr></thead>
    <tbody>{timeline_rows}</tbody>
  </table>'''}
</div>

<div class="section">
  <h2>🦠 Poisoned Entries Detail</h2>
  {"<p style='color:var(--dim)'>No poisoned entries found.</p>" if not report.poisoned_entries_list else detail_cards}
  {"<p style='color:var(--dim); font-size:0.85rem; margin-top:0.5rem'>Showing first 50 entries.</p>" if len(report.poisoned_entries_list) > 50 else ""}
</div>

<div class="section">
  <h2>🛠️ Recommendations</h2>
  <ul class="recs">{"".join(f"<li>{r}</li>" for r in report.recommendations)}</ul>
</div>

<div style="color:var(--dim); font-size:0.78rem; margin-top:2rem; text-align:center">
  Generated by Memgar v0.5.0 · memgar.io · {report.scan_completed_at}
</div>

</body>
</html>"""
