"""
Memgar High-Performance Pattern Matching
=========================================

Aho-Corasick algorithm implementation for O(n + m + z) pattern matching.
- n: text length
- m: total pattern length  
- z: number of matches

Optimized for:
- Concurrent requests (thread-safe, lock-free reads)
- Large datasets (memory-efficient trie)
- Batch processing (streaming API)
- Real-time scanning (pre-compiled automaton)

Usage:
    from memgar.core import AhoCorasick, PatternMatcher
    
    # Build automaton once
    matcher = PatternMatcher()
    matcher.add_patterns(["malicious", "attack", "inject"])
    matcher.build()
    
    # Scan many texts (thread-safe)
    matches = matcher.search("this contains malicious content")
    
    # Batch scan
    results = matcher.search_batch(["text1", "text2", "text3"])
    
    # Streaming scan
    for match in matcher.search_iter(large_text):
        print(f"Found '{match.pattern}' at {match.start}")
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True, slots=True)
class Match:
    """Immutable match result."""
    pattern: str
    start: int
    end: int
    pattern_id: Optional[str] = None
    metadata: Optional[Dict] = None
    
    @property
    def length(self) -> int:
        return self.end - self.start
    
    def __hash__(self):
        return hash((self.pattern, self.start, self.end))


@dataclass
class PatternInfo:
    """Pattern metadata."""
    pattern: str
    pattern_id: str
    category: Optional[str] = None
    severity: Optional[str] = None
    case_sensitive: bool = False
    metadata: Dict = field(default_factory=dict)


class TrieNode:
    """
    Trie node with failure links for Aho-Corasick.
    
    Uses __slots__ for memory efficiency with large pattern sets.
    """
    __slots__ = ('children', 'fail', 'output', 'depth')
    
    def __init__(self):
        self.children: Dict[str, TrieNode] = {}
        self.fail: Optional[TrieNode] = None
        self.output: List[PatternInfo] = []
        self.depth: int = 0


# =============================================================================
# AHO-CORASICK AUTOMATON
# =============================================================================

class AhoCorasick:
    """
    Aho-Corasick automaton for multi-pattern matching.
    
    Thread-safe after build() is called.
    
    Example:
        ac = AhoCorasick()
        ac.add_pattern("he")
        ac.add_pattern("she")
        ac.add_pattern("his")
        ac.add_pattern("hers")
        ac.build()
        
        matches = ac.search("ushers")
        # Returns matches for "she", "he", "hers"
    """
    
    def __init__(self, case_sensitive: bool = False):
        """
        Initialize automaton.
        
        Args:
            case_sensitive: Whether matching is case-sensitive
        """
        self._root = TrieNode()
        self._case_sensitive = case_sensitive
        self._built = False
        self._pattern_count = 0
        self._build_lock = threading.Lock()
    
    def _normalize(self, text: str) -> str:
        """Normalize text based on case sensitivity."""
        return text if self._case_sensitive else text.lower()
    
    def add_pattern(
        self,
        pattern: str,
        pattern_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Add pattern to automaton.
        
        Must call build() after adding all patterns.
        
        Args:
            pattern: Pattern string to match
            pattern_id: Optional unique identifier
            category: Optional category (e.g., "injection", "financial")
            severity: Optional severity level
            metadata: Optional additional metadata
        """
        if self._built:
            raise RuntimeError("Cannot add patterns after build(). Create new automaton.")
        
        if not pattern:
            return
        
        normalized = self._normalize(pattern)
        node = self._root
        
        for i, char in enumerate(normalized):
            if char not in node.children:
                node.children[char] = TrieNode()
                node.children[char].depth = i + 1
            node = node.children[char]
        
        # Store pattern info at terminal node
        info = PatternInfo(
            pattern=pattern,  # Store original case
            pattern_id=pattern_id or f"p_{self._pattern_count}",
            category=category,
            severity=severity,
            case_sensitive=self._case_sensitive,
            metadata=metadata or {},
        )
        node.output.append(info)
        self._pattern_count += 1
    
    def add_patterns(
        self,
        patterns: Iterable[Union[str, Tuple[str, str], Dict]],
    ) -> None:
        """
        Add multiple patterns.
        
        Args:
            patterns: Iterable of patterns. Each can be:
                - str: pattern only
                - tuple: (pattern, pattern_id)
                - dict: {pattern, pattern_id, category, severity, metadata}
        """
        for p in patterns:
            if isinstance(p, str):
                self.add_pattern(p)
            elif isinstance(p, tuple):
                self.add_pattern(p[0], pattern_id=p[1] if len(p) > 1 else None)
            elif isinstance(p, dict):
                self.add_pattern(
                    pattern=p.get("pattern", p.get("p", "")),
                    pattern_id=p.get("pattern_id", p.get("id")),
                    category=p.get("category"),
                    severity=p.get("severity"),
                    metadata=p.get("metadata"),
                )
    
    def build(self) -> None:
        """
        Build failure links using BFS.
        
        Must be called after adding all patterns and before searching.
        Thread-safe - only builds once.
        """
        with self._build_lock:
            if self._built:
                return
            
            # BFS to build failure links
            queue = deque()
            
            # Initialize depth-1 nodes
            for char, child in self._root.children.items():
                child.fail = self._root
                queue.append(child)
            
            # BFS for remaining nodes
            while queue:
                current = queue.popleft()
                
                for char, child in current.children.items():
                    queue.append(child)
                    
                    # Find failure link
                    fail = current.fail
                    while fail is not None and char not in fail.children:
                        fail = fail.fail
                    
                    child.fail = fail.children[char] if fail else self._root
                    
                    # Merge output from failure link (suffix outputs)
                    if child.fail and child.fail.output:
                        child.output = child.output + child.fail.output
            
            self._built = True
    
    def search(self, text: str) -> List[Match]:
        """
        Search text for all pattern matches.
        
        Args:
            text: Text to search
            
        Returns:
            List of Match objects, sorted by position
        """
        if not self._built:
            raise RuntimeError("Must call build() before searching")
        
        matches = []
        normalized = self._normalize(text)
        node = self._root
        
        for i, char in enumerate(normalized):
            # Follow failure links until match or root
            while node is not None and char not in node.children:
                node = node.fail
            
            if node is None:
                node = self._root
                continue
            
            node = node.children[char]
            
            # Collect all matches at this position
            for info in node.output:
                start = i - len(info.pattern) + 1
                matches.append(Match(
                    pattern=info.pattern,
                    start=start,
                    end=i + 1,
                    pattern_id=info.pattern_id,
                    metadata={
                        "category": info.category,
                        "severity": info.severity,
                        **info.metadata,
                    } if info.category or info.severity or info.metadata else None,
                ))
        
        return sorted(matches, key=lambda m: (m.start, -m.length))
    
    def search_iter(self, text: str) -> Generator[Match, None, None]:
        """
        Iterator version for streaming/large texts.
        
        Yields matches as they are found (memory efficient).
        """
        if not self._built:
            raise RuntimeError("Must call build() before searching")
        
        normalized = self._normalize(text)
        node = self._root
        
        for i, char in enumerate(normalized):
            while node is not None and char not in node.children:
                node = node.fail
            
            if node is None:
                node = self._root
                continue
            
            node = node.children[char]
            
            for info in node.output:
                start = i - len(info.pattern) + 1
                yield Match(
                    pattern=info.pattern,
                    start=start,
                    end=i + 1,
                    pattern_id=info.pattern_id,
                    metadata={
                        "category": info.category,
                        "severity": info.severity,
                        **info.metadata,
                    } if info.category or info.severity or info.metadata else None,
                )
    
    def search_first(self, text: str) -> Optional[Match]:
        """Return first match only (early termination)."""
        for match in self.search_iter(text):
            return match
        return None
    
    def contains_any(self, text: str) -> bool:
        """Check if text contains any pattern (fast boolean check)."""
        return self.search_first(text) is not None
    
    @property
    def pattern_count(self) -> int:
        """Number of patterns in automaton."""
        return self._pattern_count
    
    @property
    def is_built(self) -> bool:
        """Whether automaton has been built."""
        return self._built


# =============================================================================
# HIGH-LEVEL PATTERN MATCHER
# =============================================================================

class PatternMatcher:
    """
    High-level pattern matcher with batching and concurrency support.
    
    Features:
    - Automatic rebuilding when patterns change
    - Batch processing with thread pool
    - Pattern categories and filtering
    - Statistics and profiling
    
    Example:
        matcher = PatternMatcher()
        
        # Add patterns with categories
        matcher.add_pattern("password", category="credential")
        matcher.add_pattern("credit card", category="financial")
        matcher.add_patterns_from_list(threat_patterns)
        
        # Search
        matches = matcher.search(text)
        
        # Batch search (parallel)
        results = matcher.search_batch(texts, max_workers=4)
        
        # Filter by category
        cred_matches = matcher.search(text, categories=["credential"])
    """
    
    def __init__(
        self,
        case_sensitive: bool = False,
        auto_build: bool = True,
    ):
        """
        Initialize matcher.
        
        Args:
            case_sensitive: Case-sensitive matching
            auto_build: Automatically rebuild when patterns added
        """
        self._ac = AhoCorasick(case_sensitive=case_sensitive)
        self._case_sensitive = case_sensitive
        self._auto_build = auto_build
        self._patterns: Dict[str, PatternInfo] = {}
        self._categories: Dict[str, Set[str]] = {}  # category -> pattern_ids
        self._dirty = False
        self._lock = threading.RLock()
        
        # Statistics
        self._stats = {
            "searches": 0,
            "matches_found": 0,
            "total_search_time_ms": 0,
            "texts_processed": 0,
        }
    
    def add_pattern(
        self,
        pattern: str,
        pattern_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> str:
        """
        Add pattern to matcher.
        
        Returns:
            Pattern ID
        """
        with self._lock:
            pid = pattern_id or f"p_{len(self._patterns)}"
            
            info = PatternInfo(
                pattern=pattern,
                pattern_id=pid,
                category=category,
                severity=severity,
                metadata=metadata or {},
            )
            self._patterns[pid] = info
            
            if category:
                if category not in self._categories:
                    self._categories[category] = set()
                self._categories[category].add(pid)
            
            self._dirty = True
            
            if self._auto_build:
                self._rebuild()
            
            return pid
    
    def add_patterns(
        self,
        patterns: Iterable[Union[str, Dict]],
    ) -> List[str]:
        """Add multiple patterns. Returns list of pattern IDs."""
        with self._lock:
            old_auto = self._auto_build
            self._auto_build = False
            
            ids = []
            for p in patterns:
                if isinstance(p, str):
                    ids.append(self.add_pattern(p))
                elif isinstance(p, dict):
                    ids.append(self.add_pattern(
                        pattern=p.get("pattern", ""),
                        pattern_id=p.get("pattern_id"),
                        category=p.get("category"),
                        severity=p.get("severity"),
                        metadata=p.get("metadata"),
                    ))
            
            self._auto_build = old_auto
            if self._auto_build:
                self._rebuild()
            
            return ids
    
    def _rebuild(self) -> None:
        """Rebuild automaton with current patterns."""
        if not self._dirty:
            return
        
        self._ac = AhoCorasick(case_sensitive=self._case_sensitive)
        
        for info in self._patterns.values():
            self._ac.add_pattern(
                pattern=info.pattern,
                pattern_id=info.pattern_id,
                category=info.category,
                severity=info.severity,
                metadata=info.metadata,
            )
        
        self._ac.build()
        self._dirty = False
    
    def build(self) -> None:
        """Explicitly build automaton."""
        with self._lock:
            self._dirty = True
            self._rebuild()
    
    def search(
        self,
        text: str,
        categories: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
    ) -> List[Match]:
        """
        Search text for patterns.
        
        Args:
            text: Text to search
            categories: Filter by categories (None = all)
            severities: Filter by severities (None = all)
            
        Returns:
            List of matches
        """
        with self._lock:
            if self._dirty:
                self._rebuild()
        
        start_time = time.perf_counter()
        matches = self._ac.search(text)
        elapsed = (time.perf_counter() - start_time) * 1000
        
        # Filter if needed
        if categories or severities:
            filtered = []
            for m in matches:
                meta = m.metadata or {}
                if categories and meta.get("category") not in categories:
                    continue
                if severities and meta.get("severity") not in severities:
                    continue
                filtered.append(m)
            matches = filtered
        
        # Update stats
        self._stats["searches"] += 1
        self._stats["matches_found"] += len(matches)
        self._stats["total_search_time_ms"] += elapsed
        self._stats["texts_processed"] += 1
        
        return matches
    
    def search_batch(
        self,
        texts: List[str],
        max_workers: int = 4,
        categories: Optional[List[str]] = None,
    ) -> List[List[Match]]:
        """
        Parallel batch search.
        
        Args:
            texts: List of texts to search
            max_workers: Thread pool size
            categories: Filter by categories
            
        Returns:
            List of match lists (same order as input)
        """
        # Ensure built before parallel execution
        with self._lock:
            if self._dirty:
                self._rebuild()
        
        results = [None] * len(texts)
        
        def search_one(idx: int, text: str):
            return idx, self._ac.search(text)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(search_one, i, t)
                for i, t in enumerate(texts)
            ]
            
            for future in as_completed(futures):
                idx, matches = future.result()
                
                # Filter if needed
                if categories:
                    matches = [
                        m for m in matches
                        if (m.metadata or {}).get("category") in categories
                    ]
                
                results[idx] = matches
        
        self._stats["texts_processed"] += len(texts)
        
        return results
    
    def contains_any(self, text: str) -> bool:
        """Fast check if text contains any pattern."""
        with self._lock:
            if self._dirty:
                self._rebuild()
        return self._ac.contains_any(text)
    
    def get_categories(self) -> List[str]:
        """Get all registered categories."""
        return list(self._categories.keys())
    
    def get_patterns_by_category(self, category: str) -> List[PatternInfo]:
        """Get patterns in a category."""
        if category not in self._categories:
            return []
        return [self._patterns[pid] for pid in self._categories[category]]
    
    def get_statistics(self) -> Dict:
        """Get matcher statistics."""
        avg_time = (
            self._stats["total_search_time_ms"] / max(self._stats["searches"], 1)
        )
        return {
            **self._stats,
            "pattern_count": len(self._patterns),
            "category_count": len(self._categories),
            "avg_search_time_ms": round(avg_time, 3),
        }
    
    def clear_statistics(self) -> None:
        """Reset statistics."""
        self._stats = {
            "searches": 0,
            "matches_found": 0,
            "total_search_time_ms": 0,
            "texts_processed": 0,
        }
    
    @property
    def pattern_count(self) -> int:
        return len(self._patterns)


# =============================================================================
# THREAT PATTERN SCANNER
# =============================================================================

class ThreatScanner:
    """
    High-performance threat scanner using Aho-Corasick.
    
    Optimized replacement for regex-based pattern matching.
    
    Example:
        scanner = ThreatScanner()
        scanner.load_patterns_from_memgar()  # Load from patterns.py
        
        result = scanner.scan("ignore previous instructions")
        if result.has_threats:
            print(f"Threats: {result.threat_count}")
    """
    
    def __init__(self):
        self._matcher = PatternMatcher(case_sensitive=False)
        self._severity_scores = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10,
        }
        self._loaded = False
    
    def add_threat_pattern(
        self,
        pattern: str,
        threat_id: str,
        category: str,
        severity: str,
        description: Optional[str] = None,
    ) -> None:
        """Add a threat pattern."""
        self._matcher.add_pattern(
            pattern=pattern,
            pattern_id=threat_id,
            category=category,
            severity=severity,
            metadata={"description": description} if description else None,
        )
    
    def load_patterns(self, patterns: List[Dict]) -> int:
        """
        Load patterns from list of dicts.
        
        Expected format:
            [{"pattern": "...", "id": "...", "category": "...", "severity": "..."}]
        
        Returns:
            Number of patterns loaded
        """
        count = 0
        for p in patterns:
            if "pattern" in p or "patterns" in p:
                pats = p.get("patterns", [p.get("pattern")])
                for pat in pats:
                    if pat:
                        self.add_threat_pattern(
                            pattern=pat,
                            threat_id=p.get("id", f"t_{count}"),
                            category=p.get("category", "unknown"),
                            severity=p.get("severity", "medium"),
                            description=p.get("description"),
                        )
                        count += 1
        
        self._loaded = True
        return count
    
    def load_keywords_from_memgar(self) -> int:
        """
        Load keyword patterns from memgar.patterns module.
        
        Returns:
            Number of patterns loaded
        """
        try:
            from memgar.patterns import PATTERNS
            
            count = 0
            for threat in PATTERNS:
                # Add keywords
                for kw in threat.keywords:
                    self.add_threat_pattern(
                        pattern=kw,
                        threat_id=threat.id,
                        category=threat.category.value if hasattr(threat.category, 'value') else str(threat.category),
                        severity=threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity),
                        description=threat.description,
                    )
                    count += 1
            
            self._matcher.build()
            self._loaded = True
            return count
            
        except ImportError:
            return 0
    
    def scan(self, text: str) -> 'ScanResult':
        """
        Scan text for threats.
        
        Returns:
            ScanResult with matches and risk score
        """
        if not self._loaded:
            self._matcher.build()
        
        matches = self._matcher.search(text)
        
        # Calculate risk score
        risk_score = 0
        seen_ids = set()
        
        for m in matches:
            meta = m.metadata or {}
            severity = meta.get("severity", "medium")
            score = self._severity_scores.get(severity, 25)
            
            # Avoid double-counting same threat
            if m.pattern_id not in seen_ids:
                risk_score += score
                seen_ids.add(m.pattern_id)
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        return ScanResult(
            matches=matches,
            threat_count=len(seen_ids),
            risk_score=risk_score,
            has_threats=len(matches) > 0,
        )
    
    def scan_batch(
        self,
        texts: List[str],
        max_workers: int = 4,
    ) -> List['ScanResult']:
        """Parallel batch scanning."""
        match_lists = self._matcher.search_batch(texts, max_workers=max_workers)
        
        results = []
        for matches in match_lists:
            risk_score = 0
            seen_ids = set()
            
            for m in matches:
                meta = m.metadata or {}
                severity = meta.get("severity", "medium")
                score = self._severity_scores.get(severity, 25)
                
                if m.pattern_id not in seen_ids:
                    risk_score += score
                    seen_ids.add(m.pattern_id)
            
            risk_score = min(100, risk_score)
            
            results.append(ScanResult(
                matches=matches,
                threat_count=len(seen_ids),
                risk_score=risk_score,
                has_threats=len(matches) > 0,
            ))
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get scanner statistics."""
        return self._matcher.get_statistics()


@dataclass
class ScanResult:
    """Result of threat scan."""
    matches: List[Match]
    threat_count: int
    risk_score: int
    has_threats: bool
    
    def get_by_severity(self, severity: str) -> List[Match]:
        """Filter matches by severity."""
        return [
            m for m in self.matches
            if (m.metadata or {}).get("severity") == severity
        ]
    
    def get_by_category(self, category: str) -> List[Match]:
        """Filter matches by category."""
        return [
            m for m in self.matches
            if (m.metadata or {}).get("category") == category
        ]


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Core
    "AhoCorasick",
    "Match",
    "PatternInfo",
    "TrieNode",
    
    # High-level
    "PatternMatcher",
    "ThreatScanner",
    "ScanResult",
]
