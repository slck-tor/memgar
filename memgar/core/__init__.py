"""
Memgar Core - High-Performance Algorithms
==========================================

Optimized algorithms for concurrent requests and large datasets.

Modules:
- aho_corasick: O(n+m+z) multi-pattern matching
"""

from .aho_corasick import (
    AhoCorasick,
    Match,
    PatternInfo,
    PatternMatcher,
    ThreatScanner,
    ScanResult,
)

__all__ = [
    "AhoCorasick",
    "Match", 
    "PatternInfo",
    "PatternMatcher",
    "ThreatScanner",
    "ScanResult",
]
