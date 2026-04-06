"""
Memgar Denial of Wallet (DoW) Detection Engine
================================================

Detects and prevents Denial of Wallet attacks — adversarial prompts
engineered to cause unbounded LLM API/compute costs by exploiting
agent autonomy, infinite loops, unbounded tool chains, and token flooding.

Threat model (OWASP ASI 2026 / DoW category):

    1. Loop injection       — "repeat this forever", "keep doing X until..."
    2. Token flooding       — Massive payloads to maximize context window usage
    3. Tool chain abuse     — Unlimited recursive/chained tool invocations
    4. Cost bypass          — "ignore budget limits", "disable rate limiting"
    5. Velocity spike       — Rapidly escalating request rates per session
    6. Recursive expansion  — Self-referential prompts that expand exponentially
    7. Parallel fan-out     — "spawn 100 agents", "do this in parallel for all..."

Architecture:

    DoWDetector          — Stateless pattern-based attack detection
    DoWRateLimiter       — Per-session token/request/cost sliding-window limiter
    DoWSessionMonitor    — Per-session budget tracking + velocity spike detection
    DoWGuard             — Combined guard (Detector + RateLimiter + Monitor)

CLI usage::

    memgar dow check "Repeat this analysis for all 50,000 records"
    memgar dow scan ./agent_logs/
    memgar dow budget --session my-agent
    memgar dow status
"""

from __future__ import annotations

import json
import re
import time
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_COST_PER_1K = 0.005   # USD per 1k tokens (GPT-4o baseline)
_CHARS_PER_TOKEN = 4.0


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DoWRisk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class DoWTrigger(str, Enum):
    LOOP_INJECTION      = "loop_injection"
    TOKEN_FLOODING      = "token_flooding"
    TOOL_CHAIN_ABUSE    = "tool_chain_abuse"
    COST_BYPASS         = "cost_bypass"
    RECURSIVE_EXPANSION = "recursive_expansion"
    PARALLEL_FANOUT     = "parallel_fanout"
    UNBOUNDED_ITERATION = "unbounded_iteration"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


# ---------------------------------------------------------------------------
# Detection Patterns
# ---------------------------------------------------------------------------

@dataclass
class _Pattern:
    trigger: DoWTrigger
    regex: re.Pattern
    score: int
    description: str


def _p(trigger: DoWTrigger, pattern: str, score: int, description: str) -> _Pattern:
    return _Pattern(trigger, re.compile(pattern, re.IGNORECASE | re.DOTALL), score, description)


DOW_PATTERNS: List[_Pattern] = [
    # Loop injection
    _p(DoWTrigger.LOOP_INJECTION,
       r"\b(?:repeat|loop|keep|continue|run|do)\s+(?:this|it|forever|infinitely|endlessly|always|continuously|non.?stop)\b",
       70, "Infinite loop instruction"),
    _p(DoWTrigger.LOOP_INJECTION,
       r"\buntil\s+(?:i\s+(?:say\s+)?stop|told\s+to\s+stop|cancelled|terminated|killed)\b",
       65, "Open-ended loop condition"),
    _p(DoWTrigger.LOOP_INJECTION,
       r"\b(?:infinite|endless|perpetual|continuous|nonstop)\s+(?:loop|cycle|repetition|iteration)\b",
       80, "Explicit infinite loop keyword"),
    _p(DoWTrigger.LOOP_INJECTION,
       r"\brepeat\s+(?:this\s+)?(?:process|step|task|analysis)\s+(?:for\s+each|on\s+every|across\s+all)\b",
       55, "Per-item unbounded repetition"),
    _p(DoWTrigger.LOOP_INJECTION,
       r"\bkeep\s+(?:going|running|trying|retrying|calling|asking)\s+until\b",
       60, "Loop until condition"),

    # Unbounded iteration
    _p(DoWTrigger.UNBOUNDED_ITERATION,
       r"\b(?:all|every|each)\s+(?:\d{3,}|thousand|million|billion)\s+(?:record|item|entry|row|user|document|file)\b",
       75, "Massive unbounded dataset iteration"),
    _p(DoWTrigger.UNBOUNDED_ITERATION,
       r"\bprocess\s+(?:all|every|the\s+entire)\s+(?:database|dataset|table|collection|corpus)\b",
       65, "Process entire collection"),
    _p(DoWTrigger.UNBOUNDED_ITERATION,
       r"\bfor\s+(?:all|every|each)\s+(?:record|entry|item|row|user)\s+in\b",
       50, "Unbounded for-each pattern"),
    _p(DoWTrigger.UNBOUNDED_ITERATION,
       r"\b(?:scan|analyze|process|summarize|translate)\s+(?:the\s+)?(?:entire|whole|all|complete)\s+\w+\b",
       45, "Full collection processing"),

    # Token flooding
    _p(DoWTrigger.TOKEN_FLOODING,
       r"\brepeat\s+(?:the\s+(?:following|above|this|that)\s+)?(?:phrase|word|sentence|text|content|message)\s+\d+\s+times\b",
       85, "Explicit token repetition attack"),
    _p(DoWTrigger.TOKEN_FLOODING,
       r"\bsay\s+['\"]?.{1,50}['\"]?\s+(?:\d{2,}|\w+\s+thousand|\w+\s+hundred)\s+times\b",
       90, "Say X N times attack"),
    _p(DoWTrigger.TOKEN_FLOODING,
       r"\bwrite\s+(?:out|down)?\s*\d{3,}\s+(?:word|sentence|paragraph|line|character)\b",
       70, "Massive output request"),
    _p(DoWTrigger.TOKEN_FLOODING,
       r"\b(?:fill|pad|expand)\s+(?:the\s+)?(?:context|prompt|window|output)\b",
       75, "Context window flooding"),

    # Tool chain abuse
    _p(DoWTrigger.TOOL_CHAIN_ABUSE,
       r"\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?\w+\s+tool\s+(?:repeatedly|multiple\s+times|in\s+a\s+loop|for\s+each)\b",
       70, "Repeated tool invocation"),
    _p(DoWTrigger.TOOL_CHAIN_ABUSE,
       r"\b(?:search|fetch|query|retrieve)\s+(?:all|every|each)\s+(?:result|page|item)\s+(?:recursively|in\s+depth|exhaustively)\b",
       65, "Exhaustive recursive search"),
    _p(DoWTrigger.TOOL_CHAIN_ABUSE,
       r"\bfollow\s+(?:every|all)\s+(?:link|url|reference|citation)\s+(?:recursively|on\s+each\s+page)\b",
       80, "Recursive link following"),
    _p(DoWTrigger.TOOL_CHAIN_ABUSE,
       r"\b(?:crawl|spider|scrape)\s+(?:the\s+)?(?:entire|whole|all|every)\s+\w+\b",
       75, "Unbounded web crawl"),

    # Cost bypass
    _p(DoWTrigger.COST_BYPASS,
       r"\b(?:ignore|bypass|disable|override|skip|remove)\s+(?:the\s+)?(?:budget|cost|limit|quota|cap|rate.?limit|throttl\w+)\b",
       95, "Explicit budget bypass instruction"),
    _p(DoWTrigger.COST_BYPASS,
       r"\b(?:no\s+budget|without\s+limit|unlimited\s+(?:calls?|tokens?|requests?|usage))\b",
       90, "Unlimited resource request"),
    _p(DoWTrigger.COST_BYPASS,
       r"\b(?:pretend|act\s+as\s+if|imagine)\s+(?:there\s+is\s+no|you\s+have\s+(?:no|unlimited))\s+(?:limit|budget|quota|cost)\b",
       85, "Simulated limit bypass"),
    _p(DoWTrigger.COST_BYPASS,
       r"\b(?:don.t|do\s+not|never)\s+(?:stop|halt|pause)\s+(?:for|due\s+to|because\s+of)\s+(?:cost|budget|limit|quota)\b",
       80, "Instruction to ignore cost limits"),

    # Recursive expansion
    _p(DoWTrigger.RECURSIVE_EXPANSION,
       r"\b(?:for\s+each|with\s+every)\s+(?:result|item|output|response),?\s+(?:also\s+)?(?:run|repeat|do|call|perform)\b",
       70, "Recursive result expansion"),
    _p(DoWTrigger.RECURSIVE_EXPANSION,
       r"\b(?:recursively|in\s+depth|depth.?first|breadth.?first)\s+(?:analyze|process|expand|explore|enumerate)\b",
       65, "Recursive depth instruction"),
    _p(DoWTrigger.RECURSIVE_EXPANSION,
       r"\bfor\s+(?:each|every)\s+\w+\s+found,?\s+(?:also\s+)?(?:find|get|fetch|retrieve|analyze)\s+(?:all|its|their)\b",
       75, "Per-result fan-out expansion"),

    # Parallel fan-out
    _p(DoWTrigger.PARALLEL_FANOUT,
       r"\b(?:spawn|create|launch|start|run)\s+(?:\d{2,}|many|multiple|several|hundreds?\s+of|thousands?\s+of)\s+(?:agent|task|thread|worker|process|job|instance)\b",
       85, "Mass agent/worker spawning"),
    _p(DoWTrigger.PARALLEL_FANOUT,
       r"\b(?:in\s+parallel|simultaneously|concurrently|all\s+at\s+once)\s+(?:for\s+)?(?:all|every|each)\s+\w+\b",
       70, "Unbounded parallel execution"),
    _p(DoWTrigger.PARALLEL_FANOUT,
       r"\bdistribute\s+(?:the\s+)?(?:task|work|job|analysis)\s+across\s+(?:all|many|multiple)\s+(?:agent|worker|node|instance)\b",
       65, "Mass task distribution"),

    # Resource exhaustion
    _p(DoWTrigger.RESOURCE_EXHAUSTION,
       r"\b(?:exhaust|maximize|use\s+(?:up\s+)?(?:all|maximum)|consume\s+(?:all|as\s+much))\s+(?:token|context|memory|resource|bandwidth|credit)\b",
       90, "Explicit resource exhaustion intent"),
    _p(DoWTrigger.RESOURCE_EXHAUSTION,
       r"\b(?:fill|use)\s+(?:the\s+)?(?:entire|whole|maximum|all\s+available)\s+(?:context|token|window)\b",
       80, "Context window saturation"),
    _p(DoWTrigger.RESOURCE_EXHAUSTION,
       r"\b(?:stress\s+test|load\s+test|benchmark)\s+(?:the\s+)?(?:agent|llm|model|api|system)\b",
       55, "Potential stress/load test"),
]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class DoWMatch:
    trigger: DoWTrigger
    description: str
    matched_text: str
    score: int
    position: Tuple[int, int] = (0, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trigger": self.trigger.value,
            "description": self.description,
            "matched_text": self.matched_text[:150],
            "score": self.score,
        }


@dataclass
class DoWAnalysisResult:
    risk: DoWRisk
    score: int
    is_dow_attempt: bool
    matches: List[DoWMatch] = field(default_factory=list)
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0
    analysis_time_ms: float = 0.0
    explanation: str = ""

    @property
    def trigger_types(self) -> List[str]:
        return list({m.trigger.value for m in self.matches})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk.value,
            "score": self.score,
            "is_dow_attempt": self.is_dow_attempt,
            "trigger_types": self.trigger_types,
            "match_count": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
            "estimated_tokens": self.estimated_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "explanation": self.explanation,
        }


@dataclass
class RateLimitStatus:
    session_id: str
    window_seconds: float
    requests_in_window: int
    tokens_in_window: int
    cost_in_window_usd: float
    max_requests: int
    max_tokens: int
    max_cost_usd: float
    is_throttled: bool
    throttle_reasons: List[str] = field(default_factory=list)

    @property
    def utilization(self) -> Dict[str, float]:
        return {
            "requests_pct": round(self.requests_in_window / self.max_requests * 100, 1) if self.max_requests else 0.0,
            "tokens_pct": round(self.tokens_in_window / self.max_tokens * 100, 1) if self.max_tokens else 0.0,
            "cost_pct": round(self.cost_in_window_usd / self.max_cost_usd * 100, 1) if self.max_cost_usd else 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "window_seconds": self.window_seconds,
            "requests_in_window": self.requests_in_window,
            "tokens_in_window": self.tokens_in_window,
            "cost_in_window_usd": round(self.cost_in_window_usd, 6),
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
            "is_throttled": self.is_throttled,
            "throttle_reasons": self.throttle_reasons,
            "utilization": self.utilization,
        }


@dataclass
class SessionBudgetStats:
    session_id: str
    started_at: str
    total_requests: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    dow_attempts_detected: int = 0
    requests_throttled: int = 0
    peak_rpm: float = 0.0
    peak_tpm: float = 0.0
    velocity_spikes: int = 0
    budget_usd: float = 0.0
    budget_remaining_usd: float = 0.0
    budget_exhausted: bool = False

    @property
    def avg_tokens_per_request(self) -> float:
        return 0.0 if not self.total_requests else round(self.total_tokens / self.total_requests, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "avg_tokens_per_request": self.avg_tokens_per_request,
            "dow_attempts_detected": self.dow_attempts_detected,
            "requests_throttled": self.requests_throttled,
            "peak_rpm": round(self.peak_rpm, 2),
            "peak_tpm": round(self.peak_tpm, 2),
            "velocity_spikes": self.velocity_spikes,
            "budget_usd": self.budget_usd,
            "budget_remaining_usd": round(self.budget_remaining_usd, 6),
            "budget_exhausted": self.budget_exhausted,
        }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DoWAttackDetected(Exception):
    def __init__(self, msg: str, result: Optional[DoWAnalysisResult] = None) -> None:
        super().__init__(msg)
        self.result = result


class DoWThrottleError(Exception):
    def __init__(self, msg: str, status: Optional[RateLimitStatus] = None) -> None:
        super().__init__(msg)
        self.status = status


class DoWBudgetExhaustedError(Exception):
    def __init__(self, msg: str, stats: Optional[SessionBudgetStats] = None) -> None:
        super().__init__(msg)
        self.stats = stats


# ---------------------------------------------------------------------------
# 1. DoWDetector
# ---------------------------------------------------------------------------

class DoWDetector:
    """
    Stateless Denial of Wallet attack detector.

    Analyzes content for DoW patterns across 7 attack categories (35+ patterns).

    Usage::

        detector = DoWDetector()
        result = detector.analyze("Repeat this for all 50,000 records forever")
        if result.is_dow_attempt:
            raise DoWAttackDetected(f"DoW blocked: {result.risk.value}")
    """

    def __init__(
        self,
        cost_per_1k_tokens: float = _DEFAULT_COST_PER_1K,
        block_threshold: int = 60,
    ) -> None:
        self._cost_per_1k = cost_per_1k_tokens
        self._threshold = block_threshold

    def analyze(self, content: str) -> DoWAnalysisResult:
        t0 = time.perf_counter()
        matches: List[DoWMatch] = []
        for pat in DOW_PATTERNS:
            for m in pat.regex.finditer(content):
                matches.append(DoWMatch(
                    trigger=pat.trigger,
                    description=pat.description,
                    matched_text=m.group(0),
                    score=pat.score,
                    position=(m.start(), m.end()),
                ))
        score = self._aggregate(matches)
        risk = self._risk(score)
        est_tokens = max(1, int(len(content) / _CHARS_PER_TOKEN))
        est_cost = (est_tokens / 1000) * self._cost_per_1k
        elapsed = (time.perf_counter() - t0) * 1000
        return DoWAnalysisResult(
            risk=risk,
            score=score,
            is_dow_attempt=score >= self._threshold,
            matches=matches,
            estimated_tokens=est_tokens,
            estimated_cost_usd=est_cost,
            analysis_time_ms=elapsed,
            explanation=self._explain(score, matches),
        )

    def is_safe(self, content: str) -> bool:
        return not self.analyze(content).is_dow_attempt

    @staticmethod
    def _aggregate(matches: List[DoWMatch]) -> int:
        if not matches:
            return 0
        base = max(m.score for m in matches)
        seen = {matches[0].trigger}
        bonus = 0
        for m in matches[1:]:
            if m.trigger not in seen:
                bonus += int(m.score * 0.15)
                seen.add(m.trigger)
        return min(100, base + bonus)

    @staticmethod
    def _risk(score: int) -> DoWRisk:
        if score >= 80: return DoWRisk.CRITICAL
        if score >= 65: return DoWRisk.HIGH
        if score >= 45: return DoWRisk.MEDIUM
        if score >= 20: return DoWRisk.LOW
        return DoWRisk.NONE

    @staticmethod
    def _explain(score: int, matches: List[DoWMatch]) -> str:
        if not matches:
            return "No DoW patterns detected."
        triggers = list({m.trigger.value for m in matches})
        primary = max(matches, key=lambda m: m.score)
        return f"Score {score}/100 — Primary: {primary.description}. Triggers: {', '.join(triggers)}."


# ---------------------------------------------------------------------------
# 2. DoWRateLimiter
# ---------------------------------------------------------------------------

@dataclass
class _Request:
    timestamp: float
    tokens: int
    cost_usd: float


class DoWRateLimiter:
    """
    Sliding-window rate limiter enforcing per-session request/token/cost limits.

    Usage::

        limiter = DoWRateLimiter(max_requests_per_window=100, max_cost_per_window_usd=0.50)
        status = limiter.check_and_record("session_abc", content=prompt)
        if status.is_throttled:
            raise DoWThrottleError("Rate limit hit", status)
    """

    def __init__(
        self,
        max_requests_per_window: int = 200,
        max_tokens_per_window: int = 100_000,
        max_cost_per_window_usd: float = 1.0,
        window_seconds: float = 60.0,
        cost_per_1k_tokens: float = _DEFAULT_COST_PER_1K,
    ) -> None:
        self.max_requests = max_requests_per_window
        self.max_tokens = max_tokens_per_window
        self.max_cost = max_cost_per_window_usd
        self.window = window_seconds
        self._cost_per_1k = cost_per_1k_tokens
        self._sessions: Dict[str, Deque[_Request]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_record(
        self, session_id: str, content: str = "", tokens: Optional[int] = None
    ) -> RateLimitStatus:
        now = time.time()
        cutoff = now - self.window
        tok = tokens if tokens is not None else max(1, int(len(content) / _CHARS_PER_TOKEN))
        cost = (tok / 1000) * self._cost_per_1k

        with self._lock:
            q = self._sessions[session_id]
            while q and q[0].timestamp < cutoff:
                q.popleft()
            reqs = len(q)
            toks = sum(r.tokens for r in q)
            costs = sum(r.cost_usd for r in q)
            reasons: List[str] = []
            if reqs >= self.max_requests:
                reasons.append(f"requests ({reqs}/{self.max_requests} in {self.window:.0f}s)")
            if toks + tok > self.max_tokens:
                reasons.append(f"tokens ({toks + tok:,}/{self.max_tokens:,})")
            if costs + cost > self.max_cost:
                reasons.append(f"cost (${costs + cost:.4f}/${self.max_cost:.4f})")
            q.append(_Request(timestamp=now, tokens=tok, cost_usd=cost))

        return RateLimitStatus(
            session_id=session_id, window_seconds=self.window,
            requests_in_window=reqs + 1, tokens_in_window=toks + tok,
            cost_in_window_usd=costs + cost, max_requests=self.max_requests,
            max_tokens=self.max_tokens, max_cost_usd=self.max_cost,
            is_throttled=bool(reasons), throttle_reasons=reasons,
        )

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    @property
    def active_sessions(self) -> List[str]:
        cutoff = time.time() - self.window
        with self._lock:
            return [s for s, q in self._sessions.items() if q and q[-1].timestamp >= cutoff]


# ---------------------------------------------------------------------------
# 3. DoWSessionMonitor
# ---------------------------------------------------------------------------

@dataclass
class _TokenRecord:
    timestamp: float
    tokens: int


class DoWSessionMonitor:
    """
    Per-session budget tracker with velocity spike detection.

    Usage::

        monitor = DoWSessionMonitor("agent-1", budget_usd=2.00)
        monitor.record(tokens=850)
        stats = monitor.stats()
        if stats.budget_exhausted:
            raise DoWBudgetExhaustedError("Budget gone", stats)
    """

    def __init__(
        self,
        session_id: str,
        budget_usd: float = 0.0,
        spike_multiplier: float = 5.0,
        velocity_window: float = 30.0,
        on_spike: Optional[Callable[[str, float], None]] = None,
        on_budget_warning: Optional[Callable[[str, float], None]] = None,
        budget_warning_pct: float = 80.0,
        cost_per_1k_tokens: float = _DEFAULT_COST_PER_1K,
    ) -> None:
        self.session_id = session_id
        self.budget_usd = budget_usd
        self._spike_mult = spike_multiplier
        self._vel_window = velocity_window
        self._on_spike = on_spike
        self._on_budget_warning = on_budget_warning
        self._warn_pct = budget_warning_pct
        self._cost_per_1k = cost_per_1k_tokens
        self._started_at = datetime.now(tz=timezone.utc).isoformat()
        self._total_requests = 0
        self._total_tokens = 0
        self._total_cost = 0.0
        self._dow_count = 0
        self._throttle_count = 0
        self._velocity_spikes = 0
        self._budget_exhausted = False
        self._warned = False
        self._recent: Deque[_TokenRecord] = deque()
        self._baseline_tpm: Optional[float] = None
        self._peak_rpm = 0.0
        self._peak_tpm = 0.0
        self._req_timestamps: Deque[float] = deque()
        self._lock = threading.Lock()

    def record(self, tokens: int, is_dow: bool = False, was_throttled: bool = False) -> None:
        now = time.time()
        cost = (tokens / 1000) * self._cost_per_1k
        with self._lock:
            self._total_requests += 1
            self._total_tokens += tokens
            self._total_cost += cost
            if is_dow: self._dow_count += 1
            if was_throttled: self._throttle_count += 1
            self._recent.append(_TokenRecord(timestamp=now, tokens=tokens))
            self._req_timestamps.append(now)
            self._cleanup(now)
            tpm = self._current_tpm(now)
            rpm = self._current_rpm(now)
            if tpm > self._peak_tpm: self._peak_tpm = tpm
            if rpm > self._peak_rpm: self._peak_rpm = rpm
            if self._baseline_tpm is None and self._total_requests >= 5:
                self._baseline_tpm = self._peak_tpm
            elif self._baseline_tpm and tpm > self._baseline_tpm * self._spike_mult:
                self._velocity_spikes += 1
                if self._on_spike: self._on_spike(self.session_id, tpm)
            if self.budget_usd > 0:
                pct = (self._total_cost / self.budget_usd) * 100
                if pct >= 100:
                    self._budget_exhausted = True
                elif pct >= self._warn_pct and not self._warned:
                    self._warned = True
                    if self._on_budget_warning: self._on_budget_warning(self.session_id, self._total_cost)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self._vel_window
        while self._recent and self._recent[0].timestamp < cutoff: self._recent.popleft()
        while self._req_timestamps and self._req_timestamps[0] < cutoff: self._req_timestamps.popleft()

    def _current_tpm(self, now: float) -> float:
        if not self._recent: return 0.0
        w = min(self._vel_window, now - self._recent[0].timestamp + 0.001)
        return sum(r.tokens for r in self._recent) / w * 60

    def _current_rpm(self, now: float) -> float:
        if not self._req_timestamps: return 0.0
        w = min(self._vel_window, now - self._req_timestamps[0] + 0.001)
        return len(self._req_timestamps) / w * 60

    @property
    def budget_exhausted(self) -> bool:
        return self._budget_exhausted

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_usd - self._total_cost) if self.budget_usd else float("inf")

    def stats(self) -> SessionBudgetStats:
        with self._lock:
            return SessionBudgetStats(
                session_id=self.session_id, started_at=self._started_at,
                total_requests=self._total_requests, total_tokens=self._total_tokens,
                total_cost_usd=self._total_cost, dow_attempts_detected=self._dow_count,
                requests_throttled=self._throttle_count, peak_rpm=self._peak_rpm,
                peak_tpm=self._peak_tpm, velocity_spikes=self._velocity_spikes,
                budget_usd=self.budget_usd, budget_remaining_usd=self.budget_remaining,
                budget_exhausted=self._budget_exhausted,
            )

    def reset(self) -> None:
        with self._lock:
            self._total_requests = 0; self._total_tokens = 0; self._total_cost = 0.0
            self._dow_count = 0; self._throttle_count = 0; self._velocity_spikes = 0
            self._budget_exhausted = False; self._warned = False
            self._recent.clear(); self._req_timestamps.clear()
            self._baseline_tpm = None; self._peak_rpm = 0.0; self._peak_tpm = 0.0


# ---------------------------------------------------------------------------
# 4. DoWGuard — combined defense layer
# ---------------------------------------------------------------------------

class DoWGuard:
    """
    Combined DoW defense: detection + rate limiting + budget tracking.

    Usage::

        guard = DoWGuard(session_id="agent-1", budget_usd=2.00)
        guard.check(prompt)              # raises on attack / throttle / budget
        response = llm(prompt)
        guard.record(tokens=response.usage.total_tokens)
        print(guard.stats().to_dict())
    """

    def __init__(
        self,
        session_id: str = "default",
        budget_usd: float = 0.0,
        max_requests_per_minute: int = 200,
        max_tokens_per_minute: int = 100_000,
        max_cost_per_minute_usd: float = 1.0,
        block_on_dow: bool = True,
        block_on_throttle: bool = True,
        block_on_budget: bool = True,
        cost_per_1k_tokens: float = _DEFAULT_COST_PER_1K,
        on_spike: Optional[Callable[[str, float], None]] = None,
        on_budget_warning: Optional[Callable[[str, float], None]] = None,
    ) -> None:
        self.session_id = session_id
        self._detector = DoWDetector(cost_per_1k_tokens=cost_per_1k_tokens)
        self._limiter = DoWRateLimiter(
            max_requests_per_window=max_requests_per_minute,
            max_tokens_per_window=max_tokens_per_minute,
            max_cost_per_window_usd=max_cost_per_minute_usd,
            window_seconds=60.0,
            cost_per_1k_tokens=cost_per_1k_tokens,
        )
        self._monitor = DoWSessionMonitor(
            session_id=session_id, budget_usd=budget_usd,
            cost_per_1k_tokens=cost_per_1k_tokens,
            on_spike=on_spike, on_budget_warning=on_budget_warning,
        )
        self._block_dow = block_on_dow
        self._block_throttle = block_on_throttle
        self._block_budget = block_on_budget

    def check(self, content: str) -> DoWAnalysisResult:
        """
        Run all DoW checks before passing content to LLM.

        Raises DoWAttackDetected, DoWThrottleError, or DoWBudgetExhaustedError.
        Returns DoWAnalysisResult on success.
        """
        if self._block_budget and self._monitor.budget_exhausted:
            raise DoWBudgetExhaustedError(
                f"Budget exhausted for '{self.session_id}'", stats=self._monitor.stats()
            )
        result = self._detector.analyze(content)
        if result.is_dow_attempt and self._block_dow:
            raise DoWAttackDetected(
                f"DoW blocked (score={result.score}, risk={result.risk.value}): {result.explanation}",
                result=result,
            )
        status = self._limiter.check_and_record(self.session_id, content=content)
        if status.is_throttled and self._block_throttle:
            raise DoWThrottleError(
                f"Rate limit for '{self.session_id}': {'; '.join(status.throttle_reasons)}",
                status=status,
            )
        est_tokens = max(1, int(len(content) / _CHARS_PER_TOKEN))
        self._monitor.record(tokens=est_tokens, is_dow=result.is_dow_attempt, was_throttled=status.is_throttled)
        return result

    def record(self, tokens: int) -> None:
        """Record actual LLM response token usage."""
        self._monitor.record(tokens=tokens)

    def stats(self) -> SessionBudgetStats:
        return self._monitor.stats()

    def reset(self) -> None:
        self._limiter.reset_session(self.session_id)
        self._monitor.reset()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_dow_guard(
    session_id: str = "default",
    budget_usd: float = 1.0,
    strict: bool = False,
) -> DoWGuard:
    """
    Create a DoWGuard with sensible defaults.

    Args:
        session_id: Agent/user session identifier.
        budget_usd: Hard USD spend cap (default $1.00).
        strict:     Tighter limits — half the rate caps.
    """
    return DoWGuard(
        session_id=session_id,
        budget_usd=budget_usd,
        max_requests_per_minute=100 if strict else 200,
        max_tokens_per_minute=50_000 if strict else 100_000,
        max_cost_per_minute_usd=0.50 if strict else 1.0,
    )
