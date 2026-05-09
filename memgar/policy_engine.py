"""
Policy Engine — centralised, rule-based decision logic for Memgar.

Problem
-------
Decision logic is currently scattered across five files with five different
enums and incompatible threshold names:

  memory_guard.py         ALLOW / ALLOW_SANITIZED / QUARANTINE / BLOCK
  runtime.py              ALLOW / SANITIZE / QUARANTINE / BLOCK
  gateway/policy.py       ALLOW / SANITIZE / BLOCK
  action_guard.py         EXECUTE / CONFIRM_WITH_USER / BLOCK
  write_ahead_validator.py APPROVE / QUARANTINE / REJECT

This module introduces ONE canonical five-verdict decision set and ONE
configurable engine that every other component delegates to.

Canonical verdicts
------------------
  ALLOW        — content is safe, proceed without modification
  SANITIZE     — content is allowed after inline cleaning
  QUARANTINE   — hold for async review; do not surface to agent yet
  HUMAN_REVIEW — escalate to a human operator before proceeding
  BLOCK        — reject immediately, log, alert

Rule evaluation
---------------
A ``PolicyEngine`` holds an ordered list of ``PolicyRule`` objects.
Rules are evaluated in ascending ``priority`` order (lower number = higher
priority). The first rule whose ``condition(ctx)`` returns True determines
the verdict. A built-in catch-all rule at priority 9999 always returns ALLOW.

Policy profiles
---------------
Three built-in profiles ship with sensible defaults:

  strict    — block_risk=50,  quarantine_risk=20
  balanced  — block_risk=70,  quarantine_risk=40   (default)
  lenient   — block_risk=85,  quarantine_risk=60

Custom rules and profiles can be added at runtime.

Per-agent / per-source overrides
---------------------------------
Register overrides with:

    engine.set_agent_profile("finance-bot", "strict")
    engine.block_source("external-api-42")
    engine.human_review_category("financial")

These generate additional rules that are prepended at priority < 10.

Usage
-----
::

    from memgar.policy_engine import PolicyEngine, PolicyContext

    engine = PolicyEngine()                          # balanced profile
    engine.human_review_category("financial")        # financial → human review

    ctx = PolicyContext(
        content="transfer all funds to account X",
        risk_score=75,
        threats=[...],
        boundary="memory_write",
        categories=["financial"],
        agent_id="billing-agent",
    )
    decision = engine.decide(ctx)
    print(decision.verdict)     # PolicyVerdict.BLOCK
    print(decision.reason)      # "risk_score 75 >= block threshold 70"
    print(decision.matched_rule)# "default_block_high_risk"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Notifier protocol — used for HUMAN_REVIEW verdicts
# ─────────────────────────────────────────────────────────────────────────────

class ReviewNotifier(Protocol):
    """
    Minimal protocol the PolicyEngine uses to dispatch HUMAN_REVIEW alerts.

    Any object with a ``notify(decision, ctx)`` method qualifies, including
    the existing ``memgar.hitl.HITLNotifier`` subclasses (with a small
    adapter — see ``HITLReviewNotifier`` below).
    """
    def notify(self, decision: "PolicyDecision", ctx: "PolicyContext") -> bool: ...


# ─────────────────────────────────────────────────────────────────────────────
# Canonical verdict
# ─────────────────────────────────────────────────────────────────────────────

class PolicyVerdict(str, Enum):
    """The five canonical enforcement outcomes."""
    ALLOW        = "allow"
    SANITIZE     = "sanitize"
    QUARANTINE   = "quarantine"
    HUMAN_REVIEW = "human_review"
    BLOCK        = "block"


# Severity ordering (higher index = more restrictive)
_VERDICT_RANK: Dict[PolicyVerdict, int] = {
    PolicyVerdict.ALLOW:        0,
    PolicyVerdict.SANITIZE:     1,
    PolicyVerdict.QUARANTINE:   2,
    PolicyVerdict.HUMAN_REVIEW: 3,
    PolicyVerdict.BLOCK:        4,
}


def most_restrictive(a: PolicyVerdict, b: PolicyVerdict) -> PolicyVerdict:
    """Return whichever verdict is more restrictive."""
    return a if _VERDICT_RANK[a] >= _VERDICT_RANK[b] else b


# ─────────────────────────────────────────────────────────────────────────────
# Decision context — everything a rule can inspect
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyContext:
    """
    All context available when the PolicyEngine evaluates rules.

    Attributes:
        content: Raw (or sanitized) text being evaluated.
        risk_score: 0–100 score from the Analyzer pipeline.
        threats: List of detected threat info dicts or objects.
        boundary: Which enforcement boundary produced this context
            (e.g. "memory_write", "rag_chunk", "tool_result", "agent_summary").
        source_type: Source of the content ("email", "vector_store", …).
        source_id: Stable identifier for the source instance.
        agent_id: Agent evaluating / writing the content.
        tenant_id: Tenant for multi-tenant deployments.
        categories: Threat categories detected (e.g. ["financial", "exfiltration"]).
        canary_leaks: Number of canary tokens detected in content.
        was_sanitized: Whether the content was already cleaned upstream.
        analyzer_decision: Raw Decision enum from Analyzer ("allow"/"block"/"quarantine").
        extra: Open-ended dict for caller-specific metadata.
    """
    content: str
    risk_score: int = 0
    threats: List[Any] = field(default_factory=list)
    boundary: str = "unknown"
    source_type: str = "unknown"
    source_id: str = ""
    agent_id: str = ""
    tenant_id: str = ""
    categories: List[str] = field(default_factory=list)
    canary_leaks: int = 0
    was_sanitized: bool = False
    analyzer_decision: str = "allow"   # "allow" | "block" | "quarantine"
    extra: Dict[str, Any] = field(default_factory=dict)

    def has_category(self, *cats: str) -> bool:
        """True if any of the given categories are present."""
        return bool(set(self.categories) & set(cats))


# ─────────────────────────────────────────────────────────────────────────────
# Policy decision — output of engine.decide()
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    """
    Output of ``PolicyEngine.decide()``.

    Attributes:
        verdict: Canonical enforcement action.
        reason: Human-readable explanation.
        matched_rule: Name of the rule that triggered.
        confidence: 0.0–1.0; rules may lower this for uncertain decisions.
        ctx: The context that was evaluated (for audit logging).
        quarantine_id: ID of the QuarantineStore entry created when verdict
            is QUARANTINE/HUMAN_REVIEW. Empty when no store is wired up
            or the verdict does not require quarantining.
        notified: True when a ReviewNotifier successfully accepted a
            HUMAN_REVIEW alert. False on notifier error or absence.
        sanitized_content: Cleaned text produced when verdict is SANITIZE
            and a sanitizer is wired in. Empty for other verdicts.
    """
    verdict: PolicyVerdict
    reason: str
    matched_rule: str = "default_allow"
    confidence: float = 1.0
    ctx: Optional[PolicyContext] = None
    quarantine_id: str = ""
    notified: bool = False
    sanitized_content: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict in (PolicyVerdict.ALLOW, PolicyVerdict.SANITIZE)

    @property
    def blocked(self) -> bool:
        return self.verdict == PolicyVerdict.BLOCK

    @property
    def needs_review(self) -> bool:
        return self.verdict in (PolicyVerdict.QUARANTINE, PolicyVerdict.HUMAN_REVIEW)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "confidence": round(self.confidence, 3),
            "allowed": self.allowed,
            "needs_review": self.needs_review,
            "quarantine_id": self.quarantine_id,
            "notified": self.notified,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Policy rule
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyRule:
    """
    A single evaluable rule: condition(ctx) → verdict.

    Args:
        name: Unique rule identifier (used in audit logs and matched_rule).
        condition: Callable that returns True when this rule fires.
        verdict: The verdict to return when condition is True.
        reason: Template string for the reason. May reference ``{ctx.*}``
            attributes via ``reason.format(ctx=ctx)``.
        priority: Lower numbers are evaluated first. Built-in rules occupy
            ranges: 1–9 (canary/override), 10–99 (high-certainty), 100–499
            (threshold-based), 500–999 (supplemental), 9999 (catch-all allow).
        confidence: Decision confidence when this rule fires (0.0–1.0).
        enabled: Disabled rules are skipped without removal.
    """
    name: str
    condition: Callable[[PolicyContext], bool]
    verdict: PolicyVerdict
    reason: str
    priority: int = 100
    confidence: float = 1.0
    enabled: bool = True

    def evaluate(self, ctx: PolicyContext) -> Optional[PolicyDecision]:
        if not self.enabled:
            return None
        try:
            if self.condition(ctx):
                reason = self.reason.format(ctx=ctx) if "{ctx" in self.reason else self.reason
                return PolicyDecision(
                    verdict=self.verdict,
                    reason=reason,
                    matched_rule=self.name,
                    confidence=self.confidence,
                    ctx=ctx,
                )
        except Exception as exc:
            logger.debug("Rule %s evaluation error: %s", self.name, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Built-in rule factories
# ─────────────────────────────────────────────────────────────────────────────

def _rule_canary_leak() -> PolicyRule:
    return PolicyRule(
        name="canary_leak",
        condition=lambda ctx: ctx.canary_leaks > 0,
        verdict=PolicyVerdict.BLOCK,
        reason="canary token leak detected ({ctx.canary_leaks} token(s)) — data exfiltration probe",
        priority=1,
        confidence=0.99,
    )


def _rule_analyzer_hard_block() -> PolicyRule:
    return PolicyRule(
        name="analyzer_hard_block",
        condition=lambda ctx: ctx.analyzer_decision == "block",
        verdict=PolicyVerdict.BLOCK,
        reason="Analyzer issued hard BLOCK decision",
        priority=5,
        confidence=0.95,
    )


def _rule_extreme_risk(threshold: int = 90) -> PolicyRule:
    return PolicyRule(
        name="extreme_risk",
        condition=lambda ctx: ctx.risk_score >= threshold,
        verdict=PolicyVerdict.BLOCK,
        reason=f"risk_score {{ctx.risk_score}} ≥ extreme threshold {threshold}",
        priority=10,
        confidence=0.97,
    )


def _rule_block_risk(threshold: int = 70) -> PolicyRule:
    return PolicyRule(
        name="default_block_high_risk",
        condition=lambda ctx: ctx.risk_score >= threshold,
        verdict=PolicyVerdict.BLOCK,
        reason=f"risk_score {{ctx.risk_score}} ≥ block threshold {threshold}",
        priority=100,
        confidence=0.90,
    )


def _rule_sanitize(sanitize_threshold: int = 40, block_threshold: int = 70) -> PolicyRule:
    return PolicyRule(
        name="default_sanitize",
        condition=lambda ctx: (
            ctx.was_sanitized
            and sanitize_threshold <= ctx.risk_score < block_threshold
        ),
        verdict=PolicyVerdict.SANITIZE,
        reason=f"content sanitized; risk_score {{ctx.risk_score}} in [{sanitize_threshold}, {block_threshold})",
        priority=110,
        confidence=0.85,
    )


def _rule_quarantine_risk(threshold: int = 40, block_threshold: int = 70) -> PolicyRule:
    return PolicyRule(
        name="default_quarantine",
        condition=lambda ctx: threshold <= ctx.risk_score < block_threshold,
        verdict=PolicyVerdict.QUARANTINE,
        reason=f"risk_score {{ctx.risk_score}} in [{threshold}, {block_threshold}) — review required",
        priority=120,
        confidence=0.80,
    )


def _rule_analyzer_quarantine() -> PolicyRule:
    return PolicyRule(
        name="analyzer_quarantine",
        condition=lambda ctx: ctx.analyzer_decision == "quarantine" and ctx.risk_score < 40,
        verdict=PolicyVerdict.QUARANTINE,
        reason="Analyzer issued QUARANTINE; risk_score={ctx.risk_score}",
        priority=130,
        confidence=0.75,
    )


def _rule_catch_all() -> PolicyRule:
    return PolicyRule(
        name="catch_all_allow",
        condition=lambda _: True,
        verdict=PolicyVerdict.ALLOW,
        reason="no rule triggered — content appears safe",
        priority=9999,
        confidence=1.0,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Profile definitions
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyProfile:
    """
    Named threshold set that drives the built-in risk-score rules.

    Custom rules added via engine.add_rule() are independent of profiles.
    """
    name: str
    block_risk_score: int = 70
    quarantine_risk_score: int = 40
    extreme_risk_score: int = 90
    description: str = ""

    def build_rules(self) -> List[PolicyRule]:
        return [
            _rule_canary_leak(),
            _rule_analyzer_hard_block(),
            _rule_extreme_risk(self.extreme_risk_score),
            _rule_block_risk(self.block_risk_score),
            _rule_sanitize(self.quarantine_risk_score, self.block_risk_score),
            _rule_quarantine_risk(self.quarantine_risk_score, self.block_risk_score),
            _rule_analyzer_quarantine(),
            _rule_catch_all(),
        ]


_BUILT_IN_PROFILES: Dict[str, PolicyProfile] = {
    "strict": PolicyProfile(
        name="strict",
        block_risk_score=50,
        quarantine_risk_score=20,
        extreme_risk_score=75,
        description="High-security: lower thresholds, block more aggressively",
    ),
    "balanced": PolicyProfile(
        name="balanced",
        block_risk_score=70,
        quarantine_risk_score=40,
        extreme_risk_score=90,
        description="Default: sensible thresholds for most deployments",
    ),
    "lenient": PolicyProfile(
        name="lenient",
        block_risk_score=85,
        quarantine_risk_score=60,
        extreme_risk_score=95,
        description="Low-friction: allow more, quarantine less",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Centralised rule-based policy engine for all Memgar enforcement points.

    Rules are evaluated in ascending ``priority`` order. The first matching
    rule wins. Callers receive a ``PolicyDecision`` with a canonical
    ``PolicyVerdict``.

    Args:
        profile: Starting profile name — "strict" | "balanced" | "lenient".
        extra_rules: Additional rules merged in at construction time.
        audit_log: If True, log every decision at DEBUG level.

    Quick-start::

        engine = PolicyEngine()
        engine.human_review_category("financial", "credential")
        engine.block_source("untrusted-external-feed")

        ctx = PolicyContext(
            content="...",
            risk_score=75,
            categories=["financial"],
            boundary="memory_write",
        )
        decision = engine.decide(ctx)
        if decision.blocked:
            raise MemoryPoisoningError(decision.reason)
    """

    def __init__(
        self,
        profile: str = "balanced",
        extra_rules: Optional[List[PolicyRule]] = None,
        audit_log: bool = False,
        quarantine_store: Optional[Any] = None,
        review_notifier: Optional[ReviewNotifier] = None,
        sanitizer: Optional[Any] = None,
    ) -> None:
        """
        Args:
            profile: Threshold profile name — "strict" / "balanced" / "lenient".
            extra_rules: Additional rules merged in at construction time.
            audit_log: Log every decision at DEBUG level.
            quarantine_store: A ``QuarantineStore`` (or compatible) to which
                content will be written when verdict == QUARANTINE or
                HUMAN_REVIEW. If omitted, those verdicts are returned but no
                content is persisted (caller responsibility).
            review_notifier: A ``ReviewNotifier`` invoked on HUMAN_REVIEW
                verdicts. If omitted, no notification is sent.
            sanitizer: An object with a ``sanitize(text)`` method (e.g.
                ``InstructionSanitizer``). When verdict == SANITIZE the engine
                will populate ``decision.sanitized_content`` with the cleaned
                text. If omitted, callers must sanitize themselves.
        """
        self._audit_log = audit_log
        self._agent_profiles: Dict[str, str] = {}       # agent_id → profile name
        self._tenant_profiles: Dict[str, str] = {}      # tenant_id → profile name
        self._custom_rules: List[PolicyRule] = []        # operator-added rules
        self._profile_name = profile

        # Enforcement backends
        self._quarantine_store = quarantine_store
        self._review_notifier = review_notifier
        self._sanitizer = sanitizer

        # Load base profile rules
        self._profile_rules: List[PolicyRule] = self._load_profile(profile)

        if extra_rules:
            for r in extra_rules:
                self._custom_rules.append(r)

    # ── backend wiring (post-construction) ────────────────────────────────────

    def attach_quarantine_store(self, store: Any) -> None:
        """Attach (or replace) the QuarantineStore used for QUARANTINE verdicts."""
        self._quarantine_store = store

    def attach_review_notifier(self, notifier: ReviewNotifier) -> None:
        """Attach (or replace) the ReviewNotifier used for HUMAN_REVIEW verdicts."""
        self._review_notifier = notifier

    def attach_sanitizer(self, sanitizer: Any) -> None:
        """Attach (or replace) the sanitizer used to materialize SANITIZE content."""
        self._sanitizer = sanitizer

    @property
    def quarantine_store(self) -> Optional[Any]:
        return self._quarantine_store

    @property
    def review_notifier(self) -> Optional[ReviewNotifier]:
        return self._review_notifier

    # ── profile management ────────────────────────────────────────────────────

    def _load_profile(self, name: str) -> List[PolicyRule]:
        prof = _BUILT_IN_PROFILES.get(name)
        if prof is None:
            logger.warning("Unknown profile %r — falling back to 'balanced'", name)
            prof = _BUILT_IN_PROFILES["balanced"]
        return prof.build_rules()

    def load_profile(self, name: str) -> None:
        """Switch the base profile (replaces existing threshold rules)."""
        self._profile_rules = self._load_profile(name)
        self._profile_name = name
        logger.info("PolicyEngine: loaded profile %r", name)

    def set_agent_profile(self, agent_id: str, profile: str) -> None:
        """Route a specific agent through a named profile."""
        if profile not in _BUILT_IN_PROFILES:
            raise ValueError(f"Unknown profile {profile!r}; choose from {list(_BUILT_IN_PROFILES)}")
        self._agent_profiles[agent_id] = profile

    def set_tenant_profile(self, tenant_id: str, profile: str) -> None:
        """Route a specific tenant through a named profile."""
        if profile not in _BUILT_IN_PROFILES:
            raise ValueError(f"Unknown profile {profile!r}; choose from {list(_BUILT_IN_PROFILES)}")
        self._tenant_profiles[tenant_id] = profile

    # ── rule management ───────────────────────────────────────────────────────

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a custom rule. Lower priority number = evaluated sooner."""
        self._custom_rules.append(rule)
        logger.debug("PolicyEngine: added rule %r (priority=%d)", rule.name, rule.priority)

    def remove_rule(self, name: str) -> bool:
        """Remove a custom rule by name. Returns True if found and removed."""
        before = len(self._custom_rules)
        self._custom_rules = [r for r in self._custom_rules if r.name != name]
        return len(self._custom_rules) < before

    def disable_rule(self, name: str) -> bool:
        """Disable a rule without removing it (can be re-enabled later)."""
        for r in self._custom_rules + self._profile_rules:
            if r.name == name:
                r.enabled = False
                return True
        return False

    def enable_rule(self, name: str) -> bool:
        """Re-enable a previously disabled rule."""
        for r in self._custom_rules + self._profile_rules:
            if r.name == name:
                r.enabled = True
                return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        """Return all active rules in evaluation order."""
        return [
            {
                "name": r.name,
                "priority": r.priority,
                "verdict": r.verdict.value,
                "enabled": r.enabled,
                "source": "custom" if r in self._custom_rules else "profile",
            }
            for r in self._sorted_rules()
        ]

    # ── shortcut overrides ────────────────────────────────────────────────────

    def block_source(self, *source_ids: str) -> None:
        """Always BLOCK content from these source IDs (priority 2)."""
        sid_set = set(source_ids)
        self.add_rule(PolicyRule(
            name=f"block_source:{'|'.join(sorted(sid_set))}",
            condition=lambda ctx, s=sid_set: ctx.source_id in s,
            verdict=PolicyVerdict.BLOCK,
            reason="source_id {ctx.source_id!r} is on the block list",
            priority=2,
            confidence=0.99,
        ))

    def block_source_type(self, *source_types: str) -> None:
        """Always BLOCK content with these source types (priority 3)."""
        st_set = set(source_types)
        self.add_rule(PolicyRule(
            name=f"block_source_type:{'|'.join(sorted(st_set))}",
            condition=lambda ctx, s=st_set: ctx.source_type in s,
            verdict=PolicyVerdict.BLOCK,
            reason="source_type {ctx.source_type!r} is on the block list",
            priority=3,
            confidence=0.99,
        ))

    def human_review_category(self, *categories: str) -> None:
        """
        Route content whose threat categories overlap with the given set
        to HUMAN_REVIEW (priority 15).

        Example::

            engine.human_review_category("financial", "credential")
        """
        cat_set = set(categories)
        self.add_rule(PolicyRule(
            name=f"human_review_cat:{'|'.join(sorted(cat_set))}",
            condition=lambda ctx, c=cat_set: bool(set(ctx.categories) & c),
            verdict=PolicyVerdict.HUMAN_REVIEW,
            reason="category overlap {ctx.categories} ∩ " + str(sorted(cat_set)),
            priority=15,
            confidence=0.88,
        ))

    def quarantine_boundary(self, *boundaries: str) -> None:
        """Always quarantine content arriving from specific boundaries."""
        b_set = set(boundaries)
        self.add_rule(PolicyRule(
            name=f"quarantine_boundary:{'|'.join(sorted(b_set))}",
            condition=lambda ctx, b=b_set: ctx.boundary in b,
            verdict=PolicyVerdict.QUARANTINE,
            reason="boundary {ctx.boundary!r} is in quarantine list",
            priority=20,
            confidence=0.80,
        ))

    def allow_agent(self, *agent_ids: str) -> None:
        """Fast-allow content from trusted internal agents (priority 6)."""
        a_set = set(agent_ids)
        self.add_rule(PolicyRule(
            name=f"allow_agent:{'|'.join(sorted(a_set))}",
            condition=lambda ctx, a=a_set: ctx.agent_id in a and ctx.risk_score < 40,
            verdict=PolicyVerdict.ALLOW,
            reason="trusted agent {ctx.agent_id!r} with low risk {ctx.risk_score}",
            priority=6,
            confidence=0.90,
        ))

    # ── decision ──────────────────────────────────────────────────────────────

    def decide(self, ctx: PolicyContext) -> PolicyDecision:
        """
        Evaluate all rules against ``ctx`` and return the first match.

        Side effects (when the corresponding backend is wired in):
          * verdict=SANITIZE     → content is run through the sanitizer and
                                   the cleaned text is stored on
                                   ``decision.sanitized_content``.
          * verdict=QUARANTINE   → content is persisted to ``quarantine_store``
                                   and the entry ID is stored on
                                   ``decision.quarantine_id``.
          * verdict=HUMAN_REVIEW → content is persisted to ``quarantine_store``
                                   AND ``review_notifier.notify()`` is called;
                                   ``decision.notified`` records success.

        If the agent or tenant has a profile override, the threshold rules
        are temporarily replaced for this evaluation.
        """
        rules = self._sorted_rules(ctx)

        decision: Optional[PolicyDecision] = None
        for rule in rules:
            evaluated = rule.evaluate(ctx)
            if evaluated is not None:
                decision = evaluated
                break

        if decision is None:
            # Should never reach here (catch_all_allow always fires) but be safe
            decision = PolicyDecision(
                verdict=PolicyVerdict.ALLOW,
                reason="fallback allow",
                matched_rule="__fallback__",
                ctx=ctx,
            )

        # Apply enforcement side-effects
        self._apply_enforcement(decision, ctx)

        if self._audit_log:
            logger.debug(
                "PolicyEngine [%s/%s] → %s (rule=%s, risk=%d, qid=%s, notified=%s)",
                ctx.agent_id or "-",
                ctx.boundary,
                decision.verdict.value,
                decision.matched_rule,
                ctx.risk_score,
                decision.quarantine_id[:8] if decision.quarantine_id else "-",
                decision.notified,
            )
        return decision

    def _apply_enforcement(self, decision: PolicyDecision, ctx: PolicyContext) -> None:
        """
        Materialize the verdict by invoking the wired-in backends.

        Best-effort: backend failures are logged but never raised — a notifier
        outage must not crash the request path.
        """
        verdict = decision.verdict

        # SANITIZE → produce cleaned content
        if verdict == PolicyVerdict.SANITIZE and self._sanitizer is not None:
            try:
                sr = self._sanitizer.sanitize(ctx.content)
                # Try common attribute names across sanitizer implementations.
                # Empty string is a valid result ("everything was malicious"),
                # so use a sentinel to distinguish "didn't run" from "ran and
                # produced empty output".
                _MISSING = object()
                cleaned: Any = _MISSING
                for attr in ("sanitized_content", "sanitized_text", "cleaned", "text"):
                    val = getattr(sr, attr, _MISSING)
                    if val is not _MISSING and isinstance(val, str):
                        cleaned = val
                        break
                if cleaned is _MISSING and isinstance(sr, str):
                    cleaned = sr
                if cleaned is not _MISSING:
                    decision.sanitized_content = cleaned
            except Exception as exc:
                logger.warning("PolicyEngine sanitizer failed: %s", exc)

        # QUARANTINE / HUMAN_REVIEW → persist content for review
        if verdict in (PolicyVerdict.QUARANTINE, PolicyVerdict.HUMAN_REVIEW) \
                and self._quarantine_store is not None:
            try:
                qid = self._quarantine_store.put(
                    content=ctx.content,
                    reason=decision.reason,
                    verdict=verdict.value,
                    boundary=ctx.boundary,
                    source_type=ctx.source_type,
                    source_id=ctx.source_id,
                    agent_id=ctx.agent_id,
                    tenant_id=ctx.tenant_id,
                    risk_score=ctx.risk_score,
                    categories=list(ctx.categories),
                    matched_rule=decision.matched_rule,
                    metadata={"confidence": decision.confidence, **(ctx.extra or {})},
                )
                decision.quarantine_id = qid
            except Exception as exc:
                # Don't blank the verdict — caller still needs to know it was
                # held back; just record the persistence failure in the reason.
                logger.warning("PolicyEngine quarantine_store.put failed: %s", exc)
                decision.reason = (
                    (decision.reason + "; " if decision.reason else "")
                    + f"quarantine_store_error: {exc}"
                )

        # HUMAN_REVIEW → also fire notifier
        if verdict == PolicyVerdict.HUMAN_REVIEW and self._review_notifier is not None:
            try:
                ok = bool(self._review_notifier.notify(decision, ctx))
                decision.notified = ok
                if not ok:
                    logger.warning(
                        "ReviewNotifier returned False for decision %s (rule=%s)",
                        verdict.value, decision.matched_rule,
                    )
            except Exception as exc:
                logger.warning("PolicyEngine review_notifier failed: %s", exc)
                decision.notified = False

    def decide_from_analysis(
        self,
        analysis: Any,
        *,
        content: str,
        boundary: str = "unknown",
        source_type: str = "unknown",
        source_id: str = "",
        agent_id: str = "",
        tenant_id: str = "",
        canary_leaks: int = 0,
        was_sanitized: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Convenience wrapper: build a ``PolicyContext`` from an Analyzer result
        and call ``decide()``.

        Args:
            analysis: ``AnalysisResult`` from ``Analyzer.analyze()``.
            content: Original (or sanitized) content string.
            ... (all other PolicyContext fields)
        """
        risk = getattr(analysis, "risk_score", 0)
        raw_decision = str(getattr(analysis, "decision", "allow")).lower()
        if "block" in raw_decision:
            raw_decision = "block"
        elif "quarantine" in raw_decision:
            raw_decision = "quarantine"
        else:
            raw_decision = "allow"

        categories: List[str] = []
        for tm in getattr(analysis, "threats", []):
            cat = getattr(getattr(tm, "threat", None), "category", None)
            if cat is not None:
                categories.append(str(cat).lower().split(".")[-1])

        ctx = PolicyContext(
            content=content,
            risk_score=int(risk),
            threats=list(getattr(analysis, "threats", [])),
            boundary=boundary,
            source_type=source_type,
            source_id=source_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            categories=categories,
            canary_leaks=canary_leaks,
            was_sanitized=was_sanitized,
            analyzer_decision=raw_decision,
            extra=extra or {},
        )
        return self.decide(ctx)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _sorted_rules(self, ctx: Optional[PolicyContext] = None) -> List[PolicyRule]:
        """
        Merge custom rules with the active profile rules, sorted by priority.

        If ``ctx`` is provided and the agent/tenant has a profile override,
        the override profile's threshold rules replace the base profile rules.
        """
        base_rules = self._profile_rules

        if ctx is not None:
            override_profile = (
                self._agent_profiles.get(ctx.agent_id)
                or self._tenant_profiles.get(ctx.tenant_id)
            )
            if override_profile and override_profile != self._profile_name:
                base_rules = self._load_profile(override_profile)

        all_rules = self._custom_rules + base_rules
        return sorted(all_rules, key=lambda r: r.priority)

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def profiles(self) -> Dict[str, PolicyProfile]:
        return dict(_BUILT_IN_PROFILES)


# ─────────────────────────────────────────────────────────────────────────────
# Global / singleton helper
# ─────────────────────────────────────────────────────────────────────────────

import threading as _threading

_global_engine: Optional[PolicyEngine] = None
_global_lock = _threading.Lock()


def get_global_engine(**kwargs: Any) -> PolicyEngine:
    """Return the process-level PolicyEngine, creating it on first call."""
    global _global_engine
    if _global_engine is None:
        with _global_lock:
            if _global_engine is None:
                _global_engine = PolicyEngine(**kwargs)
    return _global_engine


def reset_global_engine() -> None:
    """Reset the singleton (useful in tests)."""
    global _global_engine
    with _global_lock:
        _global_engine = None


# ─────────────────────────────────────────────────────────────────────────────
# Concrete ReviewNotifier implementations
# ─────────────────────────────────────────────────────────────────────────────

class LoggingReviewNotifier:
    """
    Default no-frills notifier — writes a structured WARNING to the
    ``memgar.policy_engine.review`` logger.

    Useful as a baseline / fallback when no Slack / webhook is configured.
    """

    def __init__(self, logger_name: str = "memgar.policy_engine.review") -> None:
        self._log = logging.getLogger(logger_name)

    def notify(self, decision: "PolicyDecision", ctx: "PolicyContext") -> bool:
        self._log.warning(
            "[HUMAN_REVIEW] agent=%s boundary=%s risk=%d rule=%s qid=%s reason=%s",
            ctx.agent_id or "-",
            ctx.boundary,
            ctx.risk_score,
            decision.matched_rule,
            decision.quarantine_id[:8] if decision.quarantine_id else "-",
            decision.reason,
        )
        return True


class CallbackReviewNotifier:
    """
    Adapter that turns any callable into a ReviewNotifier.

    ::

        engine = PolicyEngine(
            review_notifier=CallbackReviewNotifier(
                lambda d, c: my_alert_fn(d.reason, c.agent_id)
            )
        )
    """

    def __init__(self, callback: Callable[["PolicyDecision", "PolicyContext"], Any]) -> None:
        self._cb = callback

    def notify(self, decision: "PolicyDecision", ctx: "PolicyContext") -> bool:
        try:
            result = self._cb(decision, ctx)
            return bool(result) if result is not None else True
        except Exception as exc:
            logger.warning("CallbackReviewNotifier callback raised: %s", exc)
            return False


class HITLReviewNotifier:
    """
    Adapter that bridges a ``memgar.hitl.HITLNotifier`` to the
    ``ReviewNotifier`` protocol.

    Builds an ``ApprovalRequest`` from the PolicyDecision/PolicyContext and
    calls the HITL notifier's ``send()`` method. The approve/deny URLs are
    optional — pass them when you have an HITLServer running, otherwise leave
    blank for fire-and-forget alerting.
    """

    def __init__(
        self,
        hitl_notifier: Any,
        approve_url_template: str = "",
        deny_url_template: str = "",
        timeout_seconds: float = 24 * 3600,
    ) -> None:
        self._notifier = hitl_notifier
        self._approve_tpl = approve_url_template
        self._deny_tpl = deny_url_template
        self._timeout = timeout_seconds

    def notify(self, decision: "PolicyDecision", ctx: "PolicyContext") -> bool:
        try:
            from memgar.hitl import ApprovalRequest, RiskLevel
        except Exception as exc:
            logger.warning("HITLReviewNotifier: hitl module unavailable: %s", exc)
            return False

        # Map risk_score → RiskLevel
        if ctx.risk_score >= 90:
            risk_level = RiskLevel.CRITICAL
        elif ctx.risk_score >= 70:
            risk_level = RiskLevel.HIGH
        elif ctx.risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        qid = decision.quarantine_id or "no-quarantine-id"
        approve_url = self._approve_tpl.format(quarantine_id=qid) if self._approve_tpl else ""
        deny_url = self._deny_tpl.format(quarantine_id=qid) if self._deny_tpl else ""

        request = ApprovalRequest(
            request_id=qid,
            action=f"policy:{decision.verdict.value}",
            agent_id=ctx.agent_id or "unknown",
            risk_level=risk_level,
            details={
                "boundary": ctx.boundary,
                "matched_rule": decision.matched_rule,
                "reason": decision.reason,
                "risk_score": ctx.risk_score,
                "categories": ctx.categories,
                "source_type": ctx.source_type,
                "source_id": ctx.source_id,
                "content_preview": (ctx.content or "")[:200],
            },
            timeout_seconds=self._timeout,
        )
        try:
            return bool(self._notifier.send(request, approve_url, deny_url))
        except Exception as exc:
            logger.warning("HITLReviewNotifier: notifier.send raised: %s", exc)
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Compatibility adapters — bridge from canonical verdicts to legacy enums
# ─────────────────────────────────────────────────────────────────────────────

def verdict_to_enforcement_action(verdict: PolicyVerdict) -> str:
    """
    Convert PolicyVerdict to the string value used by
    ``memgar.runtime.EnforcementAction``.
    """
    _map = {
        PolicyVerdict.ALLOW:        "allow",
        PolicyVerdict.SANITIZE:     "sanitize",
        PolicyVerdict.QUARANTINE:   "quarantine",
        PolicyVerdict.HUMAN_REVIEW: "quarantine",  # runtime shows as quarantine
        PolicyVerdict.BLOCK:        "block",
    }
    return _map[verdict]


def verdict_to_guard_decision(verdict: PolicyVerdict) -> str:
    """
    Convert PolicyVerdict to the string value used by
    ``memgar.memory_guard.GuardDecision``.
    """
    _map = {
        PolicyVerdict.ALLOW:        "allow",
        PolicyVerdict.SANITIZE:     "allow_sanitized",
        PolicyVerdict.QUARANTINE:   "quarantine",
        PolicyVerdict.HUMAN_REVIEW: "quarantine",
        PolicyVerdict.BLOCK:        "block",
    }
    return _map[verdict]


# ─────────────────────────────────────────────────────────────────────────────
# Exports
# ─────────────────────────────────────────────────────────────────────────────

__all__ = [
    "PolicyEngine",
    "PolicyVerdict",
    "PolicyContext",
    "PolicyDecision",
    "PolicyRule",
    "PolicyProfile",
    "ReviewNotifier",
    "LoggingReviewNotifier",
    "CallbackReviewNotifier",
    "HITLReviewNotifier",
    "most_restrictive",
    "get_global_engine",
    "reset_global_engine",
    "verdict_to_enforcement_action",
    "verdict_to_guard_decision",
]
