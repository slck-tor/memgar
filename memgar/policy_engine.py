"""
Policy Engine - centralised, rule-based decision logic for Memgar.

The engine exposes one canonical five-verdict model:
ALLOW, SANITIZE, QUARANTINE, HUMAN_REVIEW, BLOCK.

Custom rules are supported, but they cannot weaken the immutable safety floor
created by canary leaks, Analyzer hard-blocks, or profile risk thresholds. This
prevents a high-priority allow rule from bypassing launch-critical safeguards.
"""

from __future__ import annotations

import logging
import threading as _threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    HUMAN_REVIEW = "human_review"
    BLOCK = "block"


_VERDICT_RANK: Dict[PolicyVerdict, int] = {
    PolicyVerdict.ALLOW: 0,
    PolicyVerdict.SANITIZE: 1,
    PolicyVerdict.QUARANTINE: 2,
    PolicyVerdict.HUMAN_REVIEW: 3,
    PolicyVerdict.BLOCK: 4,
}


def most_restrictive(a: PolicyVerdict, b: PolicyVerdict) -> PolicyVerdict:
    return a if _VERDICT_RANK[a] >= _VERDICT_RANK[b] else b


@dataclass
class PolicyContext:
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
    analyzer_decision: str = "allow"
    extra: Dict[str, Any] = field(default_factory=dict)

    def has_category(self, *cats: str) -> bool:
        wanted = {c.lower() for c in cats}
        present = {c.lower() for c in self.categories}
        return bool(present & wanted)


@dataclass
class PolicyDecision:
    verdict: PolicyVerdict
    reason: str
    matched_rule: str = "default_allow"
    confidence: float = 1.0
    ctx: Optional[PolicyContext] = None

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
        }


@dataclass
class PolicyRule:
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
            logger.debug("Policy rule %s failed: %s", self.name, exc)
        return None


# Built-in rules

def _rule_canary_leak() -> PolicyRule:
    return PolicyRule(
        name="canary_leak",
        condition=lambda ctx: ctx.canary_leaks > 0,
        verdict=PolicyVerdict.BLOCK,
        reason="canary token leak detected ({ctx.canary_leaks} token(s))",
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


def _rule_extreme_risk(threshold: int) -> PolicyRule:
    return PolicyRule(
        name="extreme_risk",
        condition=lambda ctx: ctx.risk_score >= threshold,
        verdict=PolicyVerdict.BLOCK,
        reason=f"risk_score {{ctx.risk_score}} >= extreme threshold {threshold}",
        priority=10,
        confidence=0.97,
    )


def _rule_block_risk(threshold: int) -> PolicyRule:
    return PolicyRule(
        name="default_block_high_risk",
        condition=lambda ctx: ctx.risk_score >= threshold,
        verdict=PolicyVerdict.BLOCK,
        reason=f"risk_score {{ctx.risk_score}} >= block threshold {threshold}",
        priority=100,
        confidence=0.90,
    )


def _rule_sanitize(sanitize_threshold: int, block_threshold: int) -> PolicyRule:
    return PolicyRule(
        name="default_sanitize",
        condition=lambda ctx: ctx.was_sanitized and sanitize_threshold <= ctx.risk_score < block_threshold,
        verdict=PolicyVerdict.SANITIZE,
        reason=f"content sanitized; risk_score {{ctx.risk_score}} in [{sanitize_threshold}, {block_threshold})",
        priority=110,
        confidence=0.85,
    )


def _rule_quarantine_risk(threshold: int, block_threshold: int) -> PolicyRule:
    return PolicyRule(
        name="default_quarantine",
        condition=lambda ctx: threshold <= ctx.risk_score < block_threshold,
        verdict=PolicyVerdict.QUARANTINE,
        reason=f"risk_score {{ctx.risk_score}} in [{threshold}, {block_threshold}) - review required",
        priority=120,
        confidence=0.80,
    )


def _rule_analyzer_quarantine() -> PolicyRule:
    return PolicyRule(
        name="analyzer_quarantine",
        condition=lambda ctx: ctx.analyzer_decision == "quarantine",
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
        reason="no rule triggered - content appears safe",
        priority=9999,
        confidence=1.0,
    )


@dataclass
class PolicyProfile:
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
    "strict": PolicyProfile("strict", block_risk_score=50, quarantine_risk_score=20, extreme_risk_score=75, description="High-security"),
    "balanced": PolicyProfile("balanced", block_risk_score=70, quarantine_risk_score=40, extreme_risk_score=90, description="Default"),
    "lenient": PolicyProfile("lenient", block_risk_score=85, quarantine_risk_score=60, extreme_risk_score=95, description="Low-friction"),
}


class PolicyEngine:
    def __init__(
        self,
        profile: str = "balanced",
        extra_rules: Optional[List[PolicyRule]] = None,
        audit_log: bool = False,
    ) -> None:
        self._audit_log = audit_log
        self._agent_profiles: Dict[str, str] = {}
        self._tenant_profiles: Dict[str, str] = {}
        self._custom_rules: List[PolicyRule] = []
        self._profile_name = profile if profile in _BUILT_IN_PROFILES else "balanced"
        if profile not in _BUILT_IN_PROFILES:
            logger.warning("Unknown profile %r - falling back to 'balanced'", profile)
        self._profile_rules = self._load_profile(self._profile_name)
        for rule in extra_rules or []:
            self.add_rule(rule)

    def _load_profile(self, name: str) -> List[PolicyRule]:
        return _BUILT_IN_PROFILES.get(name, _BUILT_IN_PROFILES["balanced"]).build_rules()

    def load_profile(self, name: str) -> None:
        if name not in _BUILT_IN_PROFILES:
            logger.warning("Unknown profile %r - falling back to 'balanced'", name)
            name = "balanced"
        self._profile_name = name
        self._profile_rules = self._load_profile(name)

    def set_agent_profile(self, agent_id: str, profile: str) -> None:
        if profile not in _BUILT_IN_PROFILES:
            raise ValueError(f"Unknown profile {profile!r}; choose from {list(_BUILT_IN_PROFILES)}")
        self._agent_profiles[agent_id] = profile

    def set_tenant_profile(self, tenant_id: str, profile: str) -> None:
        if profile not in _BUILT_IN_PROFILES:
            raise ValueError(f"Unknown profile {profile!r}; choose from {list(_BUILT_IN_PROFILES)}")
        self._tenant_profiles[tenant_id] = profile

    def add_rule(self, rule: PolicyRule) -> None:
        self._custom_rules.append(rule)
        logger.debug("PolicyEngine: added rule %r priority=%d", rule.name, rule.priority)

    def remove_rule(self, name: str) -> bool:
        before = len(self._custom_rules)
        self._custom_rules = [r for r in self._custom_rules if r.name != name]
        return len(self._custom_rules) < before

    def disable_rule(self, name: str) -> bool:
        for rule in self._custom_rules + self._profile_rules:
            if rule.name == name:
                rule.enabled = False
                return True
        return False

    def enable_rule(self, name: str) -> bool:
        for rule in self._custom_rules + self._profile_rules:
            if rule.name == name:
                rule.enabled = True
                return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": rule.name,
                "priority": rule.priority,
                "verdict": rule.verdict.value,
                "enabled": rule.enabled,
                "source": "custom" if rule in self._custom_rules else "profile",
            }
            for rule in self._sorted_rules()
        ]

    def block_source(self, *source_ids: str) -> None:
        source_set = set(source_ids)
        self.add_rule(PolicyRule(
            name=f"block_source:{'|'.join(sorted(source_set))}",
            condition=lambda ctx, s=source_set: ctx.source_id in s,
            verdict=PolicyVerdict.BLOCK,
            reason="source_id {ctx.source_id!r} is on the block list",
            priority=2,
            confidence=0.99,
        ))

    def block_source_type(self, *source_types: str) -> None:
        type_set = set(source_types)
        self.add_rule(PolicyRule(
            name=f"block_source_type:{'|'.join(sorted(type_set))}",
            condition=lambda ctx, s=type_set: ctx.source_type in s,
            verdict=PolicyVerdict.BLOCK,
            reason="source_type {ctx.source_type!r} is on the block list",
            priority=3,
            confidence=0.99,
        ))

    def human_review_category(self, *categories: str) -> None:
        cat_set = {c.lower() for c in categories}
        self.add_rule(PolicyRule(
            name=f"human_review_cat:{'|'.join(sorted(cat_set))}",
            condition=lambda ctx, c=cat_set: bool({x.lower() for x in ctx.categories} & c),
            verdict=PolicyVerdict.HUMAN_REVIEW,
            reason="category requires human review",
            priority=15,
            confidence=0.88,
        ))

    def quarantine_boundary(self, *boundaries: str) -> None:
        boundary_set = set(boundaries)
        self.add_rule(PolicyRule(
            name=f"quarantine_boundary:{'|'.join(sorted(boundary_set))}",
            condition=lambda ctx, b=boundary_set: ctx.boundary in b,
            verdict=PolicyVerdict.QUARANTINE,
            reason="boundary {ctx.boundary!r} is in quarantine list",
            priority=20,
            confidence=0.80,
        ))

    def allow_agent(self, *agent_ids: str) -> None:
        agent_set = set(agent_ids)
        self.add_rule(PolicyRule(
            name=f"allow_agent:{'|'.join(sorted(agent_set))}",
            condition=lambda ctx, a=agent_set: ctx.agent_id in a and ctx.risk_score < 40,
            verdict=PolicyVerdict.ALLOW,
            reason="trusted agent {ctx.agent_id!r} with low risk {ctx.risk_score}",
            priority=6,
            confidence=0.90,
        ))

    def decide(self, ctx: PolicyContext) -> PolicyDecision:
        floor = self._baseline_floor(ctx)
        for rule in self._sorted_rules(ctx):
            decision = rule.evaluate(ctx)
            if decision is None:
                continue
            decision = self._enforce_floor(ctx, decision, floor)
            if self._audit_log:
                logger.debug(
                    "PolicyEngine [%s/%s] -> %s (rule=%s, risk=%d)",
                    ctx.agent_id or "-",
                    ctx.boundary,
                    decision.verdict.value,
                    decision.matched_rule,
                    ctx.risk_score,
                )
            return decision
        return PolicyDecision(floor, "baseline floor fallback", "__baseline_floor__", ctx=ctx)

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
        risk = int(getattr(analysis, "risk_score", 0) or 0)
        raw_decision = str(getattr(analysis, "decision", "allow")).lower()
        if "block" in raw_decision:
            raw_decision = "block"
        elif "quarantine" in raw_decision:
            raw_decision = "quarantine"
        else:
            raw_decision = "allow"

        categories: List[str] = []
        for match in getattr(analysis, "threats", []) or []:
            category = getattr(getattr(match, "threat", None), "category", None)
            if category is not None:
                categories.append(str(getattr(category, "value", category)).lower().split(".")[-1])

        return self.decide(PolicyContext(
            content=content,
            risk_score=risk,
            threats=list(getattr(analysis, "threats", []) or []),
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
        ))

    def _profile_for_context(self, ctx: Optional[PolicyContext]) -> PolicyProfile:
        profile_name = self._profile_name
        if ctx is not None:
            profile_name = self._agent_profiles.get(ctx.agent_id) or self._tenant_profiles.get(ctx.tenant_id) or profile_name
        return _BUILT_IN_PROFILES.get(profile_name, _BUILT_IN_PROFILES["balanced"])

    def _sorted_rules(self, ctx: Optional[PolicyContext] = None) -> List[PolicyRule]:
        base_rules = self._profile_rules
        if ctx is not None:
            override = self._agent_profiles.get(ctx.agent_id) or self._tenant_profiles.get(ctx.tenant_id)
            if override and override != self._profile_name:
                base_rules = self._load_profile(override)
        return sorted(self._custom_rules + base_rules, key=lambda r: r.priority)

    def _baseline_floor(self, ctx: PolicyContext) -> PolicyVerdict:
        profile = self._profile_for_context(ctx)
        if ctx.canary_leaks > 0:
            return PolicyVerdict.BLOCK
        if ctx.analyzer_decision == "block":
            return PolicyVerdict.BLOCK
        if ctx.risk_score >= profile.extreme_risk_score:
            return PolicyVerdict.BLOCK
        if ctx.risk_score >= profile.block_risk_score:
            return PolicyVerdict.BLOCK
        if ctx.analyzer_decision == "quarantine":
            return PolicyVerdict.QUARANTINE
        if ctx.risk_score >= profile.quarantine_risk_score:
            return PolicyVerdict.SANITIZE if ctx.was_sanitized else PolicyVerdict.QUARANTINE
        return PolicyVerdict.ALLOW

    @staticmethod
    def _enforce_floor(ctx: PolicyContext, decision: PolicyDecision, floor: PolicyVerdict) -> PolicyDecision:
        if _VERDICT_RANK[floor] <= _VERDICT_RANK[decision.verdict]:
            return decision
        return PolicyDecision(
            verdict=floor,
            reason=f"security floor {floor.value} overrides rule {decision.matched_rule}: {decision.reason}",
            matched_rule=f"{decision.matched_rule}+security_floor",
            confidence=max(decision.confidence, 0.95),
            ctx=ctx,
        )

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def profiles(self) -> Dict[str, PolicyProfile]:
        return dict(_BUILT_IN_PROFILES)


_global_engine: Optional[PolicyEngine] = None
_global_lock = _threading.Lock()


def get_global_engine(**kwargs: Any) -> PolicyEngine:
    global _global_engine
    if _global_engine is None:
        with _global_lock:
            if _global_engine is None:
                _global_engine = PolicyEngine(**kwargs)
    return _global_engine


def reset_global_engine() -> None:
    global _global_engine
    with _global_lock:
        _global_engine = None


def verdict_to_enforcement_action(verdict: PolicyVerdict) -> str:
    return {
        PolicyVerdict.ALLOW: "allow",
        PolicyVerdict.SANITIZE: "sanitize",
        PolicyVerdict.QUARANTINE: "quarantine",
        PolicyVerdict.HUMAN_REVIEW: "quarantine",
        PolicyVerdict.BLOCK: "block",
    }[verdict]


def verdict_to_guard_decision(verdict: PolicyVerdict) -> str:
    return {
        PolicyVerdict.ALLOW: "allow",
        PolicyVerdict.SANITIZE: "allow_sanitized",
        PolicyVerdict.QUARANTINE: "quarantine",
        PolicyVerdict.HUMAN_REVIEW: "quarantine",
        PolicyVerdict.BLOCK: "block",
    }[verdict]


__all__ = [
    "PolicyEngine",
    "PolicyVerdict",
    "PolicyContext",
    "PolicyDecision",
    "PolicyRule",
    "PolicyProfile",
    "most_restrictive",
    "get_global_engine",
    "reset_global_engine",
    "verdict_to_enforcement_action",
    "verdict_to_guard_decision",
]
