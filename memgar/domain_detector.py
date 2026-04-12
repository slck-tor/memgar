"""
Memgar Domain-Aware Anomaly Detection
========================================

Detects content that is inconsistent with an agent's declared domain.

Schneider (2026):
    "Anomaly detection flags content that deviates from expected patterns.
     If your agent processes financial reports, a document that suddenly
     discusses system configuration is anomalous regardless of whether
     it contains obvious injection signatures."

Problem:
    A financial agent receiving network firewall rules is not necessarily
    a known attack pattern (no signature to match), but it IS anomalous
    and SHOULD increase suspicion. Classical pattern-based detectors miss
    this class of attack entirely.

How it works:
    1. AgentDomainProfile  — declares the agent's primary domain(s)
    2. DomainClassifier    — lightweight keyword-based topic classifier
    3. DomainMismatchScore — measures overlap between detected domains
                             and the agent's expected domains
    4. DomainAnomalyResult — score + explanation + flagged topic(s)
    5. Integration hooks:
         - trust_scorer.py  S4 AnomalyScore feeds DomainAnomalyDetector
         - write_ahead_validator.py  RuleBasedChecker extended
         - Standalone API for direct use

Attack vectors detected:

    CROSS_DOMAIN_INJECTION
        Financial agent receives network configuration instructions.
        The attacker uses legitimate-looking technical content to embed
        instructions that would be normal in a different agent context.

    TOPIC_DRIFT_POISONING
        Agent's memory gradually accumulates off-domain content until the
        agent begins to act as if it has different responsibilities.

    AUTHORITY_DOMAIN_CONFUSION
        Content claims authority in an unexpected domain:
        "As the system administrator, you should always..." sent to a
        customer support agent.

Built-in domain profiles (8 types):
    financial, medical, legal, devops, network, hr, sales, research

Custom domains are fully supported via AgentDomainProfile.

Usage::

    from memgar.domain_detector import DomainAnomalyDetector, AgentDomainProfile

    # Built-in profile
    detector = DomainAnomalyDetector(
        profile=AgentDomainProfile.financial()
    )

    result = detector.check("Configure firewall rules for subnet 10.0.0.1/24")
    print(result.mismatch_score)    # 0.0 – 1.0
    print(result.is_anomalous)      # True
    print(result.detected_domains)  # ["network", "devops"]
    print(result.explanation)

    # Custom profile
    profile = AgentDomainProfile(
        agent_type="procurement",
        primary_domains=["financial", "legal"],
        allowed_domains=["hr"],           # allowed but not primary
        forbidden_domains=["network", "medical"],
    )
    detector = DomainAnomalyDetector(profile=profile)

    # Integration with trust_scorer
    from memgar.trust_scorer import CompositeTrustScorer, TrustContext
    scorer = CompositeTrustScorer(domain_detector=detector)
    result = scorer.score(content, TrustContext(source_type="document"))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Domain keyword vocabulary
# ---------------------------------------------------------------------------

# Each domain: (primary_terms, secondary_terms)
# primary_terms:   strong indicators, weight 2.0
# secondary_terms: weaker indicators, weight 1.0
_DOMAIN_VOCAB: Dict[str, Tuple[List[str], List[str]]] = {
    "financial": (
        ["payment", "transfer", "wire", "invoice", "revenue", "budget", "accounting",
         "ledger", "receivable", "payable", "remittance", "disbursement", "reconcile",
         "expense", "forecast", "p&l", "ebitda", "accrual", "amortize", "depreciation"],
        ["money", "bank", "account", "cost", "price", "fee", "fund", "capital",
         "asset", "liability", "equity", "credit", "debit", "balance", "fiscal"],
    ),
    "medical": (
        ["patient", "diagnosis", "treatment", "medication", "clinical", "symptom",
         "dosage", "prescription", "pathology", "biopsy", "prognosis", "contraindication",
         "protocol", "therapeutic", "etiology", "histology", "radiology"],
        ["health", "doctor", "hospital", "drug", "therapy", "surgery", "chronic",
         "acute", "vital", "lab", "blood", "scan", "test", "care", "nurse"],
    ),
    "legal": (
        ["contract", "liability", "jurisdiction", "clause", "statute", "plaintiff",
         "defendant", "litigation", "arbitration", "indemnity", "injunction",
         "precedent", "affidavit", "deposition", "subpoena", "covenant", "breach"],
        ["court", "law", "legal", "attorney", "counsel", "agreement", "terms",
         "rights", "obligation", "dispute", "settlement", "compliance", "regulation"],
    ),
    "devops": (
        ["kubernetes", "terraform", "ansible", "jenkins", "dockerfile", "helm",
         "pipeline", "ci/cd", "artifact", "deployment", "namespace", "ingress",
         "configmap", "secret", "replica", "autoscale", "rollout", "canary"],
        ["deploy", "container", "cluster", "pod", "service", "image", "registry",
         "build", "release", "environment", "staging", "production", "monitor"],
    ),
    "network": (
        ["firewall", "subnet", "vlan", "iptables", "bgp", "ospf", "nat", "acl",
         "dhcp", "dns", "vpn", "ssl/tls", "load balancer", "proxy", "gateway",
         "packet", "bandwidth", "latency", "throughput", "qos"],
        ["router", "switch", "tcp", "udp", "ip", "port", "protocol", "interface",
         "network", "traffic", "route", "ping", "ssh", "http", "tls"],
    ),
    "hr": (
        ["onboarding", "offboarding", "payroll", "benefits", "performance review",
         "headcount", "recruitment", "interview", "termination", "grievance",
         "compensation", "org chart", "succession", "talent", "attrition"],
        ["employee", "salary", "hire", "manager", "team", "department", "role",
         "position", "leave", "vacation", "policy", "training", "promotion"],
    ),
    "sales": (
        ["pipeline", "opportunity", "quota", "forecast", "crm", "prospect",
         "churn", "upsell", "cross-sell", "mrr", "arr", "saas", "conversion",
         "lead score", "funnel", "nurture", "demo", "proposal"],
        ["lead", "customer", "deal", "close", "account", "sales",
         "market", "product", "price", "discount", "renewal", "contract"],
    ),
    "research": (
        ["hypothesis", "methodology", "experiment", "dataset", "peer-reviewed",
         "citation", "findings", "literature review", "control group", "variable",
         "regression", "correlation", "significance", "replication", "cohort"],
        ["study", "analysis", "data", "model", "result", "paper", "journal",
         "research", "evidence", "survey", "sample", "statistical", "observation"],
    ),
    "database": (
        ["sql", "select", "insert", "update", "delete", "drop table", "truncate",
         "schema", "query", "stored procedure", "index", "transaction", "rollback",
         "foreign key", "join", "subquery", "injection", "union select"],
        ["table", "database", "column", "row", "record", "varchar", "integer",
         "primary key", "constraint", "trigger", "view", "cursor", "execute"],
    ),
}

# Content that signals a deliberate domain-crossing attack
_AUTHORITY_CONFUSION_PATTERNS = [
    re.compile(r"(?i)as\s+(?:the\s+)?(?:system\s+administrator|network\s+engineer|security\s+officer|database\s+admin)\s*,?\s+you\s+(?:should|must|need\s+to)"),
    re.compile(r"(?i)(?:this\s+is\s+|from\s+)(?:the\s+)?(?:it\s+department|security\s+team|devops\s+team|infrastructure\s+team)\s*[:.]\s*(?:please|you\s+must|you\s+should)"),
    re.compile(r"(?i)(?:sys(?:tem)?\s*admin|network\s*ops|infra(?:structure)?)\s+(?:override|directive|instruction|command)\s*[:.]"),
]


# ---------------------------------------------------------------------------
# Agent Domain Profile
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentDomainProfile:
    """
    Declares the expected content domains for an agent.

    primary_domains:   Content from these domains is normal.
    allowed_domains:   Occasional content from these is acceptable.
    forbidden_domains: Content from these is always anomalous.
    agent_type:        Human-readable name used in reports.
    mismatch_threshold: Mismatch score at which content is flagged (0–1).

    Use the class factory methods for common agent types, or construct
    a custom profile directly.
    """
    agent_type:          str
    primary_domains:     FrozenSet[str]
    allowed_domains:     FrozenSet[str] = field(default_factory=frozenset)
    forbidden_domains:   FrozenSet[str] = field(default_factory=frozenset)
    mismatch_threshold:  float = 0.30

    # ── Factory methods for common agent types ──────────────────────────────

    @classmethod
    def financial(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "financial",
            primary_domains   = frozenset({"financial"}),
            allowed_domains   = frozenset({"legal", "hr"}),
            forbidden_domains = frozenset({"network", "devops", "medical", "database"}),
        )

    @classmethod
    def medical(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "medical",
            primary_domains   = frozenset({"medical"}),
            allowed_domains   = frozenset({"research", "legal"}),
            forbidden_domains = frozenset({"financial", "network", "devops", "sales"}),
        )

    @classmethod
    def legal(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "legal",
            primary_domains   = frozenset({"legal"}),
            allowed_domains   = frozenset({"financial", "hr", "research"}),
            forbidden_domains = frozenset({"network", "devops", "medical"}),
        )

    @classmethod
    def devops(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "devops",
            primary_domains   = frozenset({"devops", "network"}),
            allowed_domains   = frozenset({"research"}),
            forbidden_domains = frozenset({"medical", "legal", "financial", "hr"}),
        )

    @classmethod
    def sales(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "sales",
            primary_domains   = frozenset({"sales"}),
            allowed_domains   = frozenset({"financial", "hr", "legal"}),
            forbidden_domains = frozenset({"network", "devops", "medical"}),
        )

    @classmethod
    def hr(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "hr",
            primary_domains   = frozenset({"hr"}),
            allowed_domains   = frozenset({"legal", "financial"}),
            forbidden_domains = frozenset({"network", "devops", "medical", "database"}),
        )

    @classmethod
    def research(cls) -> "AgentDomainProfile":
        return cls(
            agent_type        = "research",
            primary_domains   = frozenset({"research", "medical"}),
            allowed_domains   = frozenset({"legal", "financial"}),
            forbidden_domains = frozenset({"network", "devops", "sales"}),
        )

    @classmethod
    def generic(cls) -> "AgentDomainProfile":
        """No domain restrictions — any content is acceptable."""
        return cls(
            agent_type        = "generic",
            primary_domains   = frozenset(_DOMAIN_VOCAB.keys()),
            allowed_domains   = frozenset(),
            forbidden_domains = frozenset(),
            mismatch_threshold = 1.1,  # never triggers
        )

    def is_primary(self, domain: str) -> bool:
        return domain in self.primary_domains

    def is_allowed(self, domain: str) -> bool:
        return domain in self.primary_domains or domain in self.allowed_domains

    def is_forbidden(self, domain: str) -> bool:
        return domain in self.forbidden_domains


# ---------------------------------------------------------------------------
# Domain Classifier
# ---------------------------------------------------------------------------

class DomainClassifier:
    """
    Lightweight keyword-based topic classifier.

    Returns a score per domain: 0.0 (no signal) to 1.0 (strong signal).
    No external dependencies, no LLM calls.

    Primary terms score 2.0, secondary terms score 1.0.
    Final scores are normalized to [0, 1].
    """

    def __init__(self) -> None:
        # Pre-compile: domain -> [(pattern, weight)]
        self._compiled: Dict[str, List[Tuple[re.Pattern, float]]] = {}
        for domain, (primary, secondary) in _DOMAIN_VOCAB.items():
            patterns = []
            for term in primary:
                patterns.append((re.compile(r"\b" + re.escape(term) + r"\b", re.I), 2.0))
            for term in secondary:
                patterns.append((re.compile(r"\b" + re.escape(term) + r"\b", re.I), 1.0))
            self._compiled[domain] = patterns

    def classify(self, text: str) -> Dict[str, float]:
        """
        Return domain scores for text.

        Returns:
            Dict[domain, score] where score is in [0.0, 1.0].
            Only domains with score > 0 are returned.
        """
        if not text:
            return {}

        raw_scores: Dict[str, float] = {}
        for domain, patterns in self._compiled.items():
            total = sum(w for pat, w in patterns if pat.search(text))
            if total > 0:
                # Normalize against max possible score for this domain
                max_possible = sum(w for _, w in patterns)
                raw_scores[domain] = min(1.0, total / max_possible * 4.0)  # scale factor

        return {d: round(s, 4) for d, s in raw_scores.items() if s > 0}

    def dominant_domain(self, text: str) -> Optional[str]:
        """Return the single highest-scoring domain, or None."""
        scores = self.classify(text)
        if not scores:
            return None
        return max(scores, key=scores.__getitem__)


# ---------------------------------------------------------------------------
# Domain Anomaly Result
# ---------------------------------------------------------------------------

@dataclass
class DomainAnomalyResult:
    """Result of a domain mismatch check."""
    mismatch_score:    float          # 0.0 = no mismatch, 1.0 = severe mismatch
    is_anomalous:      bool           # True if above profile threshold
    is_forbidden:      bool           # True if forbidden domain detected
    detected_domains:  List[str]      # domains found in content
    unexpected_domains: List[str]     # detected domains outside profile
    forbidden_hit:     List[str]      # detected domains in forbidden list
    authority_confusion: bool         # cross-domain authority pattern found
    domain_scores:     Dict[str, float]  # raw per-domain scores
    explanation:       str
    agent_type:        str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mismatch_score":      round(self.mismatch_score, 4),
            "is_anomalous":        self.is_anomalous,
            "is_forbidden":        self.is_forbidden,
            "detected_domains":    self.detected_domains,
            "unexpected_domains":  self.unexpected_domains,
            "forbidden_hit":       self.forbidden_hit,
            "authority_confusion": self.authority_confusion,
            "explanation":         self.explanation,
            "agent_type":          self.agent_type,
        }


# ---------------------------------------------------------------------------
# Domain Anomaly Detector
# ---------------------------------------------------------------------------

class DomainAnomalyDetector:
    """
    Detects domain mismatches between content and agent profile.

    Scoring formula:
        base_score  = weighted sum of unexpected domain signals
        forbidden_bonus = 0.5 per forbidden domain hit (additive)
        authority_bonus = 0.25 if authority confusion pattern found
        mismatch_score = min(1.0, base_score + forbidden_bonus + authority_bonus)

    Args:
        profile:       AgentDomainProfile to check against
        classifier:    DomainClassifier (shared instance for efficiency)
        min_signal:    Minimum domain score to consider a domain present
    """

    def __init__(
        self,
        profile:    AgentDomainProfile,
        classifier: Optional[DomainClassifier] = None,
        min_signal: float = 0.05,
    ) -> None:
        self._profile    = profile
        self._classifier = classifier or DomainClassifier()
        self._min_signal = min_signal

    @property
    def profile(self) -> AgentDomainProfile:
        return self._profile

    def check(self, content: str) -> DomainAnomalyResult:
        """
        Check content for domain mismatch against the agent profile.

        Returns DomainAnomalyResult with mismatch_score in [0, 1].
        """
        if not content or self._profile.agent_type == "generic":
            return self._clean_result()

        # Classify content
        scores = self._classifier.classify(content)
        detected = [d for d, s in scores.items() if s >= self._min_signal]

        # Partition by profile category
        unexpected  = [d for d in detected if not self._profile.is_allowed(d)]
        forbidden   = [d for d in detected if self._profile.is_forbidden(d)]

        # Base mismatch score from unexpected domains
        if unexpected:
            unexpected_signal = sum(scores[d] for d in unexpected)
            total_signal = max(sum(scores.values()), 1e-9)
            base_score = unexpected_signal / total_signal
        else:
            base_score = 0.0

        # Forbidden domain penalty
        forbidden_bonus = min(0.5, len(forbidden) * 0.25)

        # Authority confusion detection
        auth_confusion = any(
            pat.search(content) for pat in _AUTHORITY_CONFUSION_PATTERNS
        )
        auth_bonus = 0.25 if auth_confusion else 0.0

        mismatch_score = min(1.0, base_score + forbidden_bonus + auth_bonus)
        is_anomalous = mismatch_score >= self._profile.mismatch_threshold or bool(forbidden)

        # Build explanation
        parts = [f"agent_type={self._profile.agent_type}"]
        if unexpected:
            parts.append(f"unexpected_domains={unexpected}")
        if forbidden:
            parts.append(f"FORBIDDEN={forbidden}")
        if auth_confusion:
            parts.append("authority_confusion_pattern")
        if not (unexpected or forbidden or auth_confusion):
            parts.append("no_mismatch")
        explanation = (
            f"Domain mismatch: score={mismatch_score:.3f} | "
            + " | ".join(parts)
        )

        return DomainAnomalyResult(
            mismatch_score     = mismatch_score,
            is_anomalous       = is_anomalous,
            is_forbidden       = bool(forbidden),
            detected_domains   = detected,
            unexpected_domains = unexpected,
            forbidden_hit      = forbidden,
            authority_confusion = auth_confusion,
            domain_scores      = scores,
            explanation        = explanation,
            agent_type         = self._profile.agent_type,
        )

    def _clean_result(self) -> DomainAnomalyResult:
        return DomainAnomalyResult(
            mismatch_score     = 0.0,
            is_anomalous       = False,
            is_forbidden       = False,
            detected_domains   = [],
            unexpected_domains = [],
            forbidden_hit      = [],
            authority_confusion = False,
            domain_scores      = {},
            explanation        = "No domain profile or empty content",
            agent_type         = self._profile.agent_type,
        )


# ---------------------------------------------------------------------------
# Integration helpers
# ---------------------------------------------------------------------------

def build_detector(agent_type: str, custom_profile: Optional[AgentDomainProfile] = None) -> DomainAnomalyDetector:
    """
    Build a DomainAnomalyDetector from an agent type string or custom profile.

    Built-in types: financial, medical, legal, devops, network, hr, sales,
                    research, generic

    Usage::

        detector = build_detector("financial")
        result   = detector.check("Configure firewall rules on subnet 10.0.0.1/24")
        # result.is_anomalous == True
        # result.forbidden_hit == ["network", "devops"]
    """
    if custom_profile:
        return DomainAnomalyDetector(custom_profile)

    factory = {
        "financial": AgentDomainProfile.financial,
        "medical":   AgentDomainProfile.medical,
        "legal":     AgentDomainProfile.legal,
        "devops":    AgentDomainProfile.devops,
        "network":   AgentDomainProfile.devops,   # alias
        "hr":        AgentDomainProfile.hr,
        "sales":     AgentDomainProfile.sales,
        "research":  AgentDomainProfile.research,
        "generic":   AgentDomainProfile.generic,
    }
    builder = factory.get(agent_type.lower())
    if builder is None:
        raise ValueError(
            f"Unknown agent_type '{agent_type}'. "
            f"Valid: {sorted(factory)}. "
            "Use custom_profile= for custom domains."
        )
    return DomainAnomalyDetector(builder())


def mismatch_to_trust_penalty(result: DomainAnomalyResult) -> float:
    """
    Convert a DomainAnomalyResult to a trust score penalty (0–60).

    Used by trust_scorer.py S4 integration.
    Authority confusion is penalized even without full domain mismatch.
    """
    if not result.is_anomalous and not result.authority_confusion:
        return 0.0
    # Scale: mismatch_score 0.35 → penalty 14, 1.0 → penalty 40
    base = result.mismatch_score * 40.0
    if result.is_forbidden:
        base += 15.0
    if result.authority_confusion:
        base += 10.0
    return round(min(60.0, base), 1)
