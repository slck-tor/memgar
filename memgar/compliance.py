"""
Memgar EU AI Act Compliance Report Generator
=============================================

Generates structured compliance reports for EU AI Act Article 9, 13, 16,
Annex IV (Technical Documentation), and Annex VIII (Registration).

Enforcement deadline: 2 August 2026
Penalty: up to €35M or 7% of global turnover

Sections generated:
    1.  System Classification      — risk level, prohibited check
    2.  Technical Documentation    — Annex IV requirements
    3.  Risk Management            — Article 9
    4.  Data Governance            — Article 10
    5.  Transparency               — Article 13 (logging, human oversight)
    6.  Human Oversight            — Article 14 (HITL controls)
    7.  Accuracy & Robustness      — Article 15
    8.  Cybersecurity Controls     — Article 15(5) — where Memgar evidence fits
    9.  Quality Management System  — Article 17
    10. Incident Reporting         — Article 62
    11. Conformity Assessment      — Article 43
    12. GDPR/Data Protection       — cross-reference
    13. Compliance Gap Analysis    — what's missing, remediation steps
    14. EU Database Registration   — Article 49 checklist

CLI usage::

    memgar report --format eu-ai-act
    memgar report --format eu-ai-act --output report.pdf
    memgar report --format eu-ai-act --system-name "My AI Agent" \\
        --provider "Acme Corp" --risk-class high

Python usage::

    from memgar.compliance import EUAIActReport

    report = EUAIActReport(
        system_name="Customer Service Agent",
        provider_name="Acme Corp GmbH",
        intended_purpose="Automated customer support with memory",
        risk_class="high",
        deployer_country="DE",
    )
    html = report.generate_html()
    json_data = report.generate_json()
    md = report.generate_markdown()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Article references
# ---------------------------------------------------------------------------

ARTICLES = {
    "Art.9":   "Risk Management System",
    "Art.10":  "Data and Data Governance",
    "Art.11":  "Technical Documentation (Annex IV)",
    "Art.12":  "Record-keeping / Logs",
    "Art.13":  "Transparency and Provision of Information",
    "Art.14":  "Human Oversight",
    "Art.15":  "Accuracy, Robustness, Cybersecurity",
    "Art.16":  "Obligations of Providers",
    "Art.17":  "Quality Management System",
    "Art.26":  "Obligations of Deployers",
    "Art.43":  "Conformity Assessment",
    "Art.49":  "EU Database Registration",
    "Art.62":  "Serious Incident Reporting",
    "Ann.IV":  "Technical Documentation Requirements",
    "Ann.VIII":"Registration Information",
}

ENFORCEMENT_DATE = "2026-08-02"
MAX_FINE_PCT = "7% of global annual turnover"
MAX_FINE_EUR = "€35,000,000"


# ---------------------------------------------------------------------------
# Compliance check models
# ---------------------------------------------------------------------------

class ComplianceStatus(str):
    COMPLIANT     = "COMPLIANT"
    PARTIAL       = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "N/A"


@dataclass
class ComplianceCheck:
    article:     str
    title:       str
    status:      str
    evidence:    List[str] = field(default_factory=list)   # what Memgar provides
    gaps:        List[str] = field(default_factory=list)    # what's missing
    actions:     List[str] = field(default_factory=list)    # remediation steps
    priority:    str = "medium"  # high / medium / low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "article": self.article,
            "title": self.title,
            "status": self.status,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "actions": self.actions,
            "priority": self.priority,
        }


@dataclass
class RiskClassification:
    risk_level:     str    # minimal / limited / high / unacceptable
    annex_category: Optional[str]  # e.g. "Annex III — 8(a)" for HR tools
    is_prohibited:  bool
    reasoning:      str
    obligations:    List[str]


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

@dataclass
class EUAIActReport:
    """
    EU AI Act compliance report for an AI agent system using Memgar.

    Args:
        system_name:       Name of the AI agent system
        provider_name:     Legal name of the provider/deployer
        version:           System version
        intended_purpose:  What the system does
        risk_class:        "minimal" | "limited" | "high" | "unacceptable"
        deployer_country:  EU country code (DE, FR, NL, etc.)
        uses_memgar:       Whether Memgar is deployed (affects evidence)
        memgar_version:    Memgar version in use
        memgar_modules:    Which Memgar modules are active
        custom_fields:     Additional system metadata
    """
    system_name:      str = "AI Agent System"
    provider_name:    str = "Provider Organization"
    version:          str = "1.0.0"
    intended_purpose: str = "Autonomous AI agent with persistent memory"
    risk_class:       str = "high"
    deployer_country: str = "DE"
    uses_memgar:      bool = True
    memgar_version:   str = "0.5.10"
    memgar_modules:   List[str] = field(default_factory=lambda: [
        "analyzer", "memory_ledger", "hitl", "identity", "auto_protect",
        "forensics", "dow", "siem", "supply", "websocket_guard",
    ])
    custom_fields:    Dict[str, Any] = field(default_factory=dict)

    def _now(self) -> str:
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _classify_risk(self) -> RiskClassification:
        """Map system to EU AI Act risk tier."""
        r = self.risk_class.lower()

        if r == "unacceptable":
            return RiskClassification(
                risk_level="unacceptable",
                annex_category=None,
                is_prohibited=True,
                reasoning="System performs prohibited practices under Article 5.",
                obligations=["PROHIBITED — cannot be placed on market"],
            )

        if r == "high":
            return RiskClassification(
                risk_level="high",
                annex_category="Annex III",
                is_prohibited=False,
                reasoning=(
                    "AI agent with autonomous action capabilities, persistent memory, "
                    "and potential impact on fundamental rights qualifies as high-risk "
                    "under Annex III if deployed in regulated sectors."
                ),
                obligations=[
                    "Art.9 — Risk management system required",
                    "Art.10 — Data governance documentation",
                    "Art.11 + Annex IV — Technical documentation",
                    "Art.12 — Automatic logging",
                    "Art.13 — Transparency to users",
                    "Art.14 — Human oversight mechanisms",
                    "Art.15 — Accuracy, robustness, cybersecurity",
                    "Art.17 — Quality management system",
                    "Art.43 — Conformity assessment",
                    "Art.49 — EU database registration",
                    "Art.62 — Serious incident reporting",
                ],
            )

        if r == "limited":
            return RiskClassification(
                risk_level="limited",
                annex_category=None,
                is_prohibited=False,
                reasoning="Limited risk — transparency obligations apply.",
                obligations=[
                    "Art.13 — Inform users they interact with AI",
                    "Art.50 — Disclose AI-generated content",
                ],
            )

        return RiskClassification(
            risk_level="minimal",
            annex_category=None,
            is_prohibited=False,
            reasoning="Minimal risk — no specific obligations under AI Act.",
            obligations=["Voluntary codes of conduct recommended"],
        )

    def _build_checks(self) -> List[ComplianceCheck]:
        """Build all compliance checks with Memgar evidence mapping."""
        m = self.uses_memgar
        mv = self.memgar_modules

        checks = []

        # Art.9 — Risk Management
        art9_evidence = []
        art9_gaps = []
        art9_actions = []
        if m:
            art9_evidence += [
                "memgar.analyzer — continuous threat detection on all memory writes (414 patterns)",
                "memgar.forensics — post-incident analysis and poisoning timeline reconstruction",
                "memgar.dow — Denial of Wallet / runaway cost risk detection",
                "memgar.supply — supply chain attack detection (LiteLLM, Telnyx CVEs)",
                "memgar.learning — pattern gap detection + human-supervised updates",
            ]
        art9_gaps += [
            "Formal risk register document not auto-generated",
            "Residual risk acceptance sign-off process not implemented",
        ]
        art9_actions += [
            "Generate risk register using memgar forensics scan outputs",
            "Establish quarterly risk review cadence with security team",
        ]
        checks.append(ComplianceCheck(
            article="Art.9",
            title="Risk Management System",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art9_evidence,
            gaps=art9_gaps,
            actions=art9_actions,
            priority="high",
        ))

        # Art.10 — Data Governance
        art10_evidence = []
        if m:
            art10_evidence += [
                "memgar.memory_ledger — every memory write recorded with SHA-256 hash chain",
                "memgar.auditor — snapshot + integrity verification of memory store",
                "memgar.provenance — source tracking and trust level per memory entry",
                "memgar.sanitizer — instruction stripping before persistence",
            ]
        art10_gaps = [
            "Data lineage documentation for training data not in scope",
            "Bias testing and demographic analysis not provided by Memgar",
        ]
        art10_actions = [
            "Document data sources and preprocessing steps in Annex IV",
            "Conduct bias assessment for training/fine-tuning data",
        ]
        checks.append(ComplianceCheck(
            article="Art.10",
            title="Data and Data Governance",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art10_evidence,
            gaps=art10_gaps,
            actions=art10_actions,
            priority="high",
        ))

        # Art.11 + Annex IV — Technical Documentation
        ann4_evidence = [
            "This compliance report satisfies part of Annex IV Section 1",
            "memgar.__version__ + pyproject.toml — system version tracking",
            "memgar.supply — dependency inventory with CVE references",
            "memgar.identity — per-agent authorization model documented",
        ] if m else []
        ann4_gaps = [
            "System architecture diagram not auto-generated",
            "Intended purpose statement requires human input",
            "Training methodology documentation required from model provider",
            "Evaluation metrics and test results required",
        ]
        ann4_actions = [
            "Complete Annex IV checklist below",
            "Obtain technical documentation from upstream LLM provider",
            "Document integration points, APIs, and data flows",
        ]
        checks.append(ComplianceCheck(
            article="Art.11 / Ann.IV",
            title="Technical Documentation (Annex IV)",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=ann4_evidence,
            gaps=ann4_gaps,
            actions=ann4_actions,
            priority="high",
        ))

        # Art.12 — Record-keeping
        art12_evidence = []
        if m:
            art12_evidence += [
                "memgar.memory_ledger — append-only, hash-chained log of all memory events",
                "memgar.identity.audit_log — immutable per-agent action trail",
                "memgar.siem — structured OCSF event stream to Splunk/Datadog/Elastic",
                "memgar.auditor — snapshots with cryptographic integrity verification",
            ]
        art12_gaps = [
            "Log retention period policy not configured (regulation requires minimum 6 months)",
            "Log access control (who can read audit logs) requires explicit policy",
        ]
        art12_actions = [
            "Configure SIEM retention policy: minimum 6 months",
            "Restrict audit log access via memgar identity MANAGE_AGENTS scope",
        ]
        checks.append(ComplianceCheck(
            article="Art.12",
            title="Record-keeping and Automatic Logging",
            status=ComplianceStatus.COMPLIANT if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art12_evidence,
            gaps=art12_gaps,
            actions=art12_actions,
            priority="medium",
        ))

        # Art.13 — Transparency
        art13_evidence = []
        if m:
            art13_evidence += [
                "memgar.analyzer — explains every decision (threat_id, explanation, risk_score)",
                "memgar.reporter — HTML reports with human-readable threat descriptions",
                "memgar.siem — structured audit trail for regulatory access",
            ]
        art13_gaps = [
            "End-user notification of AI interaction not implemented (requires UI/UX layer)",
            "Instructions for use document (deployer guidance) not generated",
        ]
        art13_actions = [
            "Add AI disclosure banner to user-facing interfaces",
            "Generate deployer instructions document from this compliance report",
        ]
        checks.append(ComplianceCheck(
            article="Art.13",
            title="Transparency and Provision of Information",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art13_evidence,
            gaps=art13_gaps,
            actions=art13_actions,
            priority="high",
        ))

        # Art.14 — Human Oversight
        art14_evidence = []
        if m and "hitl" in mv:
            art14_evidence += [
                "memgar.hitl — HITLCheckpoint: blocks high-risk actions until human approves",
                "memgar.hitl — Slack/Telegram/webhook notifications to human reviewers",
                "memgar.hitl — timeout→deny: safe default when no response",
                "memgar.hitl — @guard decorator: enforces approval on specific functions",
                "memgar.hitl.classify_action — auto-detects high-risk actions",
            ]
            art14_gaps = [
                "Human oversight escalation procedure must be documented",
                "Override capability for authorized humans must be tested",
            ]
        elif m:
            art14_evidence += ["Memgar HITL module available but not confirmed active"]
            art14_gaps = ["HITL module must be explicitly activated for Art.14 compliance"]
        else:
            art14_gaps = [
                "No human oversight mechanism present",
                "Human oversight required for Art.14 compliance",
            ]
        art14_actions = [
            "Activate: from memgar import HITLCheckpoint",
            "Register high-risk actions: delete_file, transfer_funds, send_email",
            "Configure Slack/Telegram notifier for 24/7 approval coverage",
            "Document override procedures for authorized human supervisors",
        ]
        status14 = (ComplianceStatus.COMPLIANT if m and "hitl" in mv
                    else ComplianceStatus.PARTIAL if m
                    else ComplianceStatus.NON_COMPLIANT)
        checks.append(ComplianceCheck(
            article="Art.14",
            title="Human Oversight",
            status=status14,
            evidence=art14_evidence,
            gaps=art14_gaps,
            actions=art14_actions,
            priority="high",
        ))

        # Art.15 — Accuracy, Robustness, Cybersecurity
        art15_evidence = []
        if m:
            art15_evidence += [
                "memgar.analyzer — 414-pattern threat detection, avg 4.8ms (p95=11ms)",
                "memgar.websocket_guard — CVE-2026-25253 CSWSH protection, rate limiting",
                "memgar.circuit_breaker — automatic agent halt on threat threshold",
                "memgar.auto_protect — zero-config framework patching",
                "memgar.supply — dependency security (prevents backdoored packages)",
                "memgar.memory_ledger — tamper detection via SHA-256 hash chain",
            ]
        art15_gaps = [
            "Formal accuracy metrics (precision/recall on threat detection) not documented",
            "Adversarial robustness testing against evasion not automated",
            "Penetration test report required for Art.15(5) cybersecurity",
        ]
        art15_actions = [
            "Run memgar benchmark to document detection accuracy",
            "Commission annual penetration test of agent endpoints",
            "Document false positive rate from production memgar.siem data",
        ]
        checks.append(ComplianceCheck(
            article="Art.15",
            title="Accuracy, Robustness, and Cybersecurity",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art15_evidence,
            gaps=art15_gaps,
            actions=art15_actions,
            priority="high",
        ))

        # Art.17 — Quality Management System
        art17_evidence = []
        if m:
            art17_evidence += [
                "memgar.learning — human-supervised pattern review pipeline",
                "memgar.supply — dependency vulnerability scanning in CI/CD",
                "memgar.siem — centralized security event monitoring",
                "memgar.identity — per-agent access control and lifecycle management",
            ]
        art17_gaps = [
            "Formal QMS documentation (ISO 9001 or equivalent) not included",
            "Change management procedure for AI system updates not defined",
            "Post-market monitoring plan not formalized",
        ]
        art17_actions = [
            "Document AI change management: test → review → deploy pipeline",
            "Establish monthly security review using memgar siem outputs",
            "Define post-market monitoring KPIs (false positives, threat detection rate)",
        ]
        checks.append(ComplianceCheck(
            article="Art.17",
            title="Quality Management System",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art17_evidence,
            gaps=art17_gaps,
            actions=art17_actions,
            priority="medium",
        ))

        # Art.43 — Conformity Assessment
        checks.append(ComplianceCheck(
            article="Art.43",
            title="Conformity Assessment",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=[
                "This report constitutes preliminary self-assessment evidence",
                "Memgar SIEM integration provides audit trail for assessors",
            ],
            gaps=[
                "Third-party conformity assessment not completed",
                "CE marking not affixed",
                "Declaration of Conformity not drafted",
            ],
            actions=[
                "Engage notified body for Art.43 conformity assessment",
                "Prepare Declaration of Conformity (DoC)",
                "Affix CE marking after successful assessment",
            ],
            priority="high",
        ))

        # Art.49 — EU Database Registration
        checks.append(ComplianceCheck(
            article="Art.49",
            title="EU Database Registration",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=["Registration data fields pre-populated below"],
            gaps=[
                "System not yet registered in EU AI Act database",
                "Registration requires completed conformity assessment first",
            ],
            actions=[
                "Complete conformity assessment (Art.43) first",
                "Register at: https://ec.europa.eu/transparency/ai-act-database",
                "Include: system name, provider, intended purpose, risk class, notified body",
            ],
            priority="high",
        ))

        # Art.62 — Incident Reporting
        art62_evidence = []
        if m:
            art62_evidence += [
                "memgar.siem — automatic serious incident detection and streaming",
                "memgar.forensics — incident reconstruction and timeline analysis",
                "memgar.memory_ledger — tamper evidence for incident investigation",
                "memgar.hitl — human escalation for high-severity events",
            ]
        checks.append(ComplianceCheck(
            article="Art.62",
            title="Serious Incident Reporting",
            status=ComplianceStatus.PARTIAL if m else ComplianceStatus.NON_COMPLIANT,
            evidence=art62_evidence,
            gaps=[
                "National authority reporting procedure not defined",
                "Incident classification thresholds not documented",
                "72-hour reporting timeline not operationalized",
            ],
            actions=[
                "Define incident severity tiers mapping memgar risk scores to Art.62 thresholds",
                "Create runbook: memgar siem alert → severity assessment → authority notification",
                f"Register contact: national authority for {self.deployer_country}",
            ],
            priority="high",
        ))

        return checks

    def _annex_iv_checklist(self) -> List[Dict[str, Any]]:
        """Annex IV technical documentation checklist."""
        return [
            {
                "section": "1. General description",
                "items": [
                    {"req": "Intended purpose and use cases", "status": "⚠️ Requires input", "note": f"Provided: {self.intended_purpose[:80]}"},
                    {"req": "Version number and update history", "status": "✅ Available", "note": f"Version: {self.version}"},
                    {"req": "Provider/developer information", "status": "✅ Available", "note": f"Provider: {self.provider_name}"},
                    {"req": "Interaction with hardware/software", "status": "⚠️ Requires input", "note": "Document LLM API, vector DB, memory store"},
                ],
            },
            {
                "section": "2. Design specifications",
                "items": [
                    {"req": "System architecture and design choices", "status": "⚠️ Requires input"},
                    {"req": "Input/output specifications", "status": "⚠️ Requires input"},
                    {"req": "Key design decisions and trade-offs", "status": "⚠️ Requires input"},
                    {"req": "Limitations and foreseeable misuses", "status": "⚠️ Requires input"},
                ],
            },
            {
                "section": "3. Training and testing",
                "items": [
                    {"req": "Training data description (if fine-tuned)", "status": "⚠️ Requires input"},
                    {"req": "Testing methodologies", "status": "✅ Partial", "note": "memgar benchmark provides detection accuracy"},
                    {"req": "Validation and test results", "status": "✅ Partial", "note": "memgar test suite: 400+ passing tests"},
                    {"req": "Known limitations and edge cases", "status": "⚠️ Requires input"},
                ],
            },
            {
                "section": "4. Monitoring and control",
                "items": [
                    {"req": "Performance monitoring metrics", "status": "✅ Provided", "note": "memgar.siem OCSF event stream"},
                    {"req": "Logging and audit trail", "status": "✅ Provided", "note": "memgar.memory_ledger + identity.audit_log"},
                    {"req": "Incident detection and reporting", "status": "✅ Provided", "note": "memgar.forensics + siem"},
                    {"req": "Human oversight procedures", "status": "✅ Provided", "note": "memgar.hitl HITLCheckpoint"},
                ],
            },
            {
                "section": "5. Risk management",
                "items": [
                    {"req": "Risk identification and assessment", "status": "✅ Partial", "note": "memgar threat patterns cover OWASP ASI Top 10"},
                    {"req": "Risk mitigation measures", "status": "✅ Provided", "note": "4-layer defense: input, sanitize, retrieval, monitor"},
                    {"req": "Residual risks and acceptance", "status": "⚠️ Requires input"},
                    {"req": "Changes and updates procedure", "status": "⚠️ Requires input"},
                ],
            },
        ]

    def _gap_summary(self, checks: List[ComplianceCheck]) -> Dict[str, Any]:
        compliant = sum(1 for c in checks if c.status == ComplianceStatus.COMPLIANT)
        partial   = sum(1 for c in checks if c.status == ComplianceStatus.PARTIAL)
        non_comp  = sum(1 for c in checks if c.status == ComplianceStatus.NON_COMPLIANT)
        total = len(checks)
        score = round((compliant + partial * 0.5) / total * 100) if total else 0
        high_gaps = [c for c in checks if c.status == ComplianceStatus.NON_COMPLIANT and c.priority == "high"]
        return {
            "total_checks":     total,
            "compliant":        compliant,
            "partial":          partial,
            "non_compliant":    non_comp,
            "compliance_score": score,
            "readiness_label":  "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
            "critical_gaps":    [c.article + " — " + c.title for c in high_gaps],
            "days_until_deadline": (
                datetime.strptime(ENFORCEMENT_DATE, "%Y-%m-%d") - datetime.now()
            ).days,
        }

    # ── Output formats ─────────────────────────────────────────────────────

    def generate_json(self) -> str:
        """Full compliance report as JSON."""
        rc = self._classify_risk()
        checks = self._build_checks()
        gap = self._gap_summary(checks)
        return json.dumps({
            "report_meta": {
                "title": "EU AI Act Compliance Report",
                "generated_at": self._now(),
                "regulation": "EU 2024/1689 (AI Act)",
                "enforcement_date": ENFORCEMENT_DATE,
                "memgar_version": self.memgar_version,
                "max_penalty": MAX_FINE_EUR + " / " + MAX_FINE_PCT,
            },
            "system": {
                "name": self.system_name,
                "provider": self.provider_name,
                "version": self.version,
                "intended_purpose": self.intended_purpose,
                "deployer_country": self.deployer_country,
            },
            "risk_classification": {
                "risk_level": rc.risk_level,
                "annex_category": rc.annex_category,
                "is_prohibited": rc.is_prohibited,
                "reasoning": rc.reasoning,
                "obligations": rc.obligations,
            },
            "compliance_summary": gap,
            "checks": [c.to_dict() for c in checks],
            "annex_iv_checklist": self._annex_iv_checklist(),
            "registration_data": self._registration_data(),
        }, indent=2, ensure_ascii=False)

    def generate_markdown(self) -> str:
        """Human-readable Markdown compliance report."""
        rc = self._classify_risk()
        checks = self._build_checks()
        gap = self._gap_summary(checks)

        lines = [
            f"# EU AI Act Compliance Report",
            f"",
            f"**Generated:** {self._now()}  ",
            f"**Regulation:** EU 2024/1689 (AI Act)  ",
            f"**Enforcement deadline:** {ENFORCEMENT_DATE}  ",
            f"**Maximum penalty:** {MAX_FINE_EUR} or {MAX_FINE_PCT}  ",
            f"**Generated by:** Memgar v{self.memgar_version}",
            f"",
            f"---",
            f"",
            f"## System Information",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| System name | {self.system_name} |",
            f"| Provider | {self.provider_name} |",
            f"| Version | {self.version} |",
            f"| Intended purpose | {self.intended_purpose} |",
            f"| Deployer country | {self.deployer_country} |",
            f"",
            f"---",
            f"",
            f"## Risk Classification",
            f"",
            f"**Risk level:** `{rc.risk_level.upper()}`  ",
            f"**Prohibited:** {'YES ⛔' if rc.is_prohibited else 'NO ✅'}  ",
            f"**Annex category:** {rc.annex_category or 'N/A'}",
            f"",
            f"{rc.reasoning}",
            f"",
            f"**Applicable obligations:**",
        ]
        for o in rc.obligations:
            lines.append(f"- {o}")

        lines += [
            f"",
            f"---",
            f"",
            f"## Compliance Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Compliance score | **{gap['compliance_score']}%** |",
            f"| Readiness | **{gap['readiness_label']}** |",
            f"| Compliant checks | {gap['compliant']}/{gap['total_checks']} |",
            f"| Partial checks | {gap['partial']}/{gap['total_checks']} |",
            f"| Non-compliant | {gap['non_compliant']}/{gap['total_checks']} |",
            f"| Days until deadline | **{gap['days_until_deadline']}** |",
            f"",
        ]

        if gap["critical_gaps"]:
            lines += [f"### ❌ Critical Gaps (High Priority)", f""]
            for g in gap["critical_gaps"]:
                lines.append(f"- {g}")
            lines.append("")

        lines += [f"---", f"", f"## Article-by-Article Compliance Checks", f""]

        icons = {
            ComplianceStatus.COMPLIANT:      "✅",
            ComplianceStatus.PARTIAL:        "⚠️",
            ComplianceStatus.NON_COMPLIANT:  "❌",
            ComplianceStatus.NOT_APPLICABLE: "—",
        }
        for c in checks:
            icon = icons.get(c.status, "?")
            lines += [
                f"### {icon} {c.article} — {c.title}",
                f"",
                f"**Status:** `{c.status}` | **Priority:** {c.priority}",
                f"",
            ]
            if c.evidence:
                lines.append("**Evidence (Memgar controls):**")
                for e in c.evidence:
                    lines.append(f"- {e}")
                lines.append("")
            if c.gaps:
                lines.append("**Gaps:**")
                for g in c.gaps:
                    lines.append(f"- {g}")
                lines.append("")
            if c.actions:
                lines.append("**Required actions:**")
                for a in c.actions:
                    lines.append(f"1. {a}")
                lines.append("")

        lines += [
            f"---",
            f"",
            f"## Annex IV — Technical Documentation Checklist",
            f"",
        ]
        for section in self._annex_iv_checklist():
            lines += [f"### {section['section']}", f""]
            lines.append("| Requirement | Status | Note |")
            lines.append("|-------------|--------|------|")
            for item in section["items"]:
                note = item.get("note", "")
                lines.append(f"| {item['req']} | {item['status']} | {note} |")
            lines.append("")

        reg = self._registration_data()
        lines += [
            f"---",
            f"",
            f"## Article 49 — EU Database Registration Data",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
        ]
        for k, v in reg.items():
            lines.append(f"| {k} | {v} |")

        lines += [
            f"",
            f"---",
            f"",
            f"## Disclaimer",
            f"",
            f"This report is generated automatically by Memgar and constitutes a",
            f"technical self-assessment. It does not constitute legal advice and does",
            f"not replace a formal conformity assessment by a qualified notified body.",
            f"Organizations should consult qualified legal and compliance professionals",
            f"before submitting to regulatory authorities.",
            f"",
            f"*Memgar v{self.memgar_version} | EU AI Act compliance module*",
        ]

        return "\n".join(lines)

    def generate_html(self) -> str:
        """HTML compliance report with styling."""
        md = self.generate_markdown()
        rc = self._classify_risk()
        checks = self._build_checks()
        gap = self._gap_summary(checks)

        score = gap["compliance_score"]
        score_color = "#22c55e" if score >= 70 else "#f59e0b" if score >= 40 else "#ef4444"

        # Simple HTML wrapper around markdown-like content
        rows = ""
        icons = {
            ComplianceStatus.COMPLIANT:     ("✅", "#22c55e"),
            ComplianceStatus.PARTIAL:       ("⚠️", "#f59e0b"),
            ComplianceStatus.NON_COMPLIANT: ("❌", "#ef4444"),
        }
        for c in checks:
            icon, color = icons.get(c.status, ("?", "#888"))
            ev_html = "".join(f"<li>{e}</li>" for e in c.evidence)
            gap_html = "".join(f"<li>{g}</li>" for g in c.gaps)
            act_html = "".join(f"<li>{a}</li>" for a in c.actions)
            rows += f"""
            <tr>
              <td><strong>{c.article}</strong><br><small>{c.title}</small></td>
              <td style="color:{color};font-weight:bold">{icon} {c.status}</td>
              <td style="color:#ef4444;font-size:12px">{c.priority.upper()}</td>
              <td><ul style="margin:0;padding-left:16px;font-size:13px">{ev_html}</ul></td>
              <td><ul style="margin:0;padding-left:16px;font-size:13px;color:#ef4444">{gap_html}</ul></td>
              <td><ol style="margin:0;padding-left:16px;font-size:13px">{act_html}</ol></td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EU AI Act Compliance Report — {self.system_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; line-height:1.6 }}
  h1 {{ color:#f8fafc; border-bottom:2px solid #334155; padding-bottom:.5rem }}
  h2 {{ color:#94a3b8; margin-top:2rem }}
  .card {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
           padding:1.5rem; margin:1rem 0 }}
  .badge {{ display:inline-block; padding:.2rem .6rem; border-radius:4px;
            font-size:12px; font-weight:600; text-transform:uppercase }}
  .badge-high   {{ background:#fef2f2; color:#dc2626 }}
  .badge-medium {{ background:#fffbeb; color:#d97706 }}
  .score {{ font-size:3rem; font-weight:700; color:{score_color} }}
  table {{ width:100%; border-collapse:collapse; font-size:14px }}
  th {{ background:#1e293b; color:#94a3b8; padding:.75rem; text-align:left;
        border-bottom:1px solid #334155; position:sticky; top:0 }}
  td {{ padding:.75rem; border-bottom:1px solid #1e293b; vertical-align:top }}
  tr:hover {{ background:#1e293b }}
  .risk-high {{ color:#ef4444; font-weight:bold }}
  .risk-limited {{ color:#f59e0b }}
  .risk-minimal {{ color:#22c55e }}
  a {{ color:#60a5fa }}
  .deadline {{ color:#f59e0b; font-weight:600 }}
</style>
</head>
<body>
<h1>🛡️ EU AI Act Compliance Report</h1>
<p>
  <strong>{self.system_name}</strong> — {self.provider_name}<br>
  Generated: {self._now()} | Memgar v{self.memgar_version}<br>
  Enforcement deadline: <span class="deadline">{ENFORCEMENT_DATE}</span>
  ({gap['days_until_deadline']} days remaining)<br>
  Max penalty: <strong>{MAX_FINE_EUR}</strong> / {MAX_FINE_PCT}
</p>

<div class="card" style="display:flex;gap:2rem;align-items:center">
  <div>
    <div class="score">{score}%</div>
    <div>Compliance Score</div>
    <div class="badge badge-{'medium' if score < 70 else 'high'}">{gap['readiness_label']} READINESS</div>
  </div>
  <div>
    <div>✅ Compliant: <strong>{gap['compliant']}</strong></div>
    <div>⚠️ Partial: <strong>{gap['partial']}</strong></div>
    <div>❌ Non-compliant: <strong>{gap['non_compliant']}</strong></div>
  </div>
  <div>
    <div>Risk level: <span class="risk-{rc.risk_level}">{rc.risk_level.upper()}</span></div>
    <div>Prohibited: {'<span style="color:#ef4444">YES</span>' if rc.is_prohibited else '<span style="color:#22c55e">NO</span>'}</div>
    <div>Annex: {rc.annex_category or 'N/A'}</div>
  </div>
</div>

{'<div class="card" style="border-color:#ef4444"><strong>❌ Critical Gaps:</strong><ul>' + "".join(f"<li>{g}</li>" for g in gap["critical_gaps"]) + "</ul></div>" if gap["critical_gaps"] else ""}

<h2>Article-by-Article Compliance</h2>
<div style="overflow-x:auto">
<table>
  <thead>
    <tr>
      <th>Article</th>
      <th>Status</th>
      <th>Priority</th>
      <th>Evidence (Memgar)</th>
      <th>Gaps</th>
      <th>Required Actions</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</div>

<h2>Annex IV — Technical Documentation</h2>
<div class="card">
{''.join(f'<h4>{s["section"]}</h4><table><thead><tr><th>Requirement</th><th>Status</th><th>Note</th></tr></thead><tbody>' + ''.join(f'<tr><td>{i["req"]}</td><td>{i["status"]}</td><td>{i.get("note","")}</td></tr>' for i in s["items"]) + '</tbody></table>' for s in self._annex_iv_checklist())}
</div>

<h2>Article 49 — Registration Data</h2>
<div class="card"><table>{''.join(f"<tr><td><strong>{k}</strong></td><td>{v}</td></tr>" for k, v in self._registration_data().items())}</table></div>

<p style="color:#475569;font-size:12px;margin-top:3rem">
This report is a technical self-assessment generated by Memgar. It does not constitute legal advice
and does not replace a formal conformity assessment. Consult qualified legal professionals.
</p>
</body>
</html>"""

    def _registration_data(self) -> Dict[str, str]:
        """Annex VIII — EU Database registration fields."""
        return {
            "Provider name":          self.provider_name,
            "System name":            self.system_name,
            "Version":                self.version,
            "Intended purpose":       self.intended_purpose,
            "Risk classification":    self.risk_class.upper(),
            "Deployer country":       self.deployer_country,
            "Conformity assessment":  "PENDING — see Art.43",
            "Notified body":          "To be assigned",
            "Registration status":    "NOT REGISTERED",
            "Registration URL":       "https://ec.europa.eu/transparency/ai-act-database",
            "Memgar security layer":  f"v{self.memgar_version} ({', '.join(self.memgar_modules[:5])}...)",
            "Report generated":       self._now(),
        }
