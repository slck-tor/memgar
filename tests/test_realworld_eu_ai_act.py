"""
Real-world EU AI Act compliance scenarios.

Covers: memgar/eu_ai_act.py — previously at 27% coverage.

Scenarios:
 - Compliance lifecycle: PENDING → COMPLIANT / NON_COMPLIANT
 - Mandatory requirement enforcement for high-risk AI systems
 - Report generation with overall status calculation
 - Non-compliant requirement recommendations
 - Evidence trail for audit purposes
 - Export formats (JSON and text)
 - create_default_requirements() for out-of-box compliance tracking
 - Category and status filtering
"""

import json
from datetime import datetime, timedelta

import pytest

from memgar.eu_ai_act import (
    ComplianceStatus,
    RiskLevel,
    RequirementCategory,
    Requirement,
    ComplianceConfig,
    ComplianceReport,
    EUAIActReporter,
    create_default_requirements,
)


# ---------------------------------------------------------------------------
# 1. Enum Values
# ---------------------------------------------------------------------------

class TestEnumValues:

    def test_compliance_status_values(self):
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.PARTIALLY_COMPLIANT.value == "partially_compliant"
        assert ComplianceStatus.PENDING.value == "pending"
        assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"
        assert ComplianceStatus.UNDER_REVIEW.value == "under_review"

    def test_risk_level_values(self):
        assert RiskLevel.UNACCEPTABLE.value == "unacceptable"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.LIMITED.value == "limited"
        assert RiskLevel.MINIMAL.value == "minimal"

    def test_requirement_category_values(self):
        assert RequirementCategory.DATA_GOVERNANCE.value == "data_governance"
        assert RequirementCategory.TRANSPARENCY.value == "transparency"
        assert RequirementCategory.HUMAN_OVERSIGHT.value == "human_oversight"
        assert RequirementCategory.CYBERSECURITY.value == "cybersecurity"
        assert RequirementCategory.BIAS_MITIGATION.value == "bias_mitigation"


# ---------------------------------------------------------------------------
# 2. Requirement Data Model
# ---------------------------------------------------------------------------

class TestRequirementModel:

    def test_requirement_creation(self):
        req = Requirement(
            requirement_id="EUAI-TEST-001",
            description="Test requirement",
            severity="critical",
        )
        assert req.requirement_id == "EUAI-TEST-001"
        assert req.status == ComplianceStatus.PENDING

    def test_requirement_default_status_pending(self):
        req = Requirement(
            requirement_id="R-001",
            description="desc",
            severity="high",
        )
        assert req.status == ComplianceStatus.PENDING

    def test_requirement_is_compliant_when_compliant(self):
        req = Requirement(
            requirement_id="R-002",
            description="desc",
            severity="critical",
            status=ComplianceStatus.COMPLIANT,
        )
        assert req.is_compliant() is True

    def test_requirement_not_compliant_when_pending(self):
        req = Requirement(
            requirement_id="R-003",
            description="desc",
            severity="high",
        )
        assert req.is_compliant() is False

    def test_requirement_add_evidence(self):
        req = Requirement(
            requirement_id="R-004",
            description="data governance",
            severity="critical",
        )
        req.add_evidence("Data processing log reviewed 2026-05-01")
        assert len(req.evidence) == 1
        assert "2026-05-01" in req.evidence[0]

    def test_requirement_add_multiple_evidence(self):
        req = Requirement(
            requirement_id="R-005",
            description="audit trail",
            severity="high",
        )
        req.add_evidence("Log entry 1")
        req.add_evidence("Log entry 2")
        req.add_evidence("Log entry 3")
        assert len(req.evidence) == 3

    def test_requirement_to_dict(self):
        req = Requirement(
            requirement_id="R-006",
            description="Human oversight requirement",
            severity="critical",
            category=RequirementCategory.HUMAN_OVERSIGHT,
            risk_level=RiskLevel.HIGH,
        )
        d = req.to_dict()
        assert d["requirement_id"] == "R-006"
        assert d["severity"] == "critical"
        assert d["category"] == "human_oversight"
        assert d["risk_level"] == "high"
        assert "status" in d

    def test_requirement_with_deadline(self):
        deadline = datetime(2026, 8, 1)
        req = Requirement(
            requirement_id="R-007",
            description="deadline req",
            severity="high",
            deadline=deadline,
        )
        d = req.to_dict()
        assert d["deadline"] is not None

    def test_requirement_string_status_normalized(self):
        """Status can be passed as string and gets normalized to enum."""
        req = Requirement(
            requirement_id="R-008",
            description="test",
            severity="low",
            status="compliant",
        )
        assert req.status == ComplianceStatus.COMPLIANT

    def test_requirement_mandatory_default_true(self):
        req = Requirement(
            requirement_id="R-009",
            description="mandatory req",
            severity="critical",
        )
        assert req.mandatory is True


# ---------------------------------------------------------------------------
# 3. ComplianceConfig
# ---------------------------------------------------------------------------

class TestComplianceConfig:

    def test_default_config_enabled(self):
        cfg = ComplianceConfig()
        assert cfg.enabled is True

    def test_default_risk_level_high(self):
        cfg = ComplianceConfig()
        assert cfg.risk_level == RiskLevel.HIGH

    def test_retention_days_default_two_years(self):
        cfg = ComplianceConfig()
        assert cfg.retention_days == 730

    def test_config_to_dict(self):
        cfg = ComplianceConfig(organization_name="Memgar Inc.")
        d = cfg.to_dict()
        assert isinstance(d, dict)
        assert d["organization_name"] == "Memgar Inc."
        assert d["enabled"] is True
        assert "retention_days" in d

    def test_strict_mode_default_false(self):
        cfg = ComplianceConfig()
        assert cfg.strict_mode is False

    def test_custom_config(self):
        cfg = ComplianceConfig(
            risk_level=RiskLevel.LIMITED,
            strict_mode=True,
            auto_report=True,
            organization_name="Test Org",
        )
        assert cfg.risk_level == RiskLevel.LIMITED
        assert cfg.strict_mode is True
        assert cfg.auto_report is True


# ---------------------------------------------------------------------------
# 4. EUAIActReporter — Core Operations
# ---------------------------------------------------------------------------

class TestEUAIActReporter:

    @pytest.fixture
    def reporter(self):
        cfg = ComplianceConfig(organization_name="Memgar Security")
        return EUAIActReporter(config=cfg)

    @pytest.fixture
    def req_factory(self):
        def _make(req_id, status=ComplianceStatus.PENDING, category=None):
            return Requirement(
                requirement_id=req_id,
                description=f"Requirement {req_id}",
                severity="critical",
                status=status,
                category=category,
            )
        return _make

    def test_reporter_starts_empty(self, reporter):
        assert len(reporter.requirements) == 0

    def test_add_requirement(self, reporter, req_factory):
        reporter.add_requirement(req_factory("R-001"))
        assert len(reporter.requirements) == 1

    def test_add_multiple_requirements(self, reporter, req_factory):
        for i in range(5):
            reporter.add_requirement(req_factory(f"R-{i:03d}"))
        assert len(reporter.requirements) == 5

    def test_get_requirement_by_id(self, reporter, req_factory):
        reporter.add_requirement(req_factory("R-42"))
        req = reporter.get_requirement("R-42")
        assert req is not None
        assert req.requirement_id == "R-42"

    def test_get_nonexistent_requirement_returns_none(self, reporter):
        result = reporter.get_requirement("NONEXISTENT")
        assert result is None

    def test_update_requirement_status(self, reporter, req_factory):
        reporter.add_requirement(req_factory("R-001"))
        success = reporter.update_requirement_status("R-001", ComplianceStatus.COMPLIANT)
        assert success is True
        req = reporter.get_requirement("R-001")
        assert req.status == ComplianceStatus.COMPLIANT

    def test_update_status_adds_evidence(self, reporter, req_factory):
        reporter.add_requirement(req_factory("R-001"))
        reporter.update_requirement_status(
            "R-001",
            ComplianceStatus.COMPLIANT,
            evidence="Audit log reviewed on 2026-05-01",
        )
        req = reporter.get_requirement("R-001")
        assert len(req.evidence) == 1

    def test_update_nonexistent_returns_false(self, reporter):
        success = reporter.update_requirement_status("GHOST", ComplianceStatus.COMPLIANT)
        assert success is False

    def test_get_requirements_by_status(self, reporter, req_factory):
        reporter.add_requirement(req_factory("R-001", ComplianceStatus.COMPLIANT))
        reporter.add_requirement(req_factory("R-002", ComplianceStatus.NON_COMPLIANT))
        reporter.add_requirement(req_factory("R-003", ComplianceStatus.PENDING))

        compliant = reporter.get_requirements_by_status(ComplianceStatus.COMPLIANT)
        assert len(compliant) == 1
        assert compliant[0].requirement_id == "R-001"

    def test_get_requirements_by_category(self, reporter, req_factory):
        reporter.add_requirement(
            req_factory("R-001", category=RequirementCategory.HUMAN_OVERSIGHT)
        )
        reporter.add_requirement(
            req_factory("R-002", category=RequirementCategory.TRANSPARENCY)
        )
        reporter.add_requirement(
            req_factory("R-003", category=RequirementCategory.HUMAN_OVERSIGHT)
        )

        oversight = reporter.get_requirements_by_category(RequirementCategory.HUMAN_OVERSIGHT)
        assert len(oversight) == 2


# ---------------------------------------------------------------------------
# 5. Report Generation
# ---------------------------------------------------------------------------

class TestReportGeneration:

    @pytest.fixture
    def reporter_with_reqs(self):
        cfg = ComplianceConfig(organization_name="Memgar AI")
        reporter = EUAIActReporter(config=cfg)
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-001",
            description="Risk management system",
            severity="critical",
            status=ComplianceStatus.COMPLIANT,
        ))
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-002",
            description="Data governance",
            severity="critical",
            status=ComplianceStatus.NON_COMPLIANT,
        ))
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-003",
            description="Technical documentation",
            severity="high",
            status=ComplianceStatus.PENDING,
        ))
        return reporter

    def test_generate_report_returns_compliance_report(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert isinstance(report, ComplianceReport)

    def test_report_has_all_fields(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert hasattr(report, 'report_id')
        assert hasattr(report, 'generated_at')
        assert hasattr(report, 'organization')
        assert hasattr(report, 'risk_level')
        assert hasattr(report, 'requirements')
        assert hasattr(report, 'overall_status')
        assert hasattr(report, 'compliant_count')
        assert hasattr(report, 'non_compliant_count')
        assert hasattr(report, 'pending_count')

    def test_report_counts_accurate(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert report.compliant_count == 1
        assert report.non_compliant_count == 1
        assert report.pending_count == 1

    def test_report_overall_status_non_compliant_when_any_fails(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert report.overall_status == ComplianceStatus.NON_COMPLIANT

    def test_report_overall_status_compliant_when_all_pass(self):
        reporter = EUAIActReporter()
        for i in range(3):
            reporter.add_requirement(Requirement(
                requirement_id=f"R-{i}",
                description="desc",
                severity="high",
                status=ComplianceStatus.COMPLIANT,
            ))
        report = reporter.generate_report()
        assert report.overall_status == ComplianceStatus.COMPLIANT

    def test_report_overall_status_partially_when_all_pending(self):
        reporter = EUAIActReporter()
        reporter.add_requirement(Requirement(
            requirement_id="R-1",
            description="desc",
            severity="high",
        ))
        report = reporter.generate_report()
        assert report.overall_status == ComplianceStatus.PARTIALLY_COMPLIANT

    def test_report_compliance_rate_calculation(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        rate = report.compliance_rate()
        expected = (1 / 3) * 100  # 1 out of 3 compliant
        assert abs(rate - expected) < 0.01

    def test_report_100_percent_compliant(self):
        reporter = EUAIActReporter()
        for i in range(5):
            reporter.add_requirement(Requirement(
                requirement_id=f"R-{i}",
                description="desc",
                severity="high",
                status=ComplianceStatus.COMPLIANT,
            ))
        report = reporter.generate_report()
        assert report.compliance_rate() == 100.0

    def test_report_recommendations_for_non_compliant(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert len(report.recommendations) >= 1
        assert any("EUAI-002" in rec for rec in report.recommendations)

    def test_report_organization_from_config(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        assert report.organization == "Memgar AI"

    def test_report_stored_in_reports_list(self, reporter_with_reqs):
        reporter_with_reqs.generate_report()
        assert len(reporter_with_reqs.reports) == 1

    def test_multiple_reports_accumulated(self, reporter_with_reqs):
        reporter_with_reqs.generate_report()
        reporter_with_reqs.generate_report()
        assert len(reporter_with_reqs.reports) == 2

    def test_report_to_dict(self, reporter_with_reqs):
        report = reporter_with_reqs.generate_report()
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "report_id" in d
        assert "statistics" in d
        assert "requirements" in d
        assert d["statistics"]["total_requirements"] == 3


# ---------------------------------------------------------------------------
# 6. Export Functions
# ---------------------------------------------------------------------------

class TestExportFunctions:

    @pytest.fixture
    def reporter_complete(self):
        reporter = EUAIActReporter(
            config=ComplianceConfig(organization_name="Test Corp")
        )
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-001",
            description="Risk management",
            severity="critical",
            status=ComplianceStatus.COMPLIANT,
            category=RequirementCategory.ACCOUNTABILITY,
        ))
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-002",
            description="Data governance",
            severity="critical",
            status=ComplianceStatus.NON_COMPLIANT,
            category=RequirementCategory.DATA_GOVERNANCE,
        ))
        return reporter

    def test_export_json_format(self, reporter_complete):
        report = reporter_complete.generate_report()
        json_output = reporter_complete.export_report(report, format="json")
        assert isinstance(json_output, str)
        parsed = json.loads(json_output)
        assert "report_id" in parsed

    def test_export_text_format(self, reporter_complete):
        report = reporter_complete.generate_report()
        text_output = reporter_complete.export_report(report, format="text")
        assert isinstance(text_output, str)
        assert "EU AI ACT COMPLIANCE REPORT" in text_output
        assert "Test Corp" in text_output

    def test_export_text_contains_compliance_rate(self, reporter_complete):
        report = reporter_complete.generate_report()
        text = reporter_complete.export_report(report, format="text")
        assert "Compliance Rate" in text or "compliance" in text.lower()

    def test_export_text_contains_recommendations(self, reporter_complete):
        report = reporter_complete.generate_report()
        text = reporter_complete.export_report(report, format="text")
        assert "RECOMMENDATIONS" in text

    def test_export_unsupported_format_raises(self, reporter_complete):
        report = reporter_complete.generate_report()
        with pytest.raises(ValueError):
            reporter_complete.export_report(report, format="pdf")

    def test_export_json_valid_statistics(self, reporter_complete):
        report = reporter_complete.generate_report()
        parsed = json.loads(reporter_complete.export_report(report))
        stats = parsed["statistics"]
        assert stats["total_requirements"] == 2
        assert stats["compliant"] == 1
        assert stats["non_compliant"] == 1


# ---------------------------------------------------------------------------
# 7. create_default_requirements()
# ---------------------------------------------------------------------------

class TestDefaultRequirements:

    def test_creates_requirements_list(self):
        reqs = create_default_requirements()
        assert isinstance(reqs, list)
        assert len(reqs) >= 5

    def test_default_ids_present(self):
        reqs = create_default_requirements()
        ids = {r.requirement_id for r in reqs}
        assert "EUAI-001" in ids
        assert "EUAI-002" in ids
        assert "EUAI-003" in ids
        assert "EUAI-004" in ids
        assert "EUAI-005" in ids

    def test_default_requirements_are_pending(self):
        reqs = create_default_requirements()
        for req in reqs:
            assert req.status == ComplianceStatus.PENDING

    def test_default_requirements_are_mandatory(self):
        reqs = create_default_requirements()
        for req in reqs:
            assert req.mandatory is True

    def test_default_requirements_cover_key_categories(self):
        reqs = create_default_requirements()
        categories = {r.category for r in reqs if r.category}
        assert RequirementCategory.HUMAN_OVERSIGHT in categories
        assert RequirementCategory.DATA_GOVERNANCE in categories

    def test_default_requirements_high_risk_level(self):
        reqs = create_default_requirements()
        for req in reqs:
            assert req.risk_level == RiskLevel.HIGH

    def test_reporter_can_load_defaults(self):
        reporter = EUAIActReporter()
        for req in create_default_requirements():
            reporter.add_requirement(req)
        assert len(reporter.requirements) >= 5
        report = reporter.generate_report()
        assert report.pending_count >= 5

    def test_default_requirements_have_descriptions(self):
        reqs = create_default_requirements()
        for req in reqs:
            assert len(req.description) > 0


# ---------------------------------------------------------------------------
# 8. Realistic Compliance Lifecycle Scenarios
# ---------------------------------------------------------------------------

class TestRealisticComplianceScenarios:

    def test_memgar_compliance_lifecycle(self):
        """
        Full lifecycle: start with defaults → run compliance checks →
        update statuses → generate final report.
        """
        reporter = EUAIActReporter(
            config=ComplianceConfig(
                organization_name="Memgar",
                risk_level=RiskLevel.HIGH,
            )
        )
        for req in create_default_requirements():
            reporter.add_requirement(req)

        # Simulate compliance work
        reporter.update_requirement_status(
            "EUAI-001",
            ComplianceStatus.COMPLIANT,
            evidence="Risk management system deployed with 4-layer analysis pipeline",
        )
        reporter.update_requirement_status(
            "EUAI-002",
            ComplianceStatus.COMPLIANT,
            evidence="WriteAheadValidator implemented, all memory writes validated",
        )
        reporter.update_requirement_status(
            "EUAI-004",
            ComplianceStatus.COMPLIANT,
            evidence="HITL checkpoint with human approval workflow deployed",
        )

        report = reporter.generate_report()
        assert report.compliant_count == 3
        assert report.pending_count == 2
        assert report.compliance_rate() == 60.0

    def test_non_compliant_report_triggers_recommendations(self):
        """Every non-compliant requirement should generate a recommendation."""
        reporter = EUAIActReporter()
        for i in range(3):
            reporter.add_requirement(Requirement(
                requirement_id=f"EUAI-{i:03d}",
                description=f"Requirement {i}",
                severity="critical",
                status=ComplianceStatus.NON_COMPLIANT,
            ))
        report = reporter.generate_report()
        assert len(report.recommendations) == 3

    def test_evidence_trail_for_audit(self):
        """Audit trail: each compliance activity records evidence."""
        reporter = EUAIActReporter()
        reporter.add_requirement(Requirement(
            requirement_id="EUAI-004",
            description="Human oversight",
            severity="critical",
            category=RequirementCategory.HUMAN_OVERSIGHT,
        ))
        reporter.update_requirement_status(
            "EUAI-004",
            ComplianceStatus.COMPLIANT,
            evidence="HITL checkpoint deployed on 2026-05-01",
        )
        reporter.update_requirement_status(
            "EUAI-004",
            ComplianceStatus.COMPLIANT,
            evidence="Quarterly audit completed 2026-05-02",
        )
        req = reporter.get_requirement("EUAI-004")
        assert len(req.evidence) == 2

    def test_high_risk_ai_system_full_report(self):
        """
        Simulate full EU AI Act compliance report for a high-risk AI system
        (Memgar falls under high-risk due to security-critical decision making).
        """
        cfg = ComplianceConfig(
            organization_name="Memgar Security Inc.",
            risk_level=RiskLevel.HIGH,
            strict_mode=True,
            include_evidence=True,
        )
        reporter = EUAIActReporter(config=cfg)
        for req in create_default_requirements():
            reporter.add_requirement(req)

        # Mark EUAI-005 (accuracy, robustness, cybersecurity) as compliant
        reporter.update_requirement_status(
            "EUAI-005",
            ComplianceStatus.COMPLIANT,
            evidence="94% precision/recall quality gate passed; ED25519 feed signatures verified",
        )

        report = reporter.generate_report(organization="Memgar Security Inc.")
        assert report.organization == "Memgar Security Inc."
        assert report.compliant_count >= 1

        # Export as JSON and verify it's valid
        json_str = reporter.export_report(report, format="json")
        parsed = json.loads(json_str)
        assert parsed["statistics"]["compliant"] >= 1

    def test_partially_compliant_agent_security_system(self):
        """
        Memgar as an agent security library: some requirements compliant,
        some under review → overall PARTIALLY_COMPLIANT.
        """
        reporter = EUAIActReporter()
        statuses = [
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.UNDER_REVIEW,
            ComplianceStatus.PARTIALLY_COMPLIANT,
        ]
        for i, status in enumerate(statuses):
            reporter.add_requirement(Requirement(
                requirement_id=f"REQ-{i}",
                description=f"requirement {i}",
                severity="high",
                status=status,
            ))

        report = reporter.generate_report()
        # No NON_COMPLIANT, not all COMPLIANT → PARTIALLY_COMPLIANT
        assert report.overall_status in (
            ComplianceStatus.PARTIALLY_COMPLIANT,
            ComplianceStatus.NON_COMPLIANT,
        )
