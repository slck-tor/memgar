"""
EU AI Act Compliance Module
============================

EU AI Act compliance tracking and reporting for Memgar.

This module provides:
- Compliance status tracking
- Requirement management
- Compliance reporting
- Configuration for EU AI Act alignment

The EU AI Act is a comprehensive regulatory framework for AI systems
in the European Union. This module helps track compliance with its
requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# =============================================================================
# ENUMERATIONS
# =============================================================================

class ComplianceStatus(Enum):
    """Compliance status enumeration"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    PENDING = "pending"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"


class RiskLevel(Enum):
    """AI system risk levels per EU AI Act"""
    UNACCEPTABLE = "unacceptable"  # Prohibited systems
    HIGH = "high"  # High-risk systems requiring strict controls
    LIMITED = "limited"  # Limited risk with transparency obligations
    MINIMAL = "minimal"  # Minimal or no risk


class RequirementCategory(Enum):
    """Categories of EU AI Act requirements"""
    DATA_GOVERNANCE = "data_governance"
    DOCUMENTATION = "documentation"
    TRANSPARENCY = "transparency"
    HUMAN_OVERSIGHT = "human_oversight"
    ACCURACY = "accuracy"
    ROBUSTNESS = "robustness"
    CYBERSECURITY = "cybersecurity"
    BIAS_MITIGATION = "bias_mitigation"
    ACCOUNTABILITY = "accountability"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Requirement:
    """
    EU AI Act requirement
    
    Represents a specific compliance requirement from the EU AI Act.
    """
    requirement_id: str
    description: str
    severity: str
    category: Optional[RequirementCategory] = None
    risk_level: Optional[RiskLevel] = None
    mandatory: bool = True
    deadline: Optional[datetime] = None
    status: ComplianceStatus = ComplianceStatus.PENDING
    evidence: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    
    def __post_init__(self):
        """Validate and normalize data after initialization"""
        if isinstance(self.status, str):
            self.status = ComplianceStatus(self.status)
        if self.category and isinstance(self.category, str):
            self.category = RequirementCategory(self.category)
        if self.risk_level and isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)
    
    def is_compliant(self) -> bool:
        """Check if requirement is met"""
        return self.status == ComplianceStatus.COMPLIANT
    
    def add_evidence(self, evidence: str) -> None:
        """Add evidence of compliance"""
        self.evidence.append(evidence)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'requirement_id': self.requirement_id,
            'description': self.description,
            'severity': self.severity,
            'category': self.category.value if self.category else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
            'mandatory': self.mandatory,
            'deadline': self.deadline.isoformat() if self.deadline else None,
            'status': self.status.value,
            'evidence': self.evidence,
            'notes': self.notes,
        }


@dataclass
class ComplianceConfig:
    """
    Configuration for EU AI Act compliance tracking
    
    Controls how compliance is monitored and reported.
    """
    enabled: bool = True
    risk_level: RiskLevel = RiskLevel.HIGH
    strict_mode: bool = False
    auto_report: bool = False
    report_format: str = "json"
    include_evidence: bool = True
    organization_name: Optional[str] = None
    contact_email: Optional[str] = None
    reporting_period: str = "monthly"
    retention_days: int = 730  # 2 years as per EU AI Act
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'enabled': self.enabled,
            'risk_level': self.risk_level.value,
            'strict_mode': self.strict_mode,
            'auto_report': self.auto_report,
            'report_format': self.report_format,
            'include_evidence': self.include_evidence,
            'organization_name': self.organization_name,
            'contact_email': self.contact_email,
            'reporting_period': self.reporting_period,
            'retention_days': self.retention_days,
        }


@dataclass
class ComplianceReport:
    """
    EU AI Act compliance report
    
    Generated report showing compliance status across all requirements.
    """
    report_id: str
    generated_at: datetime
    organization: str
    risk_level: RiskLevel
    requirements: List[Requirement]
    overall_status: ComplianceStatus
    compliant_count: int = 0
    non_compliant_count: int = 0
    pending_count: int = 0
    summary: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate statistics after initialization"""
        self._calculate_stats()
    
    def _calculate_stats(self):
        """Calculate compliance statistics"""
        self.compliant_count = sum(
            1 for r in self.requirements 
            if r.status == ComplianceStatus.COMPLIANT
        )
        self.non_compliant_count = sum(
            1 for r in self.requirements 
            if r.status == ComplianceStatus.NON_COMPLIANT
        )
        self.pending_count = sum(
            1 for r in self.requirements 
            if r.status == ComplianceStatus.PENDING
        )
    
    def compliance_rate(self) -> float:
        """Calculate overall compliance rate"""
        if not self.requirements:
            return 0.0
        return (self.compliant_count / len(self.requirements)) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'generated_at': self.generated_at.isoformat(),
            'organization': self.organization,
            'risk_level': self.risk_level.value,
            'overall_status': self.overall_status.value,
            'statistics': {
                'total_requirements': len(self.requirements),
                'compliant': self.compliant_count,
                'non_compliant': self.non_compliant_count,
                'pending': self.pending_count,
                'compliance_rate': self.compliance_rate(),
            },
            'requirements': [r.to_dict() for r in self.requirements],
            'summary': self.summary,
            'recommendations': self.recommendations,
        }


# =============================================================================
# MAIN REPORTER CLASS
# =============================================================================

class EUAIActReporter:
    """
    EU AI Act Compliance Reporter
    
    Main class for tracking and reporting EU AI Act compliance.
    
    Usage:
        reporter = EUAIActReporter(config)
        reporter.add_requirement(requirement)
        report = reporter.generate_report()
    """
    
    def __init__(self, config: Optional[ComplianceConfig] = None):
        """Initialize reporter with configuration"""
        self.config = config or ComplianceConfig()
        self.requirements: List[Requirement] = []
        self.reports: List[ComplianceReport] = []
    
    def add_requirement(self, requirement: Requirement) -> None:
        """Add a compliance requirement to track"""
        self.requirements.append(requirement)
    
    def update_requirement_status(
        self, 
        requirement_id: str, 
        status: ComplianceStatus,
        evidence: Optional[str] = None
    ) -> bool:
        """Update the status of a requirement"""
        for req in self.requirements:
            if req.requirement_id == requirement_id:
                req.status = status
                if evidence:
                    req.add_evidence(evidence)
                return True
        return False
    
    def get_requirement(self, requirement_id: str) -> Optional[Requirement]:
        """Get a specific requirement by ID"""
        for req in self.requirements:
            if req.requirement_id == requirement_id:
                return req
        return None
    
    def get_requirements_by_status(
        self, 
        status: ComplianceStatus
    ) -> List[Requirement]:
        """Get all requirements with a specific status"""
        return [r for r in self.requirements if r.status == status]
    
    def get_requirements_by_category(
        self, 
        category: RequirementCategory
    ) -> List[Requirement]:
        """Get all requirements in a category"""
        return [r for r in self.requirements if r.category == category]
    
    def generate_report(
        self, 
        organization: Optional[str] = None
    ) -> ComplianceReport:
        """Generate a compliance report"""
        import uuid
        
        # Determine overall status
        if all(r.is_compliant() for r in self.requirements):
            overall_status = ComplianceStatus.COMPLIANT
        elif any(r.status == ComplianceStatus.NON_COMPLIANT for r in self.requirements):
            overall_status = ComplianceStatus.NON_COMPLIANT
        else:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        
        # Create report
        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(),
            organization=organization or self.config.organization_name or "Unknown",
            risk_level=self.config.risk_level,
            requirements=self.requirements.copy(),
            overall_status=overall_status,
        )
        
        # Generate recommendations
        non_compliant = self.get_requirements_by_status(
            ComplianceStatus.NON_COMPLIANT
        )
        for req in non_compliant:
            report.recommendations.append(
                f"Address requirement {req.requirement_id}: {req.description}"
            )
        
        self.reports.append(report)
        return report
    
    def export_report(
        self, 
        report: ComplianceReport, 
        format: str = "json"
    ) -> str:
        """Export report in specified format"""
        if format == "json":
            import json
            return json.dumps(report.to_dict(), indent=2)
        elif format == "text":
            return self._format_text_report(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_text_report(self, report: ComplianceReport) -> str:
        """Format report as human-readable text"""
        lines = [
            "=" * 60,
            "EU AI ACT COMPLIANCE REPORT",
            "=" * 60,
            f"Report ID: {report.report_id}",
            f"Generated: {report.generated_at}",
            f"Organization: {report.organization}",
            f"Risk Level: {report.risk_level.value.upper()}",
            "",
            "COMPLIANCE SUMMARY",
            "-" * 60,
            f"Overall Status: {report.overall_status.value.upper()}",
            f"Compliance Rate: {report.compliance_rate():.1f}%",
            f"Total Requirements: {len(report.requirements)}",
            f"  ✅ Compliant: {report.compliant_count}",
            f"  ❌ Non-Compliant: {report.non_compliant_count}",
            f"  ⏳ Pending: {report.pending_count}",
            "",
        ]
        
        if report.recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 60)
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        lines.append("=" * 60)
        return "\n".join(lines)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_default_requirements() -> List[Requirement]:
    """Create a default set of EU AI Act requirements for high-risk systems"""
    return [
        Requirement(
            requirement_id="EUAI-001",
            description="Establish and maintain risk management system",
            severity="critical",
            category=RequirementCategory.ACCOUNTABILITY,
            risk_level=RiskLevel.HIGH,
        ),
        Requirement(
            requirement_id="EUAI-002",
            description="Ensure data governance and management practices",
            severity="critical",
            category=RequirementCategory.DATA_GOVERNANCE,
            risk_level=RiskLevel.HIGH,
        ),
        Requirement(
            requirement_id="EUAI-003",
            description="Maintain technical documentation",
            severity="high",
            category=RequirementCategory.DOCUMENTATION,
            risk_level=RiskLevel.HIGH,
        ),
        Requirement(
            requirement_id="EUAI-004",
            description="Enable human oversight",
            severity="critical",
            category=RequirementCategory.HUMAN_OVERSIGHT,
            risk_level=RiskLevel.HIGH,
        ),
        Requirement(
            requirement_id="EUAI-005",
            description="Ensure accuracy, robustness and cybersecurity",
            severity="critical",
            category=RequirementCategory.ROBUSTNESS,
            risk_level=RiskLevel.HIGH,
        ),
    ]


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    'ComplianceStatus',
    'RiskLevel',
    'RequirementCategory',
    # Data Classes
    'Requirement',
    'ComplianceConfig',
    'ComplianceReport',
    # Main Class
    'EUAIActReporter',
    # Helpers
    'create_default_requirements',
]
