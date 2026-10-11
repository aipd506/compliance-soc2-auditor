"""soc2audit: Infrastructure Policy Posture Evaluator and Cryptographically Signed SOC 2 Compliance Auditor.

Zero-dependency standard library implementation.
"""

__version__ = "0.1.0"

from soc2audit.posture import HostPostureEngine, HostPostureSnapshot
from soc2audit.rules import (
    RuleCategory,
    RuleSeverity,
    RuleStatus,
    RuleEvaluation,
    SOC2RuleEngine,
)
from soc2audit.gap import (
    ComplianceRating,
    GapAssessmentResult,
    calculate_gap_assessment,
    synthesize_remediations,
)
from soc2audit.report import (
    generate_audit_report,
    verify_audit_report,
    AuditReportVerificationError,
)

__all__ = [
    "HostPostureEngine",
    "HostPostureSnapshot",
    "RuleCategory",
    "RuleSeverity",
    "RuleStatus",
    "RuleEvaluation",
    "SOC2RuleEngine",
    "ComplianceRating",
    "GapAssessmentResult",
    "calculate_gap_assessment",
    "synthesize_remediations",
    "generate_audit_report",
    "verify_audit_report",
    "AuditReportVerificationError",
]
