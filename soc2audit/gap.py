"""Severity-Weighted Gap Assessment Scoring and Remediation Script Synthesizer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from soc2audit.rules import RuleEvaluation, RuleStatus


class ComplianceRating(str, Enum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


@dataclass
class GapAssessmentResult:
    total_rules: int
    passed_rules: int
    failed_rules: int
    na_rules: int
    earned_weight: int
    total_weight: int
    compliance_score: float
    rating: ComplianceRating
    evaluations: list[RuleEvaluation]
    failed_findings: list[RuleEvaluation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_rules": self.total_rules,
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "na_rules": self.na_rules,
                "earned_weight": self.earned_weight,
                "total_weight": self.total_weight,
                "compliance_score": round(self.compliance_score, 2),
                "rating": self.rating.value,
            },
            "findings": [e.to_dict() for e in self.evaluations],
        }


def calculate_gap_assessment(evaluations: list[RuleEvaluation]) -> GapAssessmentResult:
    """Calculates severity-weighted compliance score and categorizes rating."""
    passed = 0
    failed = 0
    na = 0
    earned_weight = 0
    total_weight = 0
    failed_findings: list[RuleEvaluation] = []

    for ev in evaluations:
        if ev.status == RuleStatus.PASS:
            passed += 1
            earned_weight += ev.weight
            total_weight += ev.weight
        elif ev.status == RuleStatus.FAIL:
            failed += 1
            total_weight += ev.weight
            failed_findings.append(ev)
        else:  # NA
            na += 1

    if total_weight > 0:
        score = (earned_weight / total_weight) * 100.0
    else:
        score = 100.0

    if score >= 90.0:
        rating = ComplianceRating.COMPLIANT
    elif score >= 70.0:
        rating = ComplianceRating.PARTIALLY_COMPLIANT
    else:
        rating = ComplianceRating.NON_COMPLIANT

    return GapAssessmentResult(
        total_rules=len(evaluations),
        passed_rules=passed,
        failed_rules=failed,
        na_rules=na,
        earned_weight=earned_weight,
        total_weight=total_weight,
        compliance_score=score,
        rating=rating,
        evaluations=evaluations,
        failed_findings=failed_findings,
    )


def synthesize_remediations(
    failed_evaluations: list[RuleEvaluation],
    target_platform: str = "linux",
) -> str:
    """Generates an executable Bash or PowerShell remediation script for failing rules."""
    is_windows = target_platform.lower() == "windows"
    lines: list[str] = []

    if is_windows:
        lines.append("#!/usr/bin/env pwsh")
        lines.append("# Automated SOC 2 Compliance Remediation Script (PowerShell)")
        lines.append("$ErrorActionPreference = 'Continue'\n")
        for ev in failed_evaluations:
            lines.append(f"# [{ev.rule_id}] {ev.title} (Severity: {ev.severity.value})")
            lines.append(ev.remediation_ps.strip())
            lines.append("")
    else:
        lines.append("#!/usr/bin/env bash")
        lines.append("# Automated SOC 2 Compliance Remediation Script (Bash)")
        lines.append("set -euo pipefail\n")
        for ev in failed_evaluations:
            lines.append(f"# [{ev.rule_id}] {ev.title} (Severity: {ev.severity.value})")
            lines.append(ev.remediation_bash.strip())
            lines.append("")

    return "\n".join(lines)
