"""Tests for severity-weighted gap assessment and remediation synthesis."""

from soc2audit.gap import (
    ComplianceRating,
    calculate_gap_assessment,
    synthesize_remediations,
)
from soc2audit.posture import HostPostureSnapshot
from soc2audit.rules import SOC2RuleEngine


def test_gap_assessment_compliant():
    snapshot = HostPostureSnapshot(
        hostname="secure-node",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        open_ports=[22, 443],
        file_permissions={"/etc/shadow": "0600", "/etc/passwd": "0644"},
        password_policies={"min_length": 16, "max_age_days": 60, "lockout_threshold": 3},
        ssh_config={"permit_root_login": False},
        audit_logging={"enabled": True, "retention_days": 180},
        auto_updates={"enabled": True},
    )
    evaluations = SOC2RuleEngine.evaluate_all(snapshot)
    res = calculate_gap_assessment(evaluations)

    assert res.compliance_score == 100.0
    assert res.rating == ComplianceRating.COMPLIANT
    assert len(res.failed_findings) == 0


def test_gap_assessment_non_compliant():
    # Failing critical rules (e.g. Telnet open, shadow permissions 0777, min password length 6)
    snapshot = HostPostureSnapshot(
        hostname="vulnerable-node",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        open_ports=[21, 23, 513],  # 3 critical failures: 30 pts lost
        file_permissions={"/etc/shadow": "0777"},  # critical failure: 10 pts lost
        password_policies={"min_length": 6, "max_age_days": 365, "lockout_threshold": 0},
        ssh_config={"permit_root_login": True},
        audit_logging={"enabled": False, "retention_days": 10},
        auto_updates={"enabled": False},
    )
    evaluations = SOC2RuleEngine.evaluate_all(snapshot)
    res = calculate_gap_assessment(evaluations)

    assert res.compliance_score < 70.0
    assert res.rating == ComplianceRating.NON_COMPLIANT
    assert len(res.failed_findings) > 0

    # Remediation scripts synthesized
    bash_script = synthesize_remediations(res.failed_findings, target_platform="linux")
    assert "systemctl stop telnet" in bash_script
    assert "chmod 0600 /etc/shadow" in bash_script

    ps_script = synthesize_remediations(res.failed_findings, target_platform="windows")
    assert "pwsh" in ps_script
