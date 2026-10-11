"""Tests for signed tamper-evident report generation and cryptographic verification."""

from soc2audit.gap import calculate_gap_assessment
from soc2audit.posture import HostPostureSnapshot
from soc2audit.report import generate_audit_report, verify_audit_report
from soc2audit.rules import SOC2RuleEngine


def test_generate_and_verify_report_valid():
    snapshot = HostPostureSnapshot(
        hostname="audit-node-1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        open_ports=[22],
    )
    evals = SOC2RuleEngine.evaluate_all(snapshot)
    gap = calculate_gap_assessment(evals)

    secret = "my-secret-key-2026"
    report = generate_audit_report(snapshot, gap, secret_key=secret)

    assert "signature_block" in report
    assert report["signature_block"]["algorithm"] == "HMAC-SHA256"
    assert report["signature_block"]["canonical_hash"]
    assert report["signature_block"]["signature"]

    # Verify report
    is_valid, canon_hash, err = verify_audit_report(report, secret_key=secret)
    assert is_valid is True
    assert err is None
    assert canon_hash == report["signature_block"]["canonical_hash"]


def test_verify_report_invalid_secret():
    snapshot = HostPostureSnapshot(
        hostname="audit-node-1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
    )
    evals = SOC2RuleEngine.evaluate_all(snapshot)
    gap = calculate_gap_assessment(evals)
    report = generate_audit_report(snapshot, gap, secret_key="correct-key")

    is_valid, _, err = verify_audit_report(report, secret_key="wrong-key")
    assert is_valid is False
    assert "Cryptographic signature mismatch" in err


def test_verify_report_tampered_finding():
    """Edge Case #30: Single-bit modification in findings causes canonical hash mismatch."""
    snapshot = HostPostureSnapshot(
        hostname="audit-node-1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
    )
    evals = SOC2RuleEngine.evaluate_all(snapshot)
    gap = calculate_gap_assessment(evals)
    secret = "tamper-proof-secret"
    report = generate_audit_report(snapshot, gap, secret_key=secret)

    # Tamper with 1 character in findings
    report["findings"][0]["description"] += " [tampered]"

    is_valid, _, err = verify_audit_report(report, secret_key=secret)
    assert is_valid is False
    assert "Tamper detected: Canonical hash mismatch" in err
