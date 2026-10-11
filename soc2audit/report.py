"""Cryptographically Signed Tamper-Evident SOC 2 Audit Report Generator and Verifier.

Uses Canonical JSON (RFC 8785 subset) and HMAC-SHA256 digital signatures.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import uuid
from pathlib import Path
from typing import Any

from soc2audit.gap import GapAssessmentResult
from soc2audit.posture import HostPostureSnapshot


class AuditReportVerificationError(Exception):
    """Raised when an audit report signature or canonical hash verification fails."""
    pass


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serializes a dictionary into canonical JSON bytes (sorted keys, compact delimiters)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_audit_report(
    snapshot: HostPostureSnapshot,
    assessment: GapAssessmentResult,
    secret_key: str,
    key_id: str = "audit-signing-key-default",
    auditor: str = "enterprise-secops",
) -> dict[str, Any]:
    """Builds and cryptographically signs a tamper-evident audit report."""
    report_body = {
        "report_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "auditor": auditor,
        "target_host": {
            "hostname": snapshot.hostname,
            "os_platform": snapshot.os_platform,
            "os_release": snapshot.os_release,
            "architecture": snapshot.architecture,
        },
        "summary": {
            "total_rules": assessment.total_rules,
            "passed": assessment.passed_rules,
            "failed": assessment.failed_rules,
            "na": assessment.na_rules,
            "compliance_score": round(assessment.compliance_score, 2),
            "status": assessment.rating.value,
        },
        "findings": [e.to_dict() for e in assessment.evaluations],
    }

    # Canonical hash over report body
    body_bytes = canonical_json_bytes(report_body)
    canonical_hash = hashlib.sha256(body_bytes).hexdigest()

    # HMAC-SHA256 signature over canonical hash
    signature = hmac.new(
        secret_key.encode("utf-8"),
        canonical_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    full_report = dict(report_body)
    full_report["signature_block"] = {
        "algorithm": "HMAC-SHA256",
        "canonical_hash": canonical_hash,
        "signature": signature,
        "key_id": key_id,
    }

    return full_report


def verify_audit_report(
    report_data_or_path: dict[str, Any] | str | Path,
    secret_key: str,
) -> tuple[bool, str, str | None]:
    """Verifies the integrity and authenticity of an audit report.

    Returns (is_valid, computed_canonical_hash, error_message).
    Detects single-bit alterations in body or signature block.
    """
    if isinstance(report_data_or_path, (str, Path)):
        p = Path(report_data_or_path)
        if not p.exists():
            return False, "", f"Report file not found: {p}"
        report = json.loads(p.read_text(encoding="utf-8"))
    else:
        # Deep copy to prevent modifying caller's dict
        report = json.loads(json.dumps(report_data_or_path))

    if "signature_block" not in report:
        return False, "", "Missing signature_block in audit report."

    sig_block = report.pop("signature_block")
    algorithm = sig_block.get("algorithm")
    expected_hash = sig_block.get("canonical_hash")
    expected_sig = sig_block.get("signature")

    if algorithm != "HMAC-SHA256":
        return False, "", f"Unsupported signature algorithm: {algorithm}"

    # Re-compute canonical hash over report body without signature_block
    body_bytes = canonical_json_bytes(report)
    actual_hash = hashlib.sha256(body_bytes).hexdigest()

    if actual_hash != expected_hash:
        return (
            False,
            actual_hash,
            f"Tamper detected: Canonical hash mismatch (expected {expected_hash}, recomputed {actual_hash}).",
        )

    # Re-compute HMAC
    actual_sig = hmac.new(
        secret_key.encode("utf-8"),
        actual_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, actual_sig):
        return (
            False,
            actual_hash,
            "Cryptographic signature mismatch: verification key invalid or signature altered.",
        )

    return True, actual_hash, None
