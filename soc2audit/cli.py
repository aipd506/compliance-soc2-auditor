"""CLI Entry Point for soc2audit.

Subcommands: audit, check, report, verify-report.
Exit codes: 0 = Compliant / Valid, 1 = Non-Compliant / Gaps, 2 = Argument error, 3 = Tamper / Verification failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from soc2audit.gap import calculate_gap_assessment, synthesize_remediations
from soc2audit.posture import HostPostureEngine, HostPostureSnapshot
from soc2audit.report import generate_audit_report, verify_audit_report
from soc2audit.rules import SOC2RuleEngine


def _resolve_snapshot(snapshot_arg: str | None) -> HostPostureSnapshot:
    if snapshot_arg:
        return HostPostureEngine.load_snapshot(snapshot_arg)
    return HostPostureEngine.probe_host()


def _print_output(data: Any, as_json: bool = False, text_fallback: str | None = None) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    elif text_fallback is not None:
        print(text_fallback)
    elif isinstance(data, dict):
        for k, v in data.items():
            print(f"{k}: {v}")
    elif isinstance(data, list):
        for item in data:
            print(item)
    else:
        print(str(data))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc2audit",
        description="SOC 2 Trust Services Criteria & CIS Benchmark Compliance Auditor",
    )
    parser.add_argument("--version", action="version", version="soc2audit 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. audit
    audit_p = subparsers.add_parser("audit", help="Run compliance posture audit")
    audit_p.add_argument("--target", default="LOCAL", help="Target (LOCAL or SNAPSHOT)")
    audit_p.add_argument("--snapshot", help="Path to offline infrastructure JSON snapshot")
    audit_p.add_argument("--category", choices=["access", "network", "os", "logging"], help="Filter category")
    audit_p.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter severity")
    audit_p.add_argument("--min-score", type=float, default=90.0, help="Minimum compliance score threshold")
    audit_p.add_argument("--output", help="Output file path")
    audit_p.add_argument("--format", choices=["terminal", "json", "markdown"], default="json", help="Output format")
    audit_p.add_argument("--json", action="store_true", help="Output as JSON")

    # 2. check
    check_p = subparsers.add_parser("check", help="Evaluate single policy rule")
    check_p.add_argument("--rule", "--rule-id", dest="rule_id", required=True, help="Rule ID (e.g. CC6.1-PWD-MIN-LEN)")
    check_p.add_argument("--snapshot", help="Path to offline snapshot file")
    check_p.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    check_p.add_argument("--json", action="store_true", help="Output as JSON")

    # 3. report
    rep_p = subparsers.add_parser("report", help="Generate signed compliance report")
    rep_p.add_argument("--input", "--snapshot", dest="input_file", help="Input audit snapshot file")
    rep_p.add_argument("--output", help="Output report file path")
    rep_p.add_argument("--sign-key", "--secret", dest="secret_key", default="audit-signing-secret", help="HMAC signing key")
    rep_p.add_argument("--key-id", default="audit-key-2026", help="Key identifier")
    rep_p.add_argument("--auditor", default="enterprise-secops", help="Auditor identity")
    rep_p.add_argument("--format", choices=["json", "markdown", "text"], default="json", help="Output format")
    rep_p.add_argument("--json", action="store_true", help="Output as JSON")

    # 4. verify-report
    ver_p = subparsers.add_parser("verify-report", help="Verify cryptographic signature of audit report")
    ver_p.add_argument("--report", required=True, help="Report file path")
    ver_p.add_argument("--secret", "--verify-key", dest="secret_key", required=True, help="HMAC verification key")
    ver_p.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    ver_p.add_argument("--json", action="store_true", help="Output as JSON")

    return parser


def handle_audit(args: argparse.Namespace) -> int:
    snapshot = _resolve_snapshot(args.snapshot)
    evaluations = SOC2RuleEngine.evaluate_all(
        snapshot,
        category=args.category,
        severity=args.severity,
    )
    assessment = calculate_gap_assessment(evaluations)

    res_dict = assessment.to_dict()
    res_dict["target_host"] = {
        "hostname": snapshot.hostname,
        "os_platform": snapshot.os_platform,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(res_dict, indent=2), encoding="utf-8")

    use_json = args.json or (args.format == "json")
    if use_json:
        _print_output(res_dict, as_json=True)
    elif args.format == "markdown":
        md_lines = [
            f"# SOC 2 Audit Report for {snapshot.hostname}",
            f"- **Score**: {assessment.compliance_score:.1f}% ({assessment.rating.value})",
            f"- **Passed Rules**: {assessment.passed_rules} / {assessment.total_rules}",
            f"- **Failed Rules**: {assessment.failed_rules}\n",
            "## Findings",
        ]
        for f in assessment.evaluations:
            md_lines.append(f"- [{f.status.value}] **{f.rule_id}**: {f.title} (Observed: {f.observed}, Expected: {f.expected})")
        print("\n".join(md_lines))
    else:
        print(f"Host: {snapshot.hostname} ({snapshot.os_platform})")
        print(f"Compliance Score: {assessment.compliance_score:.1f}% [{assessment.rating.value}]")
        print(f"Passed: {assessment.passed_rules}, Failed: {assessment.failed_rules}, N/A: {assessment.na_rules}")

    return 0 if assessment.compliance_score >= args.min_score else 1


def handle_check(args: argparse.Namespace) -> int:
    snapshot = _resolve_snapshot(args.snapshot)
    try:
        ev = SOC2RuleEngine.evaluate_rule(args.rule_id, snapshot)
        use_json = args.json or (args.format == "json")
        _print_output(ev.to_dict(), as_json=use_json)
        return 0 if ev.status.value == "PASS" else 1
    except ValueError as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1


def handle_report(args: argparse.Namespace) -> int:
    snapshot = _resolve_snapshot(args.input_file)
    evaluations = SOC2RuleEngine.evaluate_all(snapshot)
    assessment = calculate_gap_assessment(evaluations)

    report = generate_audit_report(
        snapshot=snapshot,
        assessment=assessment,
        secret_key=args.secret_key,
        key_id=args.key_id,
        auditor=args.auditor,
    )

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    _print_output(report, as_json=args.json or True)
    return 0


def handle_verify_report(args: argparse.Namespace) -> int:
    report_path = Path(args.report)
    if not report_path.exists():
        sys.stderr.write(f"Error: Report file not found: {args.report}\n")
        return 1

    is_valid, canon_hash, error_msg = verify_audit_report(report_path, args.secret_key)

    result = {
        "report_path": str(report_path),
        "status": "VALID" if is_valid else "TAMPERED",
        "canonical_hash": canon_hash,
        "error": error_msg,
    }

    use_json = args.json or (args.format == "json")
    if use_json:
        _print_output(result, as_json=True)
    else:
        if is_valid:
            print(f"Report verified successfully. Canonical Hash: {canon_hash}")
        else:
            print(f"VERIFICATION FAILED: {error_msg}")

    return 0 if is_valid else 3


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code

    if parsed.subcommand == "audit":
        return handle_audit(parsed)
    elif parsed.subcommand == "check":
        return handle_check(parsed)
    elif parsed.subcommand == "report":
        return handle_report(parsed)
    elif parsed.subcommand == "verify-report":
        return handle_verify_report(parsed)

    return 2


if __name__ == "__main__":
    sys.exit(main())
