"""Tests for soc2audit CLI interface and exit codes."""

import json
from soc2audit.cli import main


def _create_snapshot_file(path, compliant: bool = True):
    data = {
        "hostname": "test-node",
        "os_platform": "Linux",
        "os_release": "6.8.0",
        "os_version": "24.04",
        "architecture": "x86_64",
        "open_ports": [22, 443] if compliant else [21, 23, 80],
        "file_permissions": {"/etc/shadow": "0600", "/etc/passwd": "0644"} if compliant else {"/etc/shadow": "0777"},
        "password_policies": {
            "min_length": 16 if compliant else 6,
            "max_age_days": 60 if compliant else 365,
            "lockout_threshold": 3 if compliant else 0,
        },
        "ssh_config": {"permit_root_login": not compliant},
        "audit_logging": {"enabled": compliant, "retention_days": 180 if compliant else 10},
        "auto_updates": {"enabled": compliant},
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_cli_help():
    try:
        rc = main(["--help"])
    except SystemExit as exc:
        rc = exc.code
    assert rc == 0


def test_cli_invalid_command():
    rc = main(["unknown_action"])
    assert rc == 2


def test_cli_audit_compliant(tmp_path, capsys):
    snap_file = tmp_path / "snap_good.json"
    _create_snapshot_file(snap_file, compliant=True)

    rc = main(["audit", "--snapshot", str(snap_file), "--min-score", "90.0", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["summary"]["compliance_score"] >= 90.0
    assert data["summary"]["rating"] == "COMPLIANT"


def test_cli_audit_non_compliant(tmp_path, capsys):
    snap_file = tmp_path / "snap_bad.json"
    _create_snapshot_file(snap_file, compliant=False)

    rc = main(["audit", "--snapshot", str(snap_file), "--min-score", "90.0", "--json"])
    assert rc == 1  # Fails minimum threshold


def test_cli_check_rule_pass(tmp_path, capsys):
    snap_file = tmp_path / "snap_good.json"
    _create_snapshot_file(snap_file, compliant=True)

    rc = main(["check", "--rule", "CC6.1-PWD-MIN-LEN", "--snapshot", str(snap_file), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "PASS"


def test_cli_check_rule_fail(tmp_path, capsys):
    snap_file = tmp_path / "snap_bad.json"
    _create_snapshot_file(snap_file, compliant=False)

    rc = main(["check", "--rule", "CC6.1-PWD-MIN-LEN", "--snapshot", str(snap_file), "--json"])
    assert rc == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "FAIL"


def test_cli_report_and_verify_valid(tmp_path, capsys):
    snap_file = tmp_path / "snap_good.json"
    _create_snapshot_file(snap_file, compliant=True)

    rep_file = tmp_path / "report.json"
    secret = "test-audit-secret-2026"

    # Generate report
    rc_rep = main([
        "report",
        "--snapshot", str(snap_file),
        "--output", str(rep_file),
        "--secret", secret,
    ])
    assert rc_rep == 0
    capsys.readouterr()

    # Verify report
    rc_ver = main([
        "verify-report",
        "--report", str(rep_file),
        "--secret", secret,
        "--json",
    ])
    assert rc_ver == 0
    captured_ver = capsys.readouterr()
    ver_data = json.loads(captured_ver.out)
    assert ver_data["status"] == "VALID"


def test_cli_verify_tampered_fails_exit_3(tmp_path, capsys):
    snap_file = tmp_path / "snap_good.json"
    _create_snapshot_file(snap_file, compliant=True)

    rep_file = tmp_path / "report.json"
    secret = "test-audit-secret-2026"

    main([
        "report",
        "--snapshot", str(snap_file),
        "--output", str(rep_file),
        "--secret", secret,
    ])
    capsys.readouterr()

    # Tamper with report file
    content = json.loads(rep_file.read_text(encoding="utf-8"))
    content["findings"][0]["title"] = "Tampered Title"
    rep_file.write_text(json.dumps(content), encoding="utf-8")

    rc_tamper = main([
        "verify-report",
        "--report", str(rep_file),
        "--secret", secret,
        "--json",
    ])
    assert rc_tamper == 3
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "TAMPERED"
