"""Tests for SOC 2 and CIS Benchmark rules engine."""

from soc2audit.posture import HostPostureSnapshot
from soc2audit.rules import RuleStatus, SOC2RuleEngine


def test_rule_shadow_permissions():
    # Compliant Linux host (mode 0600)
    snap_good = HostPostureSnapshot(
        hostname="h1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        file_permissions={"/etc/shadow": "0600"},
    )
    ev_good = SOC2RuleEngine.evaluate_rule("CC6.1-FILE-PERM-SHADOW", snap_good)
    assert ev_good.status == RuleStatus.PASS

    # Non-compliant Linux host (mode 0666)
    snap_bad = HostPostureSnapshot(
        hostname="h2",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        file_permissions={"/etc/shadow": "0666"},
    )
    ev_bad = SOC2RuleEngine.evaluate_rule("CC6.1-FILE-PERM-SHADOW", snap_bad)
    assert ev_bad.status == RuleStatus.FAIL

    # Windows host marked NA gracefully
    snap_win = HostPostureSnapshot(
        hostname="h3",
        os_platform="Windows",
        os_release="10",
        os_version="10",
        architecture="AMD64",
    )
    ev_win = SOC2RuleEngine.evaluate_rule("CC6.1-FILE-PERM-SHADOW", snap_win)
    assert ev_win.status == RuleStatus.NA


def test_rule_telnet_and_ftp_ports():
    snap_open = HostPostureSnapshot(
        hostname="h1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        open_ports=[21, 23, 80],
    )
    ev_telnet = SOC2RuleEngine.evaluate_rule("CC6.6-NET-INSECURE-TELNET", snap_open)
    assert ev_telnet.status == RuleStatus.FAIL

    ev_ftp = SOC2RuleEngine.evaluate_rule("CC6.6-NET-INSECURE-FTP", snap_open)
    assert ev_ftp.status == RuleStatus.FAIL

    snap_secure = HostPostureSnapshot(
        hostname="h2",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        open_ports=[443, 22],
    )
    assert SOC2RuleEngine.evaluate_rule("CC6.6-NET-INSECURE-TELNET", snap_secure).status == RuleStatus.PASS
    assert SOC2RuleEngine.evaluate_rule("CC6.6-NET-INSECURE-FTP", snap_secure).status == RuleStatus.PASS


def test_rule_password_min_length():
    snap_pass = HostPostureSnapshot(
        hostname="h1",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        password_policies={"min_length": 14},
    )
    assert SOC2RuleEngine.evaluate_rule("CC6.1-PWD-MIN-LEN", snap_pass).status == RuleStatus.PASS

    snap_fail = HostPostureSnapshot(
        hostname="h2",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        password_policies={"min_length": 8},
    )
    assert SOC2RuleEngine.evaluate_rule("CC6.1-PWD-MIN-LEN", snap_fail).status == RuleStatus.FAIL
