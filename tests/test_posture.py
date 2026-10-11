"""Tests for HostPostureEngine and HostPostureSnapshot."""

import json
from pathlib import Path
from soc2audit.posture import HostPostureEngine, HostPostureSnapshot


def test_probe_host_live():
    snapshot = HostPostureEngine.probe_host()
    assert snapshot.hostname
    assert snapshot.os_platform
    assert isinstance(snapshot.open_ports, list)
    assert isinstance(snapshot.file_permissions, dict)
    assert isinstance(snapshot.password_policies, dict)


def test_load_snapshot_json(tmp_path):
    snap_data = {
        "hostname": "prod-web-01",
        "os_platform": "Linux",
        "os_release": "6.8.0",
        "os_version": "Ubuntu 24.04",
        "architecture": "x86_64",
        "open_ports": [80, 443],
        "file_permissions": {
            "/etc/passwd": "0644",
            "/etc/shadow": "0600",
        },
        "password_policies": {
            "min_length": 16,
            "max_age_days": 60,
            "lockout_threshold": 3,
        },
        "ssh_config": {
            "permit_root_login": False,
        },
        "audit_logging": {
            "enabled": True,
            "retention_days": 180,
        },
        "auto_updates": {
            "enabled": True,
        },
    }
    snap_file = tmp_path / "snapshot.json"
    snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

    loaded = HostPostureEngine.load_snapshot(snap_file)
    assert loaded.hostname == "prod-web-01"
    assert loaded.open_ports == [80, 443]
    assert loaded.file_permissions["/etc/shadow"] == "0600"
    assert loaded.password_policies["min_length"] == 16


def test_missing_files_graceful(tmp_path):
    """Edge Case #29: Non-existent files handled gracefully without crashing."""
    empty_snap = HostPostureSnapshot(
        hostname="test-host",
        os_platform="Linux",
        os_release="1.0",
        os_version="1.0",
        architecture="x86_64",
        file_permissions={},  # No sensitive files listed
    )
    assert empty_snap.file_permissions.get("/etc/shadow") is None
