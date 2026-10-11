"""SOC 2 Trust Services Criteria & CIS Benchmark Evaluation Rules.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from soc2audit.posture import HostPostureSnapshot


class RuleCategory(str, Enum):
    ACCESS = "access"
    NETWORK = "network"
    OS = "os"
    LOGGING = "logging"


class RuleSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_WEIGHTS = {
    RuleSeverity.CRITICAL: 10,
    RuleSeverity.HIGH: 5,
    RuleSeverity.MEDIUM: 2,
    RuleSeverity.LOW: 1,
}


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "NA"


@dataclass
class RuleEvaluation:
    rule_id: str
    title: str
    category: RuleCategory
    severity: RuleSeverity
    weight: int
    status: RuleStatus
    observed: Any
    expected: Any
    description: str
    remediation_bash: str
    remediation_ps: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "weight": self.weight,
            "status": self.status.value,
            "observed": self.observed,
            "expected": self.expected,
            "description": self.description,
            "remediation_bash": self.remediation_bash,
            "remediation_ps": self.remediation_ps,
        }


class SOC2RuleEngine:
    """Evaluates host posture snapshots against SOC 2 and CIS benchmark rules."""

    @classmethod
    def evaluate_all(
        cls,
        snapshot: HostPostureSnapshot,
        category: str | None = None,
        severity: str | None = None,
    ) -> list[RuleEvaluation]:
        evaluations: list[RuleEvaluation] = [
            cls._check_shadow_perm(snapshot),
            cls._check_passwd_perm(snapshot),
            cls._check_pwd_min_len(snapshot),
            cls._check_pwd_max_age(snapshot),
            cls._check_pwd_lockout(snapshot),
            cls._check_telnet_port(snapshot),
            cls._check_ftp_port(snapshot),
            cls._check_rsh_port(snapshot),
            cls._check_ssh_root_login(snapshot),
            cls._check_audit_daemon(snapshot),
            cls._check_log_retention(snapshot),
            cls._check_auto_updates(snapshot),
        ]

        if category:
            cat_lower = category.lower()
            evaluations = [e for e in evaluations if e.category.value == cat_lower]

        if severity:
            sev_lower = severity.lower()
            evaluations = [e for e in evaluations if e.severity.value == sev_lower]

        return evaluations

    @classmethod
    def evaluate_rule(cls, rule_id: str, snapshot: HostPostureSnapshot) -> RuleEvaluation:
        rules_map = {
            "CC6.1-FILE-PERM-SHADOW": cls._check_shadow_perm,
            "CC6.1-FILE-PERM-PASSWD": cls._check_passwd_perm,
            "CC6.1-PWD-MIN-LEN": cls._check_pwd_min_len,
            "CC6.1-PWD-MAX-AGE": cls._check_pwd_max_age,
            "CC6.1-PWD-LOCKOUT": cls._check_pwd_lockout,
            "CC6.6-NET-INSECURE-TELNET": cls._check_telnet_port,
            "CC6.6-NET-INSECURE-FTP": cls._check_ftp_port,
            "CC6.6-NET-INSECURE-RSH": cls._check_rsh_port,
            "CC6.8-SSH-ROOT-LOGIN": cls._check_ssh_root_login,
            "CC7.2-AUDIT-DAEMON": cls._check_audit_daemon,
            "CC7.2-LOG-RETENTION": cls._check_log_retention,
            "CC8.1-AUTO-UPDATES": cls._check_auto_updates,
        }
        checker = rules_map.get(rule_id.upper())
        if not checker:
            raise ValueError(f"Unknown rule ID: '{rule_id}'")
        return checker(snapshot)

    # Individual Rule Checkers

    @staticmethod
    def _check_shadow_perm(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.1-FILE-PERM-SHADOW"
        sev = RuleSeverity.CRITICAL
        # If running on Windows or shadow not in snapshot/host, mark NA gracefully (Edge Case #29)
        if s.os_platform.lower() == "windows":
            return RuleEvaluation(
                rule_id=rule_id,
                title="Verify /etc/shadow Permissions",
                category=RuleCategory.ACCESS,
                severity=sev,
                weight=SEVERITY_WEIGHTS[sev],
                status=RuleStatus.NA,
                observed="Windows OS (N/A)",
                expected="<= 0600",
                description="Checks that shadow password file permissions do not exceed 0600.",
                remediation_bash="chmod 0600 /etc/shadow",
                remediation_ps="# N/A on Windows",
            )

        perm = s.file_permissions.get("/etc/shadow")
        if perm is None:
            status = RuleStatus.NA
            obs = "File does not exist"
        else:
            mode_int = int(perm, 8) if isinstance(perm, str) else int(perm)
            status = RuleStatus.PASS if mode_int <= 0o600 else RuleStatus.FAIL
            obs = perm

        return RuleEvaluation(
            rule_id=rule_id,
            title="Verify /etc/shadow Permissions",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=obs,
            expected="<= 0600",
            description="Checks that shadow password file permissions do not exceed 0600.",
            remediation_bash="chmod 0600 /etc/shadow && chown root:root /etc/shadow",
            remediation_ps="# N/A on Windows",
        )

    @staticmethod
    def _check_passwd_perm(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.1-FILE-PERM-PASSWD"
        sev = RuleSeverity.HIGH
        if s.os_platform.lower() == "windows":
            return RuleEvaluation(
                rule_id=rule_id,
                title="Verify /etc/passwd Permissions",
                category=RuleCategory.ACCESS,
                severity=sev,
                weight=SEVERITY_WEIGHTS[sev],
                status=RuleStatus.NA,
                observed="Windows OS (N/A)",
                expected="<= 0644",
                description="Checks that passwd user database permissions do not exceed 0644.",
                remediation_bash="chmod 0644 /etc/passwd",
                remediation_ps="# N/A on Windows",
            )

        perm = s.file_permissions.get("/etc/passwd")
        if perm is None:
            status = RuleStatus.NA
            obs = "File does not exist"
        else:
            mode_int = int(perm, 8) if isinstance(perm, str) else int(perm)
            status = RuleStatus.PASS if mode_int <= 0o644 else RuleStatus.FAIL
            obs = perm

        return RuleEvaluation(
            rule_id=rule_id,
            title="Verify /etc/passwd Permissions",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=obs,
            expected="<= 0644",
            description="Checks that passwd user database permissions do not exceed 0644.",
            remediation_bash="chmod 0644 /etc/passwd && chown root:root /etc/passwd",
            remediation_ps="# N/A on Windows",
        )

    @staticmethod
    def _check_pwd_min_len(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.1-PWD-MIN-LEN"
        sev = RuleSeverity.HIGH
        min_len = s.password_policies.get("min_length", 0)
        status = RuleStatus.PASS if min_len >= 14 else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Enforce Minimum Password Length",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=min_len,
            expected=">= 14",
            description="CIS Benchmark requirement: Minimum password length must be at least 14 characters.",
            remediation_bash="sed -i 's/minlen = .*/minlen = 14/' /etc/security/pwquality.conf",
            remediation_ps="net accounts /minpwlen:14",
        )

    @staticmethod
    def _check_pwd_max_age(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.1-PWD-MAX-AGE"
        sev = RuleSeverity.MEDIUM
        max_age = s.password_policies.get("max_age_days", 999)
        status = RuleStatus.PASS if max_age <= 90 else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Enforce Maximum Password Age",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=max_age,
            expected="<= 90 days",
            description="Passwords must expire within 90 days to limit exposure duration.",
            remediation_bash="sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
            remediation_ps="net accounts /maxpwage:90",
        )

    @staticmethod
    def _check_pwd_lockout(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.1-PWD-LOCKOUT"
        sev = RuleSeverity.HIGH
        lockout = s.password_policies.get("lockout_threshold", 0)
        status = RuleStatus.PASS if (1 <= lockout <= 5) else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Enforce Account Lockout Threshold",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=lockout,
            expected="Between 1 and 5 attempts",
            description="Accounts must lock after at most 5 consecutive failed authentication attempts.",
            remediation_bash="authselect enable-feature with-faillock && faillock --set-deny 5",
            remediation_ps="net accounts /lockoutthreshold:5",
        )

    @staticmethod
    def _check_telnet_port(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.6-NET-INSECURE-TELNET"
        sev = RuleSeverity.CRITICAL
        has_telnet = 23 in s.open_ports
        status = RuleStatus.FAIL if has_telnet else RuleStatus.PASS
        return RuleEvaluation(
            rule_id=rule_id,
            title="Disable Insecure Telnet Service (Port 23)",
            category=RuleCategory.NETWORK,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="Port 23 Open" if has_telnet else "Closed",
            expected="Port 23 Closed",
            description="Telnet transmits authentication and session data in cleartext; must be disabled.",
            remediation_bash="systemctl stop telnet.socket && systemctl disable telnet.socket",
            remediation_ps="Stop-Service -Name Telnet -Force; Set-Service -Name Telnet -StartupType Disabled",
        )

    @staticmethod
    def _check_ftp_port(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.6-NET-INSECURE-FTP"
        sev = RuleSeverity.CRITICAL
        has_ftp = 21 in s.open_ports
        status = RuleStatus.FAIL if has_ftp else RuleStatus.PASS
        return RuleEvaluation(
            rule_id=rule_id,
            title="Disable Insecure FTP Service (Port 21)",
            category=RuleCategory.NETWORK,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="Port 21 Open" if has_ftp else "Closed",
            expected="Port 21 Closed",
            description="Plaintext FTP must be replaced by SFTP or FTPS.",
            remediation_bash="systemctl stop vsftpd && systemctl disable vsftpd",
            remediation_ps="Stop-Service -Name ftpsvc -Force; Set-Service -Name ftpsvc -StartupType Disabled",
        )

    @staticmethod
    def _check_rsh_port(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.6-NET-INSECURE-RSH"
        sev = RuleSeverity.CRITICAL
        has_rsh = (513 in s.open_ports) or (514 in s.open_ports)
        status = RuleStatus.FAIL if has_rsh else RuleStatus.PASS
        return RuleEvaluation(
            rule_id=rule_id,
            title="Disable Legacy RSH/Rlogin Ports (513/514)",
            category=RuleCategory.NETWORK,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="Ports 513/514 Open" if has_rsh else "Closed",
            expected="Ports 513/514 Closed",
            description="Legacy unauthenticated rsh/rlogin protocols must be disabled.",
            remediation_bash="systemctl stop rsh.socket && systemctl disable rsh.socket",
            remediation_ps="# RSH is not installed by default on Windows",
        )

    @staticmethod
    def _check_ssh_root_login(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC6.8-SSH-ROOT-LOGIN"
        sev = RuleSeverity.HIGH
        permit_root = s.ssh_config.get("permit_root_login", False)
        status = RuleStatus.FAIL if permit_root else RuleStatus.PASS
        return RuleEvaluation(
            rule_id=rule_id,
            title="Disable SSH Root Login",
            category=RuleCategory.ACCESS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="PermitRootLogin Yes" if permit_root else "PermitRootLogin No",
            expected="PermitRootLogin No",
            description="Direct remote login as root should be prohibited.",
            remediation_bash="sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
            remediation_ps="# Ensure Windows OpenSSH sshd_config sets PermitRootLogin no",
        )

    @staticmethod
    def _check_audit_daemon(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC7.2-AUDIT-DAEMON"
        sev = RuleSeverity.HIGH
        enabled = s.audit_logging.get("enabled", False)
        status = RuleStatus.PASS if enabled else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Enable System Audit Logging Daemon",
            category=RuleCategory.LOGGING,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="Enabled" if enabled else "Disabled",
            expected="Enabled",
            description="System audit daemon (auditd or Windows Event Log) must be active and recording events.",
            remediation_bash="systemctl start auditd && systemctl enable auditd",
            remediation_ps="Start-Service -Name EventLog; Set-Service -Name EventLog -StartupType Automatic",
        )

    @staticmethod
    def _check_log_retention(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC7.2-LOG-RETENTION"
        sev = RuleSeverity.MEDIUM
        retention = s.audit_logging.get("retention_days", 0)
        status = RuleStatus.PASS if retention >= 90 else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Audit Log Retention Minimum 90 Days",
            category=RuleCategory.LOGGING,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed=f"{retention} days",
            expected=">= 90 days",
            description="Audit and security event logs must be retained for at least 90 days.",
            remediation_bash="sed -i 's/num_logs = .*/num_logs = 90/' /etc/audit/auditd.conf",
            remediation_ps="wevtutil sl Security /ms:104857600",
        )

    @staticmethod
    def _check_auto_updates(s: HostPostureSnapshot) -> RuleEvaluation:
        rule_id = "CC8.1-AUTO-UPDATES"
        sev = RuleSeverity.MEDIUM
        enabled = s.auto_updates.get("enabled", False)
        status = RuleStatus.PASS if enabled else RuleStatus.FAIL
        return RuleEvaluation(
            rule_id=rule_id,
            title="Automated Security Patch Updates Enabled",
            category=RuleCategory.OS,
            severity=sev,
            weight=SEVERITY_WEIGHTS[sev],
            status=status,
            observed="Enabled" if enabled else "Disabled",
            expected="Enabled",
            description="System must have automatic security patch installation enabled.",
            remediation_bash="apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
            remediation_ps="Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv",
        )
