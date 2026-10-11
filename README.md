# compliance-soc2-auditor (`soc2audit`)

Automated Infrastructure Policy Posture Evaluator, SOC 2 Trust Services Criteria & CIS Benchmark Rule Engine, Severity-Weighted Gap Assessment, and Cryptographically Signed Tamper-Evident Audit Report Generator. Pure Python standard library implementation.

## Features

- **Multi-Platform Host Posture Engine**: Safe, read-only probing of OS configuration, sensitive file permissions (`/etc/passwd`, `/etc/shadow`, sshd config), listening network ports (flags Telnet, FTP, RSH), password policies, and audit logging.
- **Offline Infrastructure Snapshot Evaluation**: Evaluates JSON snapshots of host configurations, facilitating automated CI/CD pipeline gating and cross-platform verification.
- **SOC 2 & CIS Benchmark Rule Engine**: Pre-built rules across CC6.1, CC6.6, CC6.8, CC7.2, and CC8.1 with severity weightings (Critical: 10, High: 5, Medium: 2, Low: 1).
- **Automated Remediation Synthesizer**: Generates copy-pasteable, idempotent Bash and PowerShell scripts to remediate non-compliant settings.
- **Tamper-Evident Cryptographic Reports**: Emits audit reports cryptographically signed with HMAC-SHA256 over Canonical JSON bodies. Detects single-bit report modifications during verification.

## Installation

```bash
pip install -e .
```

## CLI Usage

### Compliance Posture Audit
```bash
# Audit local host against SOC 2 policies
soc2audit audit

# Audit an offline infrastructure snapshot with 90% threshold
soc2audit audit --snapshot host_snapshot.json --min-score 90.0
```

### Policy Rule Verification
```bash
# Check a specific rule against a snapshot
soc2audit check --rule CC6.1-PWD-MIN-LEN --snapshot host_snapshot.json
```

### Cryptographically Signed Reports
```bash
# Generate signed report
soc2audit report --snapshot host_snapshot.json --output report.json --secret super-secret-key-2026

# Verify audit report integrity
soc2audit verify-report --report report.json --secret super-secret-key-2026
```

## License

MIT License. Copyright (c) 2026 aipd506.
