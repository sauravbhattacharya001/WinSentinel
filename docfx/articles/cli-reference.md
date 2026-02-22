# CLI Reference

WinSentinel includes a full-featured command-line interface for running audits, managing compliance profiles, and viewing security history.

## Basic Usage

```powershell
winsentinel [options]
```

## Options

### General

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help information |
| `--version` | `-v` | Show version information |
| `--quiet` | `-q` | Suppress non-essential output |

### Auditing

| Option | Short | Description |
|--------|-------|-------------|
| `--audit` | `-a` | Run a full security audit |
| `--score` | `-s` | Show current security score only |
| `--modules` | `-m` | Run specific modules (comma-separated) |
| `--threshold` | `-t` | Set minimum score threshold (exit code 1 if below) |
| `--fix-all` | `-f` | Auto-apply all available remediations |

### Compliance Profiles

| Option | Short | Description |
|--------|-------|-------------|
| `--profile` | `-p` | Apply a compliance profile (cis, hipaa, pci-dss, soc2) |
| `--profiles` | | List all available compliance profiles |
| `--baseline` | | Save current state as a baseline snapshot |
| `--compare` | | Compare current state against a saved baseline |
| `--diff` | | Show detailed differences from baseline |

### Ignore Rules

| Option | Description |
|--------|-------------|
| `--ignore` | Add an ignore rule (finding ID or pattern) |
| `--ignore-module` | Ignore all findings from a specific module |
| `--ignore-severity` | Ignore findings at or below a severity level |
| `--ignore-reason` | Reason for the ignore rule |
| `--match-mode` | Matching mode: exact, contains, regex |
| `--expire-days` | Auto-expire the ignore rule after N days |
| `--show-ignored` | Show ignored findings in output |

### Output Formats

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | `-j` | Output results as JSON |
| `--html` | | Output results as HTML report |
| `--markdown` | `--md` | Output results as Markdown |
| `--output` | `-o` | Write output to a file |

### History

| Option | Description |
|--------|-------------|
| `--history` | Show audit history |
| `--days` | Number of days of history to show |
| `--limit` | Maximum number of history entries |
| `--checklist` | Show remediation checklist |
| `--desc` | Sort in descending order |
| `--force` | Force overwrite of existing files |

## Examples

### Run a Full Audit

```powershell
winsentinel --audit
```

### Run Specific Modules

```powershell
winsentinel --audit --modules defender,firewall,network,updates
```

### Apply CIS Compliance Profile

```powershell
winsentinel --audit --profile cis
```

### Export JSON Report

```powershell
winsentinel --audit --json --output report.json
```

### Check Score Meets Threshold

```powershell
# Exits with code 1 if score < 80
winsentinel --audit --threshold 80
```

### Save and Compare Baselines

```powershell
# Save baseline
winsentinel --audit --baseline

# Later, compare against baseline
winsentinel --audit --compare --diff
```

### View Audit History

```powershell
# Last 10 audits
winsentinel --history --limit 10

# Last 7 days
winsentinel --history --days 7
```

### Manage Ignore Rules

```powershell
# Ignore a specific finding
winsentinel --ignore "WD-001" --ignore-reason "Known false positive"

# Ignore with expiration
winsentinel --ignore "FW-003" --expire-days 30 --ignore-reason "Temporary exception"

# Show what's being ignored
winsentinel --audit --show-ignored
```

## Available Modules

| Module | ID | Description |
|--------|----|-------------|
| Windows Defender | `defender` | Antivirus status, definitions, scan history |
| Firewall | `firewall` | Windows Firewall rules and configuration |
| Network Security | `network` | LLMNR, NetBIOS, SMB signing, open ports |
| Windows Update | `updates` | Pending updates, update history |
| User Account | `useraccount` | Password policy, admin accounts, guest status |
| Privacy | `privacy` | Telemetry, location, advertising ID |
| BitLocker | `bitlocker` | Drive encryption status |
| Remote Desktop | `rdp` | RDP configuration and security |
| App Security | `appsecurity` | UAC, SmartScreen, exploit protection |
| Browser | `browser` | Browser security settings |
| Service Hardening | `service` | Service configurations and vulnerabilities |
| Startup Programs | `startup` | Auto-start programs and persistence mechanisms |
| Credential Guard | `credential` | Credential Guard and LSA protection |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Audit completed successfully (or score meets threshold) |
| 1 | Score below threshold or audit error |
