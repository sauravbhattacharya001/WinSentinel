# CLI Reference

WinSentinel includes a full-featured command-line interface for running audits, analyzing security posture, managing compliance, and more.

## Basic Usage

```powershell
winsentinel <command> [options]
```

## Commands

### Core

| Command | Short | Description |
|---------|-------|-------------|
| `--audit` | `-a` | Run a full security audit |
| `--score` | `-s` | Show current security score only |
| `--fix-all` | `-f` | Auto-apply all available remediations |
| `--harden` | | Interactive hardening wizard — walks through findings and applies fixes |
| `--status` | | Show current security posture summary |

### History & Trends

| Command | Description |
|---------|-------------|
| `--history` | Show audit history |
| `--trend` | Show score trends over time |
| `--timeline` | Show chronological security event timeline |
| `--checklist` | Show remediation checklist from latest audit |
| `--digest` | Generate a security digest report |

### Analysis

| Command | Description |
|---------|-------------|
| `--age <action>` | Finding age analysis: `report`, `priority`, `chronic`, `new`, `resolved` |
| `--rootcause <action>` | Root cause analysis: `report`, `top`, `causes`, `ungrouped` |
| `--attack-paths` | Analyze attack paths through correlated findings |
| `--whatif <action>` | What-if simulation: `all`, `severity`, `module`, `pattern`, `top` |
| `--threats` | Show current threat landscape |
| `--schedule-optimize` | Optimize audit scheduling based on historical data |

### Compliance & Policy

| Command | Description |
|---------|-------------|
| `--profiles` | List all available compliance profiles |
| `--baseline <action>` | Baseline management: `save`, `list`, `check`, `delete` |
| `--policy <action>` | Policy management: `export`, `import`, `validate`, `diff` |
| `--exemptions <action>` | Exemption review: `review`, `expiring`, `stale`, `unused`, `summary` |
| `--ignore <action>` | Ignore rule management: `add`, `list`, `remove`, `clear`, `purge` |

### Badges & Reports

| Command | Description |
|---------|-------------|
| `--badge <type>` | Generate SVG badges: `score`, `grade`, `findings`, `module`, `all` |
| `--quiz` | Interactive security quiz based on system findings |

### General

| Command | Short | Description |
|---------|-------|-------------|
| `--help` | `-h` | Show help information |
| `--version` | `-v` | Show version information |

---

## Options

### Output Formats

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | `-j` | Output results as JSON |
| `--html` | | Output results as HTML report |
| `--html-dark` | | Use dark theme for HTML output |
| `--html-include-pass` | | Include passing findings in HTML report |
| `--html-title <text>` | | Custom title for HTML report |
| `--markdown` | `--md` | Output results as Markdown |
| `--csv` | | Output results as CSV |
| `--sarif` | | Output results in SARIF format (for IDE/CI integration) |
| `--sarif-include-pass` | | Include passing findings in SARIF output |
| `--output` | `-o` | Write output to a file |
| `--quiet` | `-q` | Suppress non-essential output |

### Audit Options

| Option | Short | Description |
|--------|-------|-------------|
| `--modules` | `-m` | Run specific modules (comma-separated) |
| `--threshold` | `-t` | Minimum score threshold (exit code 1 if below) |
| `--profile` | `-p` | Apply a compliance profile (`cis`, `hipaa`, `pci-dss`, `soc2`, `home`, `developer`, `enterprise`, `server`) |
| `--show-ignored` | | Show ignored findings in output |

### Hardening Options

| Option | Description |
|--------|-------------|
| `--no-prompt` | Non-interactive mode (apply all without confirmation) |
| `--dry-run` | Show what would be done without executing |
| `--include-info` | Include informational findings in hardening |

### History & Trend Options

| Option | Description |
|--------|-------------|
| `--days` | Number of days of history (1-365, default: 30) |
| `--limit` / `-l` | Maximum number of entries (1-100, default: 20) |
| `--compare` | Compare current state against baseline |
| `--diff` | Show detailed differences |
| `--force` | Force overwrite of existing files |
| `--trend-days` | Days of trend data to analyze (1-365, default: 30) |
| `--trend-modules` | Show per-module trend breakdown |
| `--alert-below` | Alert when score drops below threshold (0-100) |

### Finding Age Options

| Option | Description |
|--------|-------------|
| `--age-severity <level>` | Filter by severity |
| `--age-module <name>` | Filter by module |
| `--age-class <type>` | Filter by classification: `chronic`, `recurring`, `new`, `intermittent` |
| `--age-days <n>` | Analysis window in days (1-365, default: 90) |
| `--age-top <n>` | Number of top findings to show (1-100, default: 10) |

### Root Cause Options

| Option | Description |
|--------|-------------|
| `--rootcause-top <n>` | Number of top root causes to show (1-50, default: 10) |
| `--rootcause-severity <level>` | Filter by severity |

### What-If Options

| Option | Description |
|--------|-------------|
| `--whatif-top <n>` | Number of top scenarios to simulate (1-100, default: 5) |

### Timeline Options

| Option | Description |
|--------|-------------|
| `--timeline-severity <level>` | Filter by severity |
| `--timeline-max <n>` | Maximum number of events to show |
| `--timeline-module <name>` | Filter by module |

### Baseline Options

| Option | Description |
|--------|-------------|
| `--desc <text>` | Description for baseline save |
| `--force` | Force overwrite of existing baseline |

### Policy Options

| Option | Description |
|--------|-------------|
| `--policy-file <path>` | Policy file path for import/export/diff |
| `--policy-name <name>` | Policy name |
| `--policy-desc <text>` | Policy description |

### Ignore Rule Options

| Option | Description |
|--------|-------------|
| `--ignore-module <name>` | Scope ignore rule to a specific module |
| `--ignore-severity <level>` | Scope ignore rule to a severity level |
| `--ignore-reason <text>` | Reason for the ignore rule |
| `--match-mode <mode>` | Matching mode: `exact`, `contains`, `regex` |
| `--expire-days <n>` | Auto-expire the rule after N days (1-3650) |

### Exemption Options

| Option | Description |
|--------|-------------|
| `--warning-days <n>` | Days before expiry to warn (1-365, default: 7) |
| `--stale-days <n>` | Days before marking exemption as stale (1-3650, default: 90) |

### Badge Options

| Option | Description |
|--------|-------------|
| `--badge-style <style>` | Badge style: `flat`, `flat-square`, `for-the-badge` |

### Quiz Options

| Option | Description |
|--------|-------------|
| `--quiz-count <n>` | Number of questions (1-50, default: 10) |
| `--quiz-difficulty <level>` | Difficulty level |
| `--quiz-category <name>` | Filter questions by category |
| `--quiz-export` | Export quiz to file |

### Digest Options

| Option | Description |
|--------|-------------|
| `--digest-days <n>` | Days of history to include (default: 30) |
| `--digest-format <fmt>` | Output format (default: `text`) |

### Schedule Optimize Options

| Option | Description |
|--------|-------------|
| `--opt-days <n>` | Days of history to analyze (1-365, default: 90) |

---

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

### Export Reports

```powershell
# JSON
winsentinel --audit --json --output report.json

# HTML with dark theme
winsentinel --audit --html --html-dark --output report.html

# CSV for spreadsheet analysis
winsentinel --audit --csv --output findings.csv

# SARIF for IDE integration
winsentinel --audit --sarif --output results.sarif
```

### Check Score Against Threshold

```powershell
# Exit code 1 if score < 80 — useful in CI/CD pipelines
winsentinel --audit --threshold 80
```

### Interactive Hardening

```powershell
# Walk through each finding and decide whether to fix
winsentinel --harden

# Non-interactive: apply all fixes automatically
winsentinel --harden --no-prompt

# Preview without applying
winsentinel --harden --dry-run
```

### Baseline Management

```powershell
# Save current state as a named baseline
winsentinel --baseline save initial-setup --desc "Clean install baseline"

# List all saved baselines
winsentinel --baseline list

# Check current state against a baseline
winsentinel --baseline check initial-setup

# Delete a baseline
winsentinel --baseline delete old-baseline --force
```

### Trend Analysis

```powershell
# Score trends over 30 days (default)
winsentinel --trend

# 90-day trends with per-module breakdown
winsentinel --trend --trend-days 90 --trend-modules

# Alert if score drops below 70
winsentinel --trend --alert-below 70
```

### Finding Age Analysis

```powershell
# Full age report
winsentinel --age report

# Top 5 chronic findings
winsentinel --age chronic --age-top 5

# Priority queue: oldest critical findings first
winsentinel --age priority --age-severity critical
```

### Root Cause Analysis

```powershell
# Full root cause report
winsentinel --rootcause report

# Top 5 root causes
winsentinel --rootcause top --rootcause-top 5
```

### What-If Simulation

```powershell
# What if we fixed all critical findings?
winsentinel --whatif severity critical

# What if we fixed everything in the firewall module?
winsentinel --whatif module firewall

# Top 10 most impactful fixes
winsentinel --whatif top --whatif-top 10
```

### Security Timeline

```powershell
# Full event timeline
winsentinel --timeline

# Critical events in the firewall module
winsentinel --timeline --timeline-severity critical --timeline-module firewall
```

### Policy Management

```powershell
# Export current policy
winsentinel --policy export --policy-file my-policy.json

# Import a policy
winsentinel --policy import --policy-file strict-policy.json

# Validate a policy file
winsentinel --policy validate --policy-file policy.json

# Diff current vs file
winsentinel --policy diff --policy-file other-policy.json
```

### Exemption Review

```powershell
# Full exemption review
winsentinel --exemptions review

# Find exemptions expiring within 14 days
winsentinel --exemptions expiring --warning-days 14

# Find stale exemptions (>90 days)
winsentinel --exemptions stale
```

### Ignore Rules

```powershell
# Add an ignore rule with reason and expiration
winsentinel --ignore add "FW-003" --ignore-reason "Temporary exception" --expire-days 30

# List all ignore rules
winsentinel --ignore list

# Remove a specific rule
winsentinel --ignore remove rule-id-here

# Purge expired rules
winsentinel --ignore purge
```

### Badges

```powershell
# Generate score badge
winsentinel --badge score --output badge.svg

# Generate all badges
winsentinel --badge all --badge-style for-the-badge --output badges/
```

### Security Quiz

```powershell
# 10-question quiz (default)
winsentinel --quiz

# 20 hard questions about network security
winsentinel --quiz --quiz-count 20 --quiz-difficulty hard --quiz-category network
```

### Security Digest

```powershell
# 30-day digest (default)
winsentinel --digest

# 7-day digest as JSON
winsentinel --digest --digest-days 7 --digest-format json
```

---

## Exit Codes

| Code | Meaning |
|:----:|:--------|
| 0 | Audit completed successfully (or score meets threshold) |
| 1 | Score below threshold, warnings found, or audit error |
| 2 | Critical findings found |
| 3 | Error during execution |

## Available Modules

| Module | ID | Description |
|--------|----|-------------|
| Windows Defender | `defender` | Antivirus status, definitions, scan history |
| Firewall | `firewall` | Windows Firewall rules and configuration |
| Network Security | `network` | LLMNR, NetBIOS, SMB signing, open ports |
| Windows Update | `updates` | Pending updates, update history |
| User Account | `useraccount` | Password policy, admin accounts, guest status |
| Privacy | `privacy` | Telemetry, location, advertising ID |
| BitLocker / Encryption | `encryption` | Drive encryption and TLS configuration |
| Remote Access | `remoteaccess` | RDP, WinRM, remote management |
| App Security | `appsecurity` | UAC, SmartScreen, exploit protection |
| Browser | `browser` | Chrome/Edge security settings |
| Service Hardening | `service` | Service configurations and vulnerabilities |
| Startup Programs | `startup` | Auto-start programs and persistence mechanisms |
| Credential Exposure | `credential` | Credential Guard, LSA, WDigest, LSASS hardening |
| DNS | `dns` | DNS configuration, DNS-over-HTTPS |
| Driver | `driver` | Unsigned drivers, vulnerable driver blocklist |
| Certificate | `certificate` | Certificate store, expiration, weak algorithms |
| Bluetooth | `bluetooth` | Adapter state, paired devices, discoverability |
| Backup | `backup` | Shadow copies, System Restore, backup schedules |
| Event Log | `eventlog` | Security log analysis, audit policy gaps |
| Group Policy | `grouppolicy` | Applied GPOs, security-relevant policies |
| PowerShell | `powershell` | Execution policy, script block logging |
| Process | `process` | Running process analysis, unsigned binaries |
| Registry | `registry` | Critical registry key ACLs, autorun entries |
| Scheduled Task | `scheduledtask` | Suspicious task actions, privilege escalation |
| SMB Share | `smbshare` | Network share permissions, SMBv1, null sessions |
| Software Inventory | `software` | Installed software, EOL detection |
| System | `system` | Secure Boot, DEP, ASLR, UAC |
| Virtualization | `virtualization` | Hyper-V, WSL, sandbox isolation |
| Wi-Fi | `wifi` | Saved profiles, encryption strength, open networks |
| Environment | `environment` | PATH hijacking, temp directory permissions |
