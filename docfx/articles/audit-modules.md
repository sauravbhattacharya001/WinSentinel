# Audit Modules

WinSentinel ships with 13 audit modules that cover comprehensive Windows security assessment. Each module runs independently and produces findings with severity levels and remediation guidance.

## Module Overview

| Module | Class | Checks | Focus Area |
|--------|-------|--------|------------|
| [Defender](#defender-audit) | `DefenderAudit` | 5 | Antivirus status, definitions, real-time protection |
| [Firewall](#firewall-audit) | `FirewallAudit` | 6 | Firewall profile status, inbound rules |
| [Network](#network-audit) | `NetworkAudit` | 8 | LLMNR, NetBIOS, SMB signing, open ports |
| [Updates](#updates-audit) | `UpdateAudit` | 4 | Pending updates, update age |
| [Account](#account-audit) | `AccountAudit` | 5 | Password policy, admin accounts, guest status |
| [Privacy](#privacy-audit) | `PrivacyAudit` | 7 | Telemetry, location, advertising ID |
| [Encryption](#encryption-audit) | `EncryptionAudit` | 4 | BitLocker, drive encryption |
| [App Security](#app-security-audit) | `AppSecurityAudit` | 8 | UAC, SmartScreen, exploit protection |
| [Browser](#browser-audit) | `BrowserAudit` | 6 | Browser security settings |
| [System](#system-audit) | `SystemAudit` | 5 | OS version, Secure Boot, TPM |
| [Startup](#startup-audit) | `StartupAudit` | 4 | Auto-start programs, persistence |
| [Process](#process-audit) | `ProcessAudit` | 4 | Running processes, suspicious activity |
| [Event Log](#event-log-audit) | `EventLogAudit` | 6 | Security events, failed logins, audit policy |

## Severity Levels

Each finding is assigned a severity:

| Level | Weight | Description |
|-------|--------|-------------|
| **Critical** | 10 | Immediate security risk, must fix now |
| **High** | 7 | Significant vulnerability, fix soon |
| **Medium** | 4 | Moderate risk, should address |
| **Low** | 2 | Minor issue, good to fix |
| **Info** | 0 | Informational, no action required |

## Defender Audit

Checks Windows Defender / Microsoft Defender Antivirus status.

**Checks:**
- Real-time protection enabled
- Virus definition age (warns if > 3 days)
- Quick scan recency (warns if > 7 days)
- Full scan recency (warns if > 30 days)
- Cloud-delivered protection enabled

## Firewall Audit

Audits Windows Firewall configuration across all profiles.

**Checks:**
- Domain profile enabled
- Private profile enabled
- Public profile enabled
- Default inbound action (should be Block)
- Suspicious allow-all inbound rules
- Overly permissive rules with wide port ranges

## Network Audit

Deep network security assessment.

**Checks:**
- LLMNR disabled (prevents relay attacks)
- NetBIOS over TCP/IP disabled
- SMB signing required (prevents NTLM relay)
- IPv6 configuration
- Open listening ports
- DNS configuration
- Network adapter security
- Wi-Fi security protocols

## Updates Audit

Windows Update status and compliance.

**Checks:**
- Pending critical/security updates
- Time since last update check
- Automatic updates enabled
- Update installation age

## Account Audit

User account security assessment.

**Checks:**
- Number of administrator accounts
- Guest account disabled
- Password policy requirements
- Account lockout policy
- Last password change age

## Privacy Audit

Windows privacy settings audit.

**Checks:**
- Telemetry level (should be minimal)
- Advertising ID disabled
- Location tracking
- Activity history
- Diagnostic data
- Feedback frequency
- Speech recognition privacy

## Encryption Audit

Drive and data encryption status.

**Checks:**
- BitLocker enabled on OS drive
- BitLocker on data drives
- Recovery key backed up
- Encryption method strength

## App Security Audit

Application-level security controls.

**Checks:**
- UAC enabled and level
- SmartScreen enabled
- Exploit protection (DEP, ASLR, CFG)
- Developer mode status
- Sideloading policy
- PowerShell execution policy
- .NET Framework security
- Windows Script Host

## Browser Audit

Web browser security configuration.

**Checks:**
- Default browser identification
- SmartScreen for Edge
- Pop-up blocker
- Safe browsing settings
- Extension security
- Password manager integration

## System Audit

Core system security posture.

**Checks:**
- Windows version and build (end-of-life check)
- Secure Boot enabled
- TPM 2.0 present and active
- Kernel DMA protection
- Virtualization-based security (VBS)

## Startup Audit

Auto-start program analysis.

**Checks:**
- Registry Run/RunOnce entries
- Startup folder programs
- Scheduled tasks with suspicious triggers
- Service auto-start entries

## Process Audit

Running process security analysis.

**Checks:**
- Processes running as SYSTEM
- Unsigned executables
- Processes from temporary directories
- High-privilege process count

## Event Log Audit

Security event log analysis.

**Checks:**
- Failed login attempts (brute force detection)
- Account lockout events
- Privilege escalation events
- Audit policy configuration
- Log size and retention
- Critical security events (last 24h)

## Creating Custom Modules

See the [Extending WinSentinel](extending.md) guide for detailed instructions on creating your own audit modules.
