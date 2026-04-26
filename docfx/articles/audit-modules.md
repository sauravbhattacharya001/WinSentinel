# Audit Modules

WinSentinel ships with **30 audit modules** covering comprehensive Windows security assessment. Each module runs independently and produces findings with severity levels and remediation guidance.

## Module Overview

| Module | Class | Focus Area |
|--------|-------|------------|
| [Account](#account-audit) | `AccountAudit` | Password policy, admin accounts, guest status |
| [App Security](#app-security-audit) | `AppSecurityAudit` | UAC, SmartScreen, exploit protection |
| [Backup](#backup-audit) | `BackupAudit` | VSS, System Restore, File History, ransomware resilience |
| [Bluetooth](#bluetooth-audit) | `BluetoothAudit` | Bluetooth radio, discoverable mode, paired devices |
| [Browser](#browser-audit) | `BrowserAudit` | Browser security settings, extensions |
| [Certificate](#certificate-audit) | `CertificateAudit` | Expired/weak certs, untrusted root CAs |
| [Credential Exposure](#credential-exposure-audit) | `CredentialExposureAudit` | Plaintext creds, SSH keys, git stores, RDP files |
| [Defender](#defender-audit) | `DefenderAudit` | Antivirus status, definitions, real-time protection |
| [DNS](#dns-audit) | `DnsAudit` | DNS servers, DoH, cache poisoning, hosts tampering |
| [Driver](#driver-audit) | `DriverAudit` | Unsigned/vulnerable drivers, BYOVD detection |
| [Encryption](#encryption-audit) | `EncryptionAudit` | BitLocker, drive encryption |
| [Environment](#environment-audit) | `EnvironmentAudit` | PATH hijacking, secrets in env vars, proxy settings |
| [Event Log](#event-log-audit) | `EventLogAudit` | Security events, failed logins, audit policy |
| [Firewall](#firewall-audit) | `FirewallAudit` | Firewall profile status, inbound rules |
| [Group Policy](#group-policy-audit) | `GroupPolicyAudit` | Security-relevant GPO settings |
| [Network](#network-audit) | `NetworkAudit` | LLMNR, NetBIOS, SMB signing, open ports |
| [PowerShell](#powershell-audit) | `PowerShellAudit` | Execution policy, v2 engine, logging config |
| [Privacy](#privacy-audit) | `PrivacyAudit` | Telemetry, location, advertising ID |
| [Process](#process-audit) | `ProcessAudit` | Running processes, suspicious activity |
| [Registry](#registry-audit) | `RegistryAudit` | UAC, AutoRun, credential caching, WDigest |
| [Remote Access](#remote-access-audit) | `RemoteAccessAudit` | RDP, SSH, VNC, TeamViewer, WinRM, Remote Registry |
| [Scheduled Task](#scheduled-task-audit) | `ScheduledTaskAudit` | Persistence mechanisms, suspicious tasks |
| [Service](#service-audit) | `ServiceAudit` | Unquoted paths, SYSTEM services, missing binaries |
| [SMB Share](#smb-share-audit) | `SmbShareAudit` | SMBv1, signing, admin shares, permissive ACLs |
| [Software Inventory](#software-inventory-audit) | `SoftwareInventoryAudit` | Unsigned software, PUPs, orphaned installs |
| [Startup](#startup-audit) | `StartupAudit` | Auto-start programs, persistence |
| [System](#system-audit) | `SystemAudit` | OS version, Secure Boot, TPM |
| [Updates](#updates-audit) | `UpdateAudit` | Pending updates, update age |
| [Virtualization](#virtualization-audit) | `VirtualizationAudit` | Hyper-V, WSL, Sandbox, Docker, Credential Guard |
| [Wi-Fi](#wi-fi-audit) | `WifiAudit` | Weak encryption profiles, auto-connect, MAC randomization |

## Severity Levels

Each finding is assigned a severity:

| Level | Weight | Description |
|-------|--------|-------------|
| **Critical** | 10 | Immediate security risk, must fix now |
| **High** | 7 | Significant vulnerability, fix soon |
| **Medium** | 4 | Moderate risk, should address |
| **Low** | 2 | Minor issue, good to fix |
| **Info** | 0 | Informational, no action required |

---

## Account Audit

User account security assessment.

**Checks:**
- Number of administrator accounts
- Guest account disabled
- Password policy requirements
- Account lockout policy
- Last password change age

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

## Backup Audit

Backup and recovery security posture — critical for ransomware resilience.

**Checks:**
- Volume Shadow Copy (VSS) service status and shadow copies
- System Restore configuration and restore points
- File History settings
- Windows Backup configuration
- Ransomware resilience indicators (VSS accessible, recent backups)
- Recovery partition presence

## Bluetooth Audit

Bluetooth attack surface and device security.

**Checks:**
- Bluetooth radio left enabled when not needed (attack surface)
- Discoverable mode enabled (BlueBorne, BlueSmack, BlueSnarfing risk)
- Paired devices with outdated or unknown profiles
- Bluetooth services exposing sensitive capabilities (OBEX, PAN, serial)
- Missing or weak Bluetooth authentication/encryption settings

## Browser Audit

Web browser security configuration.

**Checks:**
- Default browser identification
- SmartScreen for Edge
- Pop-up blocker
- Safe browsing settings
- Extension security
- Password manager integration

## Certificate Audit

Windows certificate store security.

**Checks:**
- Expired certificates
- Soon-to-expire certificates
- Weak signature algorithms (SHA-1, MD5)
- Untrusted root CAs
- Self-signed certificates in trusted stores

## Credential Exposure Audit

Credential storage and exposure risk assessment.

**Checks:**
- Windows Credential Manager entries (generic/domain/certificate)
- Git credential stores (plaintext, cache, manager)
- SSH key security (passphrase-less keys, weak algorithms, permissions)
- Plaintext credential files in common locations
- Saved RDP connection credentials (.rdp files with passwords)
- Browser credential stores
- Cloud credential configurations
- Sensitive file permissions

## Defender Audit

Checks Windows Defender / Microsoft Defender Antivirus status.

**Checks:**
- Real-time protection enabled
- Virus definition age (warns if > 3 days)
- Quick scan recency (warns if > 7 days)
- Full scan recency (warns if > 30 days)
- Cloud-delivered protection enabled

## DNS Audit

DNS security configuration assessment.

**Checks:**
- DNS servers set to known-insecure or unexpected addresses
- DNS-over-HTTPS (DoH) not enabled
- DNS cache poisoning exposure (large cache, no secure validation)
- LLMNR/NetBIOS name resolution enabled (spoofing risk)
- DNS client settings that leak queries to untrusted networks
- Hosts file tampering

## Driver Audit

Loaded kernel and user-mode driver security.

**Checks:**
- Unsigned or self-signed drivers (code integrity bypass)
- Drivers loaded from suspicious/user-writable paths
- Known vulnerable drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks
- Drivers with revoked certificates
- Driver age analysis (very old drivers may have unpatched vulns)

## Encryption Audit

Drive and data encryption status.

**Checks:**
- BitLocker enabled on OS drive
- BitLocker on data drives
- Recovery key backed up
- Encryption method strength

## Environment Audit

Environment variable security assessment.

**Checks:**
- PATH hijacking via writable or suspicious directories (MITRE T1574.007)
- Secrets leaked in environment variables (API keys, tokens, passwords)
- Proxy settings that could redirect traffic to untrusted servers
- Dangerous PATHEXT entries enabling script execution
- TEMP/TMP directories with overly permissive ACLs

## Event Log Audit

Security event log analysis.

**Checks:**
- Failed login attempts (brute force detection)
- Account lockout events
- Privilege escalation events
- Audit policy configuration
- Log size and retention
- Critical security events (last 24h)

## Firewall Audit

Audits Windows Firewall configuration across all profiles.

**Checks:**
- Domain profile enabled
- Private profile enabled
- Public profile enabled
- Default inbound action (should be Block)
- Suspicious allow-all inbound rules
- Overly permissive rules with wide port ranges

## Group Policy Audit

Security-relevant Group Policy settings via registry.

**Checks:**
- Account lockout policies
- Password complexity requirements
- Audit and logging policies
- Security option configurations
- Restricted software policies

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

## PowerShell Audit

PowerShell security configuration and logging.

**Checks:**
- Unrestricted execution policy allowing arbitrary script execution
- PowerShell v2 engine enabled (downgrade attack vector)
- Script block logging disabled (lack of command visibility)
- Module logging disabled (can't track loaded modules)
- Transcription logging disabled (no session transcripts)

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

## Process Audit

Running process security analysis.

**Checks:**
- Processes running as SYSTEM
- Unsigned executables
- Processes from temporary directories
- High-privilege process count

## Registry Audit

Windows Registry security analysis.

**Checks:**
- UAC disabled or weakened (ConsentPromptBehaviorAdmin, EnableLUA)
- Remote Desktop enabled without NLA
- AutoPlay/AutoRun not disabled (infection vector)
- Credential caching (CachedLogonsCount)
- WDigest plain-text credential storage

## Remote Access Audit

Remote access exposure and configuration.

**Checks:**
- RDP enabled with weak settings (no NLA, default port, weak encryption)
- SSH server exposure without key-only authentication
- VNC/TeamViewer/AnyDesk/other remote tools running with weak config
- Remote Desktop Users group membership
- WinRM/PSRemoting exposure
- Remote Registry service enabled
- Remote Assistance enabled

## Scheduled Task Audit

Windows Scheduled Tasks security analysis (MITRE T1053).

**Checks:**
- Tasks running as SYSTEM/admin with suspicious actions
- Tasks executing from writable/temp/user directories
- Hidden tasks or tasks with missing/unsigned executables
- Tasks triggered at logon/startup (persistence mechanism)
- Tasks running encoded PowerShell or cmd /c chains

## Service Audit

Windows services security analysis.

**Checks:**
- Unquoted service paths (privilege escalation via path interception)
- Services running as SYSTEM from user-writable or suspicious directories
- Non-standard services running with highest privileges
- Disabled security-critical services (Defender, Firewall, etc.)
- Services with suspicious executable paths (temp, downloads, user dirs)
- Services set to auto-start that point to missing binaries
- Services using cmd.exe or powershell.exe as wrappers

## SMB Share Audit

SMB and network share security.

**Checks:**
- SMBv1 protocol enabled (MITRE T1210, WannaCry/NotPetya vector)
- SMB signing not required (MITRE T1557.001, relay attacks)
- Administrative shares (C$, ADMIN$, IPC$) exposed
- User-created shares with permissive access (Everyone/Authenticated Users)

## Software Inventory Audit

Installed software security analysis.

**Checks:**
- Unsigned or tampered executables
- Programs installed in non-standard/suspicious locations
- Outdated software with known vulnerability indicators
- Potentially Unwanted Programs (PUPs) based on heuristic patterns
- Orphaned installations (uninstaller missing or broken)

## Startup Audit

Auto-start program analysis.

**Checks:**
- Registry Run/RunOnce entries
- Startup folder programs
- Scheduled tasks with suspicious triggers
- Service auto-start entries

## System Audit

Core system security posture.

**Checks:**
- Windows version and build (end-of-life check)
- Secure Boot enabled
- TPM 2.0 present and active
- Kernel DMA protection
- Virtualization-based security (VBS)

## Updates Audit

Windows Update status and compliance.

**Checks:**
- Pending critical/security updates
- Time since last update check
- Automatic updates enabled
- Update installation age

## Virtualization Audit

Virtualization and container security.

**Checks:**
- Hyper-V isolation and settings
- WSL version, distribution security, networking exposure
- Windows Sandbox availability and configuration
- Docker Desktop / container daemon security
- Credential Guard and VBS (Virtualization-Based Security)
- Hypervisor-enforced code integrity (HVCI)

## Wi-Fi Audit

Wi-Fi security configuration.

**Checks:**
- Saved profiles using weak/no encryption (Open, WEP, WPA-TKIP)
- Auto-connect to insecure or public networks
- Cleartext password exposure in saved profiles
- Hosted network / WiFi Direct exposure
- MAC address randomization not enabled

---

## Creating Custom Modules

See the [Extending WinSentinel](extending.md) guide for detailed instructions on creating your own audit modules.
