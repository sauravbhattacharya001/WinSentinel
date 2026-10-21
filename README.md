<div align="center">

# 🛡️ WinSentinel

### Your Always-On Windows Security Agent

[![Build & Test](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml)
[![CodeQL](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/sauravbhattacharya001/WinSentinel/graph/badge.svg)](https://codecov.io/gh/sauravbhattacharya001/WinSentinel)
[![NuGet](https://img.shields.io/nuget/v/WinSentinel.Core?logo=nuget&label=NuGet)](https://www.nuget.org/packages/WinSentinel.Core)
[![Release](https://img.shields.io/github/v/release/sauravbhattacharya001/WinSentinel?include_prereleases&logo=github)](https://github.com/sauravbhattacharya001/WinSentinel/releases)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker)](https://github.com/sauravbhattacharya001/WinSentinel/pkgs/container/winsentinel)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows11)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-5376%20passing-brightgreen)]()
[![Lines of Code](https://img.shields.io/badge/LOC-111k%2B-blue)]()

**Not just an auditor - a living agent that monitors, detects, correlates, and responds 24/7.**

*Real-time threat detection • 64 audit modules • Auto-remediation • Chat control plane • AI-powered correlation • Compliance profiles • Plugin system*

[🚀 Quick Start](#-quick-start) · [📦 Install](#-installation) · [📖 Docs](https://docs.winsentinel.ai) · [🐛 Issues](https://github.com/sauravbhattacharya001/WinSentinel/issues) · [📋 Changelog](https://winsentinel.ai/changelog)

---

</div>

## Why WinSentinel?

Most Windows security tools run once and give you a report. WinSentinel is different:

- **Always on** - runs as a Windows Service, monitoring your system 24/7
- **Correlates events** - doesn't just flag individual events, it detects multi-stage attack patterns
- **Takes action** - auto-remediates threats with full undo support
- **Speaks your language** - chat-based control plane with 25+ commands plus natural language
- **Compliance-aware** - built-in profiles for Home, Enterprise, HIPAA, PCI-DSS, and CIS L1
- **Deeply tested** - 5,376 automated tests across 188 test files
- **Extensible** - plugin architecture with Ed25519-signed community modules

---

## 🏗️ Architecture

Two-process design: a background agent (Windows Service) and a WPF dashboard connected via named pipe IPC.

```mermaid
graph TB
    subgraph Agent["🛡️ WinSentinel Agent (Windows Service)"]
        PM[⚙️ Process Monitor]
        FM[📁 File System Watcher]
        EL[📋 Event Log Listener]
        NM[🌐 Network Monitor]
        SA[📊 Scheduled Auditor<br/>full audit suite]
        AB[🧠 Agent Brain +<br/>Threat Correlator]
        AR[🔧 Auto-Remediator<br/>7 actions + undo]
        IS[🔒 Input Sanitizer]
        IPC_S[📡 IPC Server]
    end

    subgraph Dashboard["💻 WinSentinel Dashboard (WPF)"]
        LD[📊 Live Dashboard +<br/>Score Gauge]
        TF[⚠️ Real-time Threat Feed]
        CC[💬 Chat Control Plane]
        SH[📈 Score History & Trends]
        CP[📋 Compliance Profiles]
        FR[🔕 Finding Rules]
        PC[⚙️ Policy Configuration]
        ER[📤 Export Reports]
    end

    PM & FM & EL & NM -->|events| AB
    SA -->|findings| AB
    AB -->|threats| AR
    AB -->|alerts| IPC_S
    IPC_S <-->|Named Pipe IPC| Dashboard
```

### Threat Detection Flow

```mermaid
flowchart LR
    A[Raw Events] --> B{Monitor<br/>Modules}
    B --> C[Process<br/>Events]
    B --> D[File<br/>Events]
    B --> E[EventLog<br/>Events]
    B --> F[Network<br/>Events]
    C & D & E & F --> G[🧠 Threat<br/>Correlator]
    G -->|Single event| H[Classify &<br/>Score]
    G -->|Multi-event<br/>pattern| I[Attack Chain<br/>Detection]
    H & I --> J{Severity?}
    J -->|Critical/High| K[⚡ Auto-Remediate]
    J -->|Medium| L[⚠️ Alert User]
    J -->|Low/Info| M[📝 Log]
    K --> N[Undo Log]
```

The agent runs continuously - even with the dashboard closed - watching processes, file changes, event logs, and network activity. When it detects suspicious behavior, it correlates events, classifies threats, and auto-remediates based on configurable policies.

---

## ⚡ Features at a Glance

| Category | What You Get |
|:---|:---|
| 🔍 **4 Real-Time Monitors** | Process creation/termination, file system changes, Windows Event Log, network connections - always watching |
| 🧠 **AI-Powered Brain** | Correlates individual events into attack chains. Detects multi-stage attacks that single-event analysis misses |
| 🔧 **7 Auto-Remediation Actions** | Kill process, quarantine file, block IP, disable account, restore hosts, re-enable Defender, revert registry - **all with undo** |
| 💬 **Chat Control Plane** | 25+ commands plus natural language. Run audits, query threats, configure policies - from the chat panel |
| 📊 **64 Audit Modules** | Firewall, Updates, Defender, Accounts, Network, Processes, Startup, System, Privacy, Browser, App Security, Encryption, Event Log, Identity & Credentials, PowerShell, USB/Removable Media, DNS, Drivers, Certificates, Remote Access, and 44 more |
| 📋 **Compliance Profiles** | Home, Enterprise, HIPAA, PCI-DSS, CIS L1 - context-aware scoring with per-profile severity adjustments |
| 🔕 **Finding Suppression** | Ignore/suppress known-acceptable findings with regex rules, expiration dates, and audit trail |
| 📈 **Score History** | SQLite-backed audit tracking with trends, heatmaps, and regression detection |
| 📤 **Export Reports** | HTML, JSON, CSV, SARIF, Text, Markdown - save and share results |
| 🔔 **Toast Notifications** | Critical finding alerts via Windows notification center |
| 💻 **CLI Mode** | Full CLI with 50+ subcommands for scripting, automation, and CI/CD gate checks |
| 🔌 **Plugin System** | Ed25519-signed community plugins with multi-publisher trust model |
| 🎯 **GitHub Action** | Marketplace action for automated security auditing in CI/CD |
| ⚙️ **System Tray** | Minimize to tray and run silently in the background |
| 🛡️ **Input Sanitization** | Centralized security layer prevents command injection in all user-facing inputs |

---

## 📸 Sample Audit Output

```
╔══════════════════════════════════════════════════════╗
║           WinSentinel Security Audit Report          ║
║              2026-02-21 22:35:00 PST                 ║
║           Profile: Enterprise                        ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║         Security Score:  92 / 100   Grade: A         ║
║         ████████████████████████████████░░  92%       ║
║                                                      ║
╠══════════════════════════════════════════════════════╣
║  Module           Score   Status                     ║
╠══════════════════════════════════════════════════════╣
║  🔥 Firewall       100    ██████████  PASS           ║
║  🔄 Updates          95    █████████░  PASS           ║
║  🛡️ Defender        100    ██████████  PASS           ║
║  👤 Accounts        100    ██████████  PASS           ║
║  🌐 Network          90    █████████░  PASS           ║
║  ⚙️ Processes        90    █████████░  PASS           ║
║  🚀 Startup          95    █████████░  PASS           ║
║  💻 System          100    ██████████  PASS           ║
║  🔒 Privacy          95    █████████░  PASS           ║
║  🌍 Browser          85    ████████░░  PASS           ║
║  📦 App Security     90    █████████░  PASS           ║
║  🔐 Encryption       80    ████████░░  WARN           ║
║  📋 Event Log        85    ████████░░  PASS           ║
║  🔑 Identity         90    █████████░  PASS           ║
║  ⚡ PowerShell       85    ████████░░  PASS           ║
║  🔌 USB              95    █████████░  PASS           ║
║  ... +48 more modules                              ║
╠══════════════════════════════════════════════════════╣
║  Findings: 65 total | 0 critical | 5 warnings       ║
║  Suppressed: 2 (accepted risk)                       ║
║  Modules scanned: 64                                 ║
╚══════════════════════════════════════════════════════╝
```

---

## 🚀 Quick Start

### Prerequisites

- **Windows 10 or 11** (x64)
- [**.NET 8 SDK**](https://dotnet.microsoft.com/download/dotnet/8.0) (for building from source)

### Clone, Build & Run

```bash
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel

# Build
dotnet build WinSentinel.sln -p:Platform=x64

# Run the dashboard
dotnet run --project src/WinSentinel.App -p:Platform=x64

# Run tests (4,173 tests)
dotnet test -p:Platform=x64
```

### Quick Audit (no build needed)

```powershell
.\RunAudit.ps1
```

---

## 📦 Installation

### Option 1: .NET Global Tool (Recommended)

```powershell
dotnet tool install --global WinSentinel.Cli
winsentinel --audit
```

### Option 2: WinGet (Windows Package Manager)

```powershell
winget install SauravBhattacharya.WinSentinel
```

### Option 3: MSIX Installer

```powershell
# Downloads cert, installs MSIX - one command
.\Install-WinSentinel.ps1
```

### Option 4: Windows Service

```powershell
dotnet build src/WinSentinel.Agent -c Release

# Install (requires Administrator)
.\Install-Agent.ps1 -Install

# Check status
.\Install-Agent.ps1 -Status
```

### Option 5: Build MSIX from Source

```powershell
cd src\WinSentinel.Installer
.\Build-Msix.ps1
# → dist\WinSentinel.msix
```

---

## 🔍 Real-Time Monitors

| Monitor | What It Watches | Key Detections |
|:---|:---|:---|
| ⚙️ **Process** | Process creation & termination | Suspicious executables, unsigned binaries, temp/download path launches, known-bad names |
| 📁 **File System** | File create/modify/delete/rename | System directory changes, hosts file tampering, startup folder modifications, suspicious DLLs |
| 📋 **Event Log** | Windows Security & System logs | Failed logons, privilege escalation, audit policy changes, service installations, account modifications |
| 🌐 **Network** | Active connections & listening ports | New listeners, known-bad IPs, unusual outbound ports, DNS anomalies |

---

## 📊 The Audit Modules

| # | Module | What It Scans |
|:---:|:---|:---|
| 1 | **Account** | Checks local user accounts, admin membership, password policies, and guest account status. |
| 2 | **App Security** | Detects outdated, end-of-life, and insecure software by scanning installed programs against known-safe minimum versions, flagging EOL products, suspicious installs, duplicate x86/x64 installations, MSIX/AppX sideloading & developer-mode posture, and installed remote-access/RMM tools (T1219 foothold surface). |
| 3 | **Application Control (AppLocker/WDAC)** | Checks application allowlisting - AppLocker rule collections and enforcement, the Application Identity service, WDAC/Code Integrity policy, and Smart App Control - against Essential 8 #1 and CIS Windows L1. |
| 4 | **Attachment Manager / Mark-of-the-Web** | Checks Windows Attachment Manager / Mark-of-the-Web hardening on a single machine: whether downloaded files keep their untrusted zone mark (so SmartScreen and Office Protected View still fire), whether saved attachments are scanned for malware, and whether any file types have been force-classified as low-risk - the controls that decide how safely untrusted downloads are handled. |
| 5 | **Audit Policy** | Checks this machine's advanced audit policy - whether the security-relevant subcategories (Logon, Credential Validation, Process Creation, Audit Policy Change, User Account Management) are recording the Success/Failure events an investigation relies on. |
| 6 | **Automatic Sign-On** | Checks single-machine Windows Automatic Restart Sign-On (ARSO) and sign-in-screen hardening - whether ARSO is disabled (DisableAutomaticRestartSignOn) so the machine does not silently re-establish the last user's session after an update reboot, and whether the sign-in screen is blocked from displaying account details (BlockUserFromShowingAccountDetailsOnSignin) - CIS L1 interactive-logon controls. |
| 7 | **Backup Security** | Checks Volume Shadow Copy, System Restore, File History, backup recency, and ransomware resilience posture. |
| 8 | **Bluetooth Security** | Checks Bluetooth radio state, discoverability, paired device trust, exposed services, authentication settings, and legacy pairing risks. |
| 9 | **Boot Integrity** | Checks single-machine platform boot-integrity and kernel-protection posture - UEFI Secure Boot, Virtualization-Based Security (VBS), Memory Integrity (HVCI), Kernel DMA Protection, and whether the kernel is booted with test signing or debugging enabled - the mitigations that keep the kernel trustworthy. |
| 10 | **Browser** | Checks installed browsers (Chrome, Edge, Firefox), versions, extensions, saved passwords, auto-update, Safe Browsing, SmartScreen, and security settings. |
| 11 | **Certificate** | Checks Windows certificate stores for expired, weak, or untrusted certificates. |
| 12 | **Credential Exposure** | Scans for stored credentials, exposed secrets, and credential storage misconfigurations. |
| 13 | **Credential Protection** | Checks single-machine LSASS credential-theft defenses - LSA Protection (RunAsPPL), Credential Guard (LsaCfgFlags) and WDigest cleartext caching (UseLogonCredential) - to confirm that credentials in LSASS memory are protected against Mimikatz-style dumping. |
| 14 | **Defender** | Checks Windows Defender status, real-time protection, antivirus definition freshness, Attack Surface Reduction (ASR) rules, Controlled Folder Access (anti-ransomware), and PUA (potentially-unwanted application) protection. |
| 15 | **Delivery Optimization** | Checks single-machine Windows Delivery Optimization download-source posture - whether the machine peers update/Store content with other machines and, critically, whether it peers across the public Internet (DODownloadMode=3) - to avoid turning the machine into an Internet-facing content peer. |
| 16 | **Diagnostics Hardening** | Checks single-machine Windows diagnostics / troubleshooting hardening - the scripted-diagnostics (MSDT) engine, the ms-msdt: URL protocol handler behind Follina (CVE-2022-30190), built-in MSDT troubleshooter policy, and the diagnostic-data (telemetry) floor - the local controls that decide how much of the MSDT / diagnostics attack surface is exposed on this box. |
| 17 | **DNS Security** | Checks DNS server configuration, DNS-over-HTTPS status, LLMNR/NetBIOS exposure, hosts file integrity, and cache settings. |
| 18 | **Driver Security** | Checks loaded drivers for unsigned binaries, known vulnerable driver hashes (BYOVD), suspicious load paths, revoked certificates, and driver age risks. |
| 19 | **Encryption** | Checks BitLocker status, TPM availability, EFS usage, certificate store health, TLS/SSL configuration, Credential Guard, DPAPI protection, hibernation / Fast Startup RAM-at-rest exposure, and Kernel DMA Protection, and UEFI Secure Boot. |
| 20 | **Environment Variable Security** | Checks PATH hijacking risks, secrets in environment variables, proxy configuration, and dangerous PATHEXT/TEMP settings. |
| 21 | **Event Log Analysis** | Analyzes Windows Event Logs for failed logins, account lockouts, privilege escalation, suspicious activity, audit policy gaps, service installations, and security events. |
| 22 | **Exploit Mitigation** | Checks system-wide exploit mitigations - SEHOP (exception-chain validation), mandatory image relocation (ASLR / MoveImages), the machine-wide process MitigationOptions policy, and the DEP/NX boot policy - all foundational memory-corruption defenses on a single machine. |
| 23 | **Firewall** | Checks Windows Firewall profile states (Domain/Private/Public), per-profile dropped-packet logging, the default inbound and outbound policies, the inbound allow-rule surface, and over-permissive wide-open inbound rules that let any program accept connections from any address on any port. |
| 24 | **Firewall Logging** | Checks single-machine Windows Firewall logging per profile (Domain/Private/Public) - dropped-packet logging, successful-connection logging, log file size, and log file path - the CIS L1 controls that decide whether the firewall leaves any evidence of scans, blocked C2, or unexpected egress. |
| 25 | **Firewall Rule Analysis** | Deep analysis of individual inbound firewall Allow rules: flags rules exposing dangerous ports (RDP, SMB, WinRM, SQL, Redis, MongoDB, …), overly-permissive wide-open rules, Public-profile exposure, duplicate rules, and shadowed/redundant rules, with an overall firewall risk score. |
| 26 | **Group Policy Security** | Checks security-relevant Group Policy settings including account lockout, NTLM restrictions, audit policy, credential protection, SMB signing, and application whitelisting configuration. |
| 27 | **Hosts File Integrity** | Checks the local hosts file for tampering - security/update domains blackholed to a non-routable address (blocks Windows Update and AV), hostnames redirected to public IPs (traffic hijack / phishing), and unusually large blocklists - to catch a common, low-effort DNS-override attack on a single machine. |
| 28 | **Identity & Credential** | Audits local admin sprawl, stale accounts, password-never-expires flags, LAPS deployment status, cached credential exposure, LSA Protection (RunAsPPL), WDigest cleartext credential caching, LM/NTLM authentication level, and Credential Guard. |
| 29 | **Interactive Logon** | Checks single-machine Windows interactive-logon policy hardening - whether a pre-logon legal-notice banner is configured (LegalNoticeCaption / LegalNoticeText) and, when smart-card logon is in use, whether removing the card locks or logs off the session (ScRemoveOption) - CIS L1 interactive-logon controls. |
| 30 | **Kerberos Hardening** | Checks single-machine Kerberos client encryption-type hardening - the SupportedEncryptionTypes bitmask that controls which cipher suites the host will negotiate - flagging the broken DES suites and the weak RC4 suite (which enables fast offline Kerberoasting) and confirming a strong AES suite is offered. |
| 31 | **LSA Hardening** | Checks single-machine LSA / credential-protection hardening - LSASS Protected Process (RunAsPPL), WDigest plaintext caching, LM hash storage, NTLM dialect restriction, anonymous null-session enumeration, blank-password remote logon, cached domain logon count, cleartext autologon, and outbound/inbound NTLM restriction (RestrictSending/ReceivingNTLMTraffic) - the classic CIS L1 controls that decide how hard it is to lift, replay, or relay credentials on this box. |
| 32 | **Name Resolution** | Checks single-machine name-resolution poisoning hardening - whether LLMNR, NetBIOS over TCP/IP (NBT-NS), mDNS and WPAD proxy auto-discovery are disabled - to remove the Responder/NetNTLM-capture and proxy-MITM surface on untrusted networks. |
| 33 | **Network** | Checks open ports, listening services, SMB/RDP exposure, IPv6, Wi-Fi security, network profile, LLMNR/NetBIOS/WPAD/mDNS, and ARP anomalies. |
| 34 | **Network Protection** | Checks single-machine Microsoft Defender Network Protection - whether outbound connections from any process are blocked when they target low-reputation (malware C2, phishing, exploit-hosting) domains and IPs, whether the feature is enforcing (Block) or only logging (Audit), and whether Defender real-time and cloud-delivered protection are active to back it - the most effective free control against commodity C2 callbacks. |
| 35 | **Office Macro Security** | Checks single-machine Microsoft Office macro-security posture - whether macros run without a prompt (VBAWarnings), whether macros in files from the internet are hard-blocked, and whether Protected View is disabled for risky document origins - to reduce the phishing-borne macro initial-access surface. |
| 36 | **Optional Features** | Checks for risky enabled Windows optional features - SMB 1.0/CIFS, the legacy PowerShell 2.0 engine, and cleartext legacy clients (Telnet, TFTP) - that expand the local attack surface or bypass other controls. |
| 37 | **PowerShell Security** | Checks PowerShell execution policy, logging configuration, language mode, AMSI status, and remoting exposure. |
| 38 | **Print Spooler Hardening** | Checks Print Spooler / PrintNightmare hardening on a single machine: whether the spooler is running, whether printer-driver installation is restricted to administrators (CVE-2021-34527), and whether Point-and-Print suppresses the install/update elevation prompts - the controls on one of the most-exploited Windows privilege-escalation surfaces. |
| 39 | **Privacy** | Checks telemetry level, location tracking, advertising ID, diagnostic data, clipboard sync, and activity history. |
| 40 | **Process** | Checks running processes for unsigned executables, suspicious locations, and known risks. |
| 41 | **Process Lineage** | Analyzes parent-child process relationships to detect suspicious execution chains, LOLBin abuse, and living-off-the-land techniques. |
| 42 | **Registry Security** | Checks registry-based security policies including UAC, Remote Desktop, credential storage, LSASS protection, scripting hosts, and persistence mechanisms. |
| 43 | **Remote Access Security** | Checks RDP configuration, SSH exposure, third-party remote tools, WinRM, Remote Registry, and remote assistance settings for security risks. |
| 44 | **Remote Desktop Hardening** | Checks Remote Desktop (RDP) hardening on a single machine: whether RDP is enabled, whether Network Level Authentication is required, the minimum encryption level, the TLS security layer, and whether RDP listens on the default port 3389 - the primary controls on one of the most-attacked Windows remote-access surfaces. |
| 45 | **Scheduled Task Security** | Checks scheduled tasks for suspicious executables, elevated privileges, persistence mechanisms, encoded commands, and missing binaries. |
| 46 | **Session Lock** | Checks single-machine interactive-session lock and sign-in hardening - machine inactivity auto-lock, a password-protected screensaver fallback, hiding the last user on the logon/locked screen, requiring Ctrl+Alt+Del, and disabling automatic passwordless console logon - CIS L1 session-security controls. |
| 47 | **SmartScreen** | Checks single-machine Windows SmartScreen reputation posture - whether App & File (Explorer) SmartScreen is enabled and set to Block, whether Microsoft Edge SmartScreen and PUA blocking are on, and whether SmartScreen still evaluates Store/App Installer web content - to preserve the built-in reputation check against downloaded-executable droppers and browser-borne malware. |
| 48 | **SMB & Network Share Security** | Checks SMB protocol versions, signing enforcement, share permissions, null session access, encryption status, and hidden share exposure. |
| 49 | **SMB Security Hardening** | Checks SMB server/client signing enforcement, the legacy SMBv1 protocol, SMB share encryption, null-session access, and insecure guest-logon fallback against CIS Windows L1. |
| 50 | **Software Inventory** | Scans installed programs for unsigned executables, outdated software, suspicious install locations, and potentially unwanted programs. |
| 51 | **Startup** | Checks startup items, scheduled tasks, and registry run keys for persistence mechanisms. |
| 52 | **System** | Checks OS version, Secure Boot, BitLocker, UAC level, and RDP configuration. |
| 53 | **Time Synchronization** | Checks single-machine Windows time-synchronization security - the Windows Time service (W32Time) state, the sync source type (NTP / NT5DS / NoSync), the NTP peer relative to the machine's domain role, and whether clock phase-correction caps are bounded - because accurate time underpins Kerberos auth, certificate validity, and log correlation. |
| 54 | **Update** | Checks Windows Update status, pending updates, and last install date. |
| 55 | **USB & Removable Media** | Checks USB device history, autorun/autoplay settings, BitLocker-to-Go coverage, and USB write-protect policies for removable storage. |
| 56 | **User Account Control (UAC) Hardening** | Checks UAC enablement, the admin elevation-prompt behaviour, secure-desktop prompting, Admin Approval Mode for the built-in Administrator, installer detection, and the remote UAC token-filtering override (Pass-the-Hash enabler) against CIS Windows L1. |
| 57 | **Virtualization Security** | Checks Hyper-V, WSL, Windows Sandbox, Docker, and virtualization-based security features for misconfigurations and exposure risks. |
| 58 | **WiFi Security** | Checks saved WiFi profiles for weak encryption, auto-connect risks, password exposure, MAC randomization, and network privacy settings. |
| 59 | **Windows Error Reporting Exposure** | Checks Windows Error Reporting upload posture (additional in-memory data, automatic consent level), local crash-dump writing (WER LocalDumps and full-dump type), and whether WER is disabled - all data exposure / credential-harvesting surfaces on a single machine. |
| 60 | **Windows Installer** | Checks single-machine Windows Installer (MSI) hardening - whether AlwaysInstallElevated is enabled in both HKLM and HKCU (a classic local privilege-escalation path that lets any user install an MSI as SYSTEM), whether ad-hoc MSI installs are restricted (DisableMSI), and whether unprivileged users can override restricted install properties (EnableUserControl) - CIS L1 controls that decide how easily msiexec becomes a local escalation and malware-delivery surface on this box. |
| 61 | **Windows Recall** | Checks single-machine Windows Recall exposure - whether Recall snapshotting is disabled by policy (DisableAIDataAnalysis), whether Recall is blocked from being enabled (AllowRecallEnablement), and whether a Recall snapshot store already exists on disk - to reduce local screen-capture data exposure that can include passwords, tokens and private data. |
| 62 | **Windows Script Host** | Checks single-machine Windows Script Host hardening - whether wscript.exe/cscript.exe are disabled, whether a per-user override re-enables WSH over a machine-wide disable, whether remote script execution is allowed, and whether signed-only (Authenticode) TrustPolicy is enforced - to reduce the .vbs/.js living-off-the-land execution surface. |
| 63 | **Windows Service Security** | Checks Windows services for unquoted paths, excessive privileges, suspicious binaries, disabled security services, and configuration risks. |
| 64 | **WinRM Remote Management Hardening** | Checks Windows Remote Management (WS-Man) service and client hardening - unencrypted traffic, Basic/Digest auth, channel-binding-token enforcement, and wildcard TrustedHosts - against CIS Windows L1. |

---

## 📋 Compliance Profiles

Built-in profiles adjust severity weights and scoring for different security contexts:

| Profile | Target Environment | Key Adjustments |
|:---|:---|:---|
| 🏠 **Home** | Personal/home use | Relaxed - info-level items don't penalize |
| 🏢 **Enterprise** | Corporate workstations | Moderate - emphasizes patching, network, accounts |
| 🏥 **HIPAA** | Healthcare environments | Strict - encryption, audit logging, access control weighted heavily |
| 💳 **PCI-DSS** | Payment card processing | Strict - network segmentation, firewall, patching critical |
| 🔒 **CIS L1** | CIS Benchmarks Level 1 | Comprehensive - baseline security for all organizations |

Switch profiles via the dashboard or CLI to see how your system scores under different compliance frameworks.

---

## 🔧 Auto-Remediation

7 autonomous response actions, each with full undo:

| Action | What It Does | Reversible |
|:---|:---|:---:|
| Kill Process | Terminates suspicious process | - |
| Quarantine File | Moves to quarantine directory | ✅ |
| Block IP | Creates firewall block rule | ✅ |
| Disable Account | Disables compromised account | ✅ |
| Restore Hosts | Reverts hosts file to clean state | ✅ |
| Re-enable Defender | Turns real-time protection back on | - |
| Revert Registry | Undoes malicious registry changes | ✅ |

---

## 💬 Chat Control Plane

25+ commands plus natural language understanding:

```
> status                    # Agent uptime, active monitors
> threats                   # Recent threat events
> audit                     # Run full audit
> audit firewall            # Run specific module
> score                     # Current score and grade
> history                   # Score trend over time
> monitor status            # All 4 monitor states
> start monitor process     # Start specific monitor
> policy                    # Show current policies
> set risk tolerance high   # Adjust sensitivity
> quarantine                # List quarantined files
> undo <id>                 # Reverse a remediation action
> journal                   # Agent activity log
> export html               # Export report
> fix all                   # Auto-fix all fixable findings
```

Natural language works too:

```
> Why is my network score low?
> What's the most dangerous thing on my system?
> Show me failed login attempts from today
```

---

## 💻 CLI Reference

```powershell
# Full audit
winsentinel --audit

# JSON output for scripting
winsentinel --audit --json

# Specific modules only
winsentinel --audit --modules firewall,network,privacy

# CI/CD gate: fail if score < 90
winsentinel --audit --threshold 90

# Auto-fix everything
winsentinel --fix-all

# Compare runs / show delta
winsentinel diff
winsentinel diff <run-id>

# Live watch mode (re-audits on interval)
winsentinel watch --interval 300

# Explain a finding
winsentinel why "LLMNR enabled"

# Export in any format
winsentinel export json                              # Positional
winsentinel export --json                            # Or as a flag
winsentinel export --sarif -o findings.sarif         # SARIF for GitHub Code Scanning
winsentinel export --csv -o report.csv               # CSV for spreadsheets
winsentinel export --markdown -o report.md           # Markdown for issue trackers
winsentinel export                                   # No args => defaults to JSON on stdout

# Manage ignored findings
winsentinel ignore add --pattern "telemetry" --reason "accepted risk"
winsentinel ignore list
winsentinel ignore rm <rule-id>

# Self-update from NuGet
winsentinel self-update
winsentinel self-update --check

# Agent daemon
winsentinel agent start
winsentinel agent status
winsentinel agent install   # as Windows Service

# Fleet management (Pro)
winsentinel fleet status
winsentinel fleet scan-all
winsentinel fleet push-policy --file policy.json

# Plugin management
winsentinel plugin list
winsentinel plugin trust <publisher-key>
```

| Flag / Command | Description |
|:---|:---|
| `--audit` | Run full security audit |
| `--score` | Print score and grade only |
| `--fix-all` | Auto-fix all fixable findings |
| `--history` | View past audit runs |
| `--json` / `--html` / `--md` / `--csv` / `--sarif` | Output format |
| `--output <file>` | Save to file |
| `--modules <list>` | Comma-separated module list |
| `--threshold <n>` | Fail if score below n |
| `--compare` / `--diff` | Compare runs or show deltas |
| `--summary` | Executive security summary |
| `--quiet` | Score + exit code only |
| `diff [run-id]` | Show what changed between scans |
| `watch` | Continuous monitoring with alerts |
| `why <finding>` | Explain why a finding matters |
| `export <format>` | Export results (json, csv, sarif, markdown) |
| `ignore add/list/rm` | Manage finding suppression rules |
| `self-update` | Update CLI from NuGet |
| `agent start/stop/status/install` | Manage the background agent |
| `fleet status/scan-all/push-policy` | Fleet orchestration (Pro) |
| `plugin list/trust/untrust` | Manage community plugins |
| `telemetry enable/disable/status` | Anonymous usage telemetry |

**Exit codes:** `0` = pass, `1` = warnings, `2` = critical, `3` = error

---

## 📊 Scoring

Starts at 100, deductions by severity:

| Severity | Deduction | Example |
|:---:|:---:|:---|
| 🔴 Critical | -15 pts | Real-time protection disabled, firewall off |
| 🟡 Warning | -5 pts | LLMNR enabled, outdated definitions |
| 🔵 Info | -1 pt | Telemetry at default level |
| ✅ Pass | 0 pts | Secure Boot enabled, UAC on |

**Grades:** A+ (95+) · A (90-94) · B (80-89) · C (70-79) · D (60-69) · F (<60)

Compliance profiles adjust these weights contextually - a finding that's info-level for Home use might be a warning under HIPAA.

---

## 🏗️ Project Structure

```
WinSentinel.sln
├── src/
│   ├── WinSentinel.Core/          # Security audit engine (64 modules)
│   │   ├── Audits/                # Firewall, Network, Defender, Identity, etc.
│   │   ├── Models/                # AuditResult, Finding, SecurityReport
│   │   ├── Services/              # AuditEngine, Orchestrator, Scorer
│   │   ├── Plugins/               # Plugin host, Ed25519 verification
│   │   └── Helpers/               # Shell, PowerShell, Registry, WMI
│   │
│   ├── WinSentinel.Agent/         # Always-on agent (Windows Service)
│   │   ├── Modules/               # 4 real-time monitors
│   │   ├── Services/              # Brain, Correlator, Remediator, Chat
│   │   │                          # Journal, Policy, IPC, Sanitizer
│   │   └── Ipc/                   # Named pipe protocol
│   │
│   ├── WinSentinel.App/           # WPF dashboard (MVVM)
│   │   ├── Views/                 # Dashboard, Chat, Policy, Compliance
│   │   ├── ViewModels/            # CommunityToolkit.Mvvm
│   │   └── Services/              # IPC client, ChatAI
│   │
│   ├── WinSentinel.Cli/           # Command-line interface (50+ commands)
│   ├── WinSentinel.Service/       # Service host
│   └── WinSentinel.Installer/     # MSIX packaging
│
├── action/                         # GitHub Action for CI security audits
├── tests/
│   └── WinSentinel.Tests/         # 5,376 xUnit tests (188 files)
│
├── docfx/                          # Documentation site source
├── winget/                         # WinGet manifest templates
├── RunAudit.ps1                   # Quick audit script
├── Install-Agent.ps1              # Service installer
├── Install-WinSentinel.ps1        # MSIX installer
└── Fix-Network.ps1                # Network security fix script
```

**By the numbers:** 111k+ lines of source code, 67k+ lines of tests, 560+ commits, 188 test files.

---

## ⚙️ Tech Stack

| Component | Technology |
|:---|:---|
| Runtime | .NET 8 (LTS) |
| UI | WPF + MVVM (CommunityToolkit.Mvvm) |
| Language | C# 12 |
| Agent | Microsoft.Extensions.Hosting + Windows Services |
| IPC | Named Pipes (System.IO.Pipes) |
| Database | SQLite (Microsoft.Data.Sqlite) |
| Testing | xUnit — 5,376 tests |
| Security | CodeQL scanning, input sanitization |
| Packaging | MSIX with code signing |
| CI/CD | GitHub Actions (build, test, release, CodeQL) |
| AI | Ollama (local LLM) + built-in rule engine |

---

## 📋 Releases

| Version | Date | Highlights |
|:---|:---|:---|
| [**v1.19.1**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.19.1) | 2026-06-01 | Plugin trust model, Ed25519 publisher key, CI hardening |
| [**v1.19.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.19.0) | 2026-05-31 | Plugin architecture, `self-update`, `export` subcommand, `pro activate` |
| [**v1.18.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.18.0) | 2026-05-27 | USB audit module, BVT gating, E2E smoke tests |
| [**v1.17.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.17.0) | 2026-05-26 | Test infrastructure, release prep, roadmap docs |
| [**v1.16.1**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.16.1) | 2026-05-24 | NuGet workflow fix, orphan process reaper |
| [**v1.16.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.16.0) | 2026-05-24 | Agentic advisors (ScheduledTask, Service, WMI, DLL hijack) |
| [**v1.15.1**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.15.1) | 2026-05-22 | Score history, heatmaps, regression predictor, burndown |
| [**v1.15.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.15.0) | 2026-05-21 | Watch mode, attack surface analyzer, grep, playbooks |
| [**v1.14.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.14.0) | 2026-05-20 | Gamification, habits, maturity model, noise reduction |
| [**v1.13.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.13.0) | 2026-05-18 | Risk matrix, coverage analysis, SLA tracking |
| [**v1.12.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.12.0) | 2026-05-16 | Hotspots, tags, dependency graph, timeline |
| [**v1.11.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.11.0) | 2026-05-14 | Compliance framework, benchmark, cost analysis, what-if |
| [**v1.4.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.4.0) | 2026-03-29 | Major feature release |
| [**v1.3.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.3.0) | 2026-03-20 | CLI power tools & hardened security |
| [**v1.2.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.2.0) | 2026-03-16 | Deep system auditing & threat intelligence |
| [**v1.1.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.1.0) | 2026-02-20 | Compliance profiles, finding suppression, remediation checklists |
| [**v1.0.0**](https://github.com/sauravbhattacharya001/WinSentinel/releases/tag/v1.0.0) | 2026-02-17 | Initial release — always-on agent, 4 monitors, AI correlator |

Full changelog at [winsentinel.ai/changelog](https://winsentinel.ai/changelog).

---

## 🔐 Security Model

WinSentinel follows a defense-in-depth approach:

| Layer | Protection |
|:---|:---|
| **Input Sanitization** | All user inputs (chat, CLI, config) pass through a centralized `InputSanitizer` that blocks command injection, path traversal, and control characters |
| **Least Privilege** | The dashboard runs as the current user. Only the agent service and remediation actions require Administrator |
| **Undo Journal** | Every auto-remediation action is logged with full undo metadata - quarantined files can be restored, blocked IPs unblocked, disabled accounts re-enabled |
| **Named Pipe IPC** | Dashboard↔Agent communication uses local-only named pipes (no network exposure). The pipe is ACL-restricted to the installing user and SYSTEM |
| **Finding Suppression Audit Trail** | When you suppress a finding, WinSentinel records who, when, why, and expiration - suppressions don't silently hide real threats |
| **No Outbound Telemetry (by default)** | WinSentinel sends zero data home unless you opt in via `winsentinel telemetry enable`. When opted in, reports are anonymous and stripped of PII. AI features use local Ollama models only |

> **Reporting vulnerabilities:** See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

---

## ❓ Troubleshooting

<details>
<summary><strong>Agent service won't start</strong></summary>

1. Ensure you're running PowerShell as **Administrator**
2. Check .NET 8 is installed: `dotnet --list-runtimes`
3. Review Windows Event Viewer → Application log for `WinSentinel.Agent` errors
4. Try running the agent manually first: `dotnet run --project src/WinSentinel.Agent`

</details>

<details>
<summary><strong>Dashboard can't connect to agent</strong></summary>

1. Verify the agent service is running: `.\Install-Agent.ps1 -Status`
2. Named pipe connections require both processes to run under the same user (or SYSTEM)
3. Some antivirus software blocks named pipe creation - add an exclusion for `WinSentinel.Agent.exe`

</details>

<details>
<summary><strong>False positives in audit results</strong></summary>

1. Use **Finding Rules** in the dashboard to suppress known-acceptable findings
2. Switch to a more appropriate **Compliance Profile** (e.g., Home vs Enterprise)
3. Use `--modules` flag in CLI to skip irrelevant audit modules
4. Open an [issue](https://github.com/sauravbhattacharya001/WinSentinel/issues) if a detection rule is genuinely wrong

</details>

<details>
<summary><strong>Build fails on x86 or ARM</strong></summary>

WinSentinel targets **x64 only**. Always pass `-p:Platform=x64`:
```powershell
dotnet build WinSentinel.sln -p:Platform=x64
dotnet test -p:Platform=x64
```

</details>

<details>
<summary><strong>Network score seems wrong</strong></summary>

1. Run `.\Fix-Network.ps1` to apply recommended network hardening
2. Some findings (LLMNR, NetBIOS) require registry changes + reboot
3. VPN adapters can trigger false "open port" findings - suppress with Finding Rules

</details>

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Test** your changes (`dotnet test -p:Platform=x64`)
4. **Push** and open a Pull Request

**Ideas:** Linux port, UI themes, localization, additional compliance profiles.

WinSentinel supports plugins for custom audit modules. Write your own security checks, share them with the community, or keep them private for your org's specific compliance needs. See [docs/CREATING-PLUGINS.md](docs/CREATING-PLUGINS.md) to build your own plugin.

### CI/CD Integration

Use the official [GitHub Action](https://github.com/sauravbhattacharya001/WinSentinel/tree/main/action) to run security audits in your CI pipeline:

```yaml
- uses: sauravbhattacharya001/WinSentinel@main
  with:
    fail-below: 85                         # fail the job if score < 85 (0 = never fail)
    modules: firewall,network,defender     # comma-separated; omit to run all modules
    sarif: true                            # upload results to GitHub Code Scanning
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with C# on .NET 8 · 111k+ LOC · 5,376 tests · 64 audit modules · Always watching 🛡️**

[⭐ Star](https://github.com/sauravbhattacharya001/WinSentinel) · [🐛 Report Bug](https://github.com/sauravbhattacharya001/WinSentinel/issues) · [💡 Request Feature](https://github.com/sauravbhattacharya001/WinSentinel/issues)

</div>
