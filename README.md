<div align="center">

# 🛡️ WinSentinel

### Your Always-On Windows Security Agent

[![Build & Test](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml)
[![Release](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/release.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/releases)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Windows 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows11)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-192%20passing-brightgreen)]()

**Not just an auditor — a living agent that monitors, detects, and responds 24/7.**

*Real-time threat detection • 13 audit modules • Auto-remediation • Chat control plane • AI-powered correlation*

[🚀 Quick Start](#-quick-start) · [📦 Install](#-installation) · [📖 Docs](https://sauravbhattacharya001.github.io/WinSentinel/) · [🐛 Issues](https://github.com/sauravbhattacharya001/WinSentinel/issues)

---

</div>

## 🏗️ Architecture

WinSentinel is a **two-process architecture**: a background agent that runs as a Windows Service and a WPF dashboard that connects via named pipe IPC.

```
┌─────────────────────────────────┐
│ WinSentinel Agent (Win Service) │
│ ├── Process Monitor             │
│ ├── File System Watcher         │
│ ├── Event Log Listener          │
│ ├── Network Monitor             │
│ ├── Scheduled Auditor (13 mods) │
│ ├── Agent Brain + Correlator    │
│ ├── Auto-Remediator (7 actions) │
│ └── IPC Server (named pipe)     │
└──────────────┬──────────────────┘
               │
┌──────────────┴──────────────────┐
│ WinSentinel UI (WPF Dashboard)  │
│ ├── Live Dashboard              │
│ ├── Real-time Threat Feed       │
│ ├── Chat Control Plane          │
│ ├── Score History & Trends      │
│ ├── Policy Configuration        │
│ └── Export Reports              │
└─────────────────────────────────┘
```

The **agent** runs continuously — even when the dashboard is closed — watching processes, file system changes, event logs, and network activity. When it detects suspicious behavior, it correlates events, classifies threats, and can auto-remediate based on configurable policies. The **dashboard** connects to the agent in real time to show live threat feeds, run commands, and configure policies.

---

## ⚡ Feature Highlights

| Feature | Description |
|:---|:---|
| 🔍 **Real-Time Monitoring** | Four live monitors: Process creation/termination, File System changes, Windows Event Log, and Network connections. Always watching. |
| 🧠 **Agent Brain & Correlator** | AI-powered decision engine that correlates individual events into attack chains. Detects multi-stage attacks that single-event analysis misses. |
| 🔧 **Auto-Remediation** | 7 autonomous response actions (kill process, quarantine file, block IP, disable account, restore hosts, re-enable Defender, revert registry) — all with **full undo** support. |
| 💬 **Chat Control Plane** | 25+ commands plus natural language understanding. Talk to your agent: run audits, query threats, check status, configure policies — all from the chat panel. |
| 📊 **13 Audit Modules** | Comprehensive security auditing: Firewall, Updates, Defender, Accounts, Network, Processes, Startup, System, Privacy, Browser, App Security, Encryption, Event Log. |
| 📈 **Score History & Trends** | SQLite-backed audit history with score tracking over time. See how your security posture changes day by day. |
| 📋 **Export Reports** | Generate reports in HTML, JSON, Text, and Markdown formats. Save and share your audit results. |
| 🔔 **Windows Toast Notifications** | Get notified about critical findings and score drops even when the dashboard is minimized. |
| ⚙️ **Configurable Policies** | Per-category risk tolerance, auto-remediation rules, monitoring sensitivity — tune the agent to your environment. |
| 🖥️ **System Tray Mode** | Minimize to tray and run silently. The agent keeps monitoring in the background. |
| 💻 **CLI Support** | Full command-line interface (`winsentinel.exe`) for scripting, automation, and CI/CD pipelines. JSON/HTML/Text/Markdown output. |

---

## 📸 Sample Audit Output

```
╔══════════════════════════════════════════════════════╗
║           WinSentinel Security Audit Report          ║
║              2026-02-16 16:00:00 PST                 ║
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
║  🌐 Network          80    ████████░░  WARN           ║
║  ⚙️ Processes        90    █████████░  PASS           ║
║  🚀 Startup          95    █████████░  PASS           ║
║  💻 System          100    ██████████  PASS           ║
║  🔒 Privacy          95    █████████░  PASS           ║
║  🌍 Browser          85    ████████░░  PASS           ║
║  📦 App Security     90    █████████░  PASS           ║
║  🔐 Encryption       80    ████████░░  WARN           ║
║  📋 Event Log        85    ████████░░  PASS           ║
╠══════════════════════════════════════════════════════╣
║  Findings: 65 total | 0 critical | 5 warnings       ║
╚══════════════════════════════════════════════════════╝
```

---

## 🔍 Real-Time Monitoring Modules

| Module | What It Watches | Key Detections |
|:---:|:---|:---|
| ⚙️ | **Process Monitor** | New process creation & termination | Suspicious executables, unsigned binaries, processes from temp/download paths, known-bad process names |
| 📁 | **File System Watcher** | File create/modify/delete/rename | Changes to system directories, hosts file tampering, new executables in startup folders, suspicious DLLs |
| 📋 | **Event Log Listener** | Windows Security & System logs | Failed logon attempts, privilege escalation, audit policy changes, service installations, account modifications |
| 🌐 | **Network Monitor** | Active connections & listening ports | New listening services, connections to known-bad IPs, unusual outbound ports, DNS anomalies |

---

## 📊 The 13 Audit Modules

| # | Module | What It Scans |
|:---:|:---:|:---|
| 1 | 🔥 **Firewall** | Windows Firewall status, all profile states (Domain/Private/Public), rule analysis, dangerous port exposure (RDP 3389, SMB 445, Telnet 23) |
| 2 | 🔄 **Updates** | Windows Update service status, pending updates count, last successful install date, update source configuration |
| 3 | 🛡️ **Defender** | Real-time protection, cloud protection, behavior monitoring, definition age, tamper protection, PUA detection |
| 4 | 👤 **Accounts** | Local users enumeration, admin account audit, password policies, guest account status, empty passwords check |
| 5 | 🌐 **Network** | Open ports & listening services, SMB/RDP exposure, LLMNR & NetBIOS poisoning vectors, Wi-Fi security, ARP anomalies, IPv6 exposure |
| 6 | ⚙️ **Processes** | Running processes audit, unsigned executable detection, suspicious path analysis, high-privilege process monitoring |
| 7 | 🚀 **Startup** | Startup programs, scheduled tasks, registry Run/RunOnce keys, service startup types |
| 8 | 💻 **System** | OS version & build, Secure Boot status, BitLocker encryption, UAC level, RDP configuration, DEP/NX status |
| 9 | 🔒 **Privacy** | Telemetry level, advertising ID, location tracking, clipboard sync, remote assistance, camera/mic permissions, activity history |
| 10 | 🌍 **Browser** | Chrome/Edge settings, dangerous extensions, saved password warnings, update status |
| 11 | 📦 **App Security** | Outdated software detection, EOL software flagging, installed program analysis |
| 12 | 🔐 **Encryption** | BitLocker status, EFS usage, certificate store audit, TPM status |
| 13 | 📋 **Event Log** | Failed login attempts, suspicious events, audit policy gaps, recent security events |

---

## 🔧 Auto-Remediation Actions

The agent can take **7 autonomous response actions**, each with full undo support:

| Action | What It Does | Undo |
|:---|:---|:---|
| **Kill Process** | Terminates a suspicious process | N/A (process was running) |
| **Quarantine File** | Moves malicious file to quarantine directory | Restores file to original location |
| **Block IP** | Creates Windows Firewall rule to block an IP | Removes the firewall rule |
| **Disable User Account** | Disables a compromised local account | Re-enables the account |
| **Restore Hosts File** | Reverts hosts file to clean state | Restores from backup |
| **Re-enable Defender** | Turns real-time protection back on | N/A |
| **Revert Registry** | Undoes malicious registry changes | Restores original registry values |

---

## 💬 Chat Control Plane

Talk to your agent using 25+ commands or natural language:

| Command | Description |
|:---|:---|
| `status` | Agent status, uptime, active monitors |
| `threats` / `recent threats` | Show recent threat events |
| `threat stats` | Threat statistics by severity |
| `audit` / `run audit` | Run full 13-module security audit |
| `audit <module>` | Run specific module (e.g., `audit firewall`) |
| `score` | Current security score and grade |
| `history` | Score history over time |
| `monitor status` | Status of all 4 real-time monitors |
| `start monitor <name>` | Start a specific monitor |
| `stop monitor <name>` | Stop a specific monitor |
| `policy` | Show current policy settings |
| `set risk tolerance <low\|medium\|high>` | Adjust risk tolerance |
| `quarantine` | List quarantined files |
| `undo <id>` | Undo a remediation action |
| `journal` | View agent activity journal |
| `export <format>` | Export report (html/json/text/md) |
| `fix all` | Auto-fix all fixable findings |
| `help` | Show all available commands |

Plus **natural language** — ask anything about security and the agent understands context:
```
> Why is my network score low?
> What's the most dangerous thing on my system right now?
> Should I be worried about failed logins?
```

---

## 🚀 Quick Start

### Prerequisites

- **Windows 10 or 11** (x64)
- [**.NET 8 SDK**](https://dotnet.microsoft.com/download/dotnet/8.0) (for building from source)

### Clone, Build & Run

```bash
# Clone the repo
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel

# Build everything
dotnet build WinSentinel.sln -p:Platform=x64

# Run the WPF dashboard
dotnet run --project src/WinSentinel.App -p:Platform=x64

# Run the agent (Windows Service)
dotnet run --project src/WinSentinel.Agent

# Run tests (192+ tests)
dotnet test -p:Platform=x64
```

### Quick Audit (no agent needed)

```powershell
.\RunAudit.ps1
```

---

## 📦 Installation

### Option 1: MSIX Installer (recommended)

```powershell
# Run as Administrator — imports cert, installs MSIX, done!
.\Install-WinSentinel.ps1
```

### Option 2: Install Agent as Windows Service

```powershell
# Build the agent
dotnet build src/WinSentinel.Agent -c Release

# Install as a Windows Service (requires Administrator)
.\Install-Agent.ps1 -Install

# Check service status
.\Install-Agent.ps1 -Status

# Uninstall
.\Install-Agent.ps1 -Uninstall
```

### Option 3: Build MSIX from Source

```powershell
cd src\WinSentinel.Installer
.\Build-Msix.ps1
# Output: dist\WinSentinel.msix
```

### Option 4: Manual Sideload

1. Enable **Developer Mode** → Settings > Privacy & Security > For Developers
2. Right-click `.msix` → **Install**
3. Or: `Add-AppxPackage -Path dist\WinSentinel.msix`

---

## 💻 CLI Mode

Full command-line interface (`winsentinel.exe`) for scripting, automation, and CI/CD pipelines.

### Commands

| Command | Description |
|:---|:---|
| `winsentinel --audit` | Run full security audit with colored output |
| `winsentinel --score` | Print security score and grade only |
| `winsentinel --fix-all` | Run audit and auto-fix all fixable findings |
| `winsentinel --history` | View past audit runs, scores, and trends |
| `winsentinel --help` | Show usage information |
| `winsentinel --version` | Show version info |

### Options

| Flag | Short | Description |
|:---|:---:|:---|
| `--json` | `-j` | Output as machine-parseable JSON |
| `--html` | | Output as HTML report |
| `--markdown` | `--md` | Output as Markdown report |
| `--output <file>` | `-o` | Save output to file |
| `--modules <list>` | `-m` | Run specific modules only (comma-separated) |
| `--quiet` | `-q` | Minimal output — score + exit code only |
| `--threshold <n>` | `-t` | Exit with error if score below n (0-100) |
| `--compare` | | Compare latest two runs side-by-side (with `--history`) |
| `--diff` | | Show new/resolved findings between runs (with `--history`) |
| `--days <n>` | | History lookback period in days (default: 30) |
| `--limit <n>` | `-l` | Max history entries to display (default: 20) |

### Examples

```powershell
# Full audit with colored terminal output
winsentinel --audit

# JSON output for scripting
winsentinel --audit --json

# Save HTML report to file
winsentinel --audit --html -o report.html

# Scan only specific modules
winsentinel --audit --modules firewall,network,privacy

# CI/CD gate: fail pipeline if score < 90
winsentinel --audit --threshold 90

# Auto-fix all fixable findings
winsentinel --fix-all

# Compare latest two audit runs
winsentinel --history --compare

# Show what changed between runs
winsentinel --history --diff
```

### Exit Codes

| Code | Meaning |
|:---:|:---|
| `0` | All checks pass (or score ≥ threshold) |
| `1` | Warnings found (or score < threshold) |
| `2` | Critical findings found |
| `3` | Error during execution |

### Available Modules

`firewall`, `updates`, `defender`, `accounts`, `network`, `processes`, `startup`, `system`, `privacy`, `browser`, `appsecurity`, `encryption`, `eventlog`

---

## 📊 Security Scoring

The score (0-100) starts at 100 with deductions based on finding severity:

| Severity | Impact | Example |
|:---:|:---:|:---|
| 🔴 Critical | **-15 pts** | Real-time protection disabled, firewall off |
| 🟡 Warning | **-5 pts** | LLMNR enabled, outdated definitions |
| 🔵 Info | **-1 pt** | Telemetry at default level |
| ✅ Pass | **0 pts** | Secure Boot enabled, UAC on |

**Grade Scale:** A+ (95+) · A (90-94) · B (80-89) · C (70-79) · D (60-69) · F (<60)

---

## 📸 Screenshots

*Coming soon — screenshots of the live dashboard, threat feed, chat control plane, and policy configuration.*

---

## 🏗️ Project Structure

```
WinSentinel.sln
│
├── src/
│   ├── WinSentinel.Core/              # 🧠 Security audit engine (class library)
│   │   ├── Audits/                    #    13 audit modules
│   │   ├── Models/                    #    AuditResult, Finding, Severity, SecurityReport
│   │   ├── Services/                  #    AuditEngine, AuditOrchestrator, SecurityScorer
│   │   ├── Helpers/                   #    Shell, PowerShell, Registry, WMI helpers
│   │   └── Interfaces/               #    IAuditModule contract
│   │
│   ├── WinSentinel.Agent/            # 🤖 Always-on security agent (Windows Service)
│   │   ├── Modules/                   #    ProcessMonitor, FileSystemWatcher, EventLogListener, NetworkMonitor
│   │   ├── Services/                  #    AgentBrain, ThreatCorrelator, AutoRemediator, ChatHandler
│   │   │                              #    IpcServer, ScheduledAuditModule, AgentJournal, ResponsePolicy
│   │   └── Ipc/                       #    Named pipe IPC message protocol
│   │
│   ├── WinSentinel.App/              # 🖥️ WPF desktop dashboard
│   │   ├── Views/                     #    Dashboard, AuditDetail, Chat, PolicySettings pages
│   │   ├── ViewModels/                #    MVVM with CommunityToolkit.Mvvm
│   │   ├── Services/                  #    IPC client, ChatAiService
│   │   └── Controls/                  #    Converters & utilities
│   │
│   ├── WinSentinel.Cli/              # 💻 Command-line interface
│   │   ├── Program.cs                 #    Entry point & command handlers
│   │   ├── CliParser.cs               #    Argument parsing
│   │   └── ConsoleFormatter.cs        #    Color-coded terminal output
│   │
│   ├── WinSentinel.Service/          # 🔄 Legacy background monitoring service
│   │   └── SecurityMonitorWorker     #    Scheduled scanning (pre-agent)
│   │
│   └── WinSentinel.Installer/        # 📦 MSIX packaging
│       ├── AppxManifest.xml           #    Package manifest
│       ├── Build-Msix.ps1            #    Automated build + sign script
│       └── Assets/                    #    App icons & logos
│
├── tests/
│   └── WinSentinel.Tests/            # ✅ 192+ xUnit tests
│
├── Install-Agent.ps1                  # 🔧 Agent service installer
├── Install-WinSentinel.ps1            # 📦 MSIX installer
├── RunAudit.ps1                       # ⚡ Quick audit script
└── Fix-Network.ps1                    # 🔧 Network security fix script
```

---

## ⚙️ Tech Stack

| Component | Technology |
|:---|:---|
| **Runtime** | .NET 8 (LTS) |
| **UI Framework** | WPF with MVVM (CommunityToolkit.Mvvm) |
| **Language** | C# 12 |
| **Agent** | Microsoft.Extensions.Hosting + Windows Services |
| **IPC** | Named Pipes (System.IO.Pipes) |
| **Database** | SQLite (Microsoft.Data.Sqlite) |
| **Testing** | xUnit (192+ tests) |
| **Packaging** | MSIX with code signing |
| **CI/CD** | GitHub Actions (build, test, release) |
| **AI** | Ollama (local LLM) + built-in rule engine |

---

## ⚙️ CI/CD

| Workflow | Trigger | What It Does |
|:---|:---|:---|
| **Build & Test** | Push/PR to `main` | Restore → Build → Run 192 tests → Upload results |
| **Release** | Tag `v*` | Build → Test → Publish → Create MSIX → Sign → GitHub Release |

**Release artifacts:**
- `WinSentinel-vX.X.X.msix` — Signed MSIX installer
- `WinSentinel-App-vX.X.X.zip` — Portable self-contained app
- `WinSentinel-Service-vX.X.X.zip` — Background monitoring service

---

## 🤝 Contributing

Contributions are welcome! Here's how to get involved:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Ideas for Contributions

- 🔌 Plugin system for custom audit modules
- 🧪 Additional monitoring modules
- 🎨 UI themes and customization
- 🌍 Localization / i18n support
- 🐧 Linux port (cross-platform system auditing)

---

## 🗺️ Roadmap

- [x] 13 security audit modules
- [x] Real-time security scoring (0-100)
- [x] WPF dashboard with MVVM
- [x] AI chat assistant (Ollama + rule-based)
- [x] MSIX packaging & signing
- [x] GitHub Actions CI/CD
- [x] 192+ xUnit tests
- [x] Scheduled / automated scanning
- [x] Audit history & trend graphs
- [x] One-click fix scripts for all findings
- [x] Export reports (HTML, JSON, Text, Markdown)
- [x] System tray background monitoring
- [x] CLI mode for scripting & CI/CD
- [x] **Always-on agent (Windows Service)**
- [x] **Real-time process monitoring**
- [x] **File system change detection**
- [x] **Event log monitoring**
- [x] **Network connection monitoring**
- [x] **Agent Brain with threat correlation**
- [x] **Auto-remediation with undo support**
- [x] **Chat control plane (25+ commands)**
- [x] **Live threat feed in dashboard**
- [x] **Configurable policies**
- [ ] 🔮 Plugin system for custom audit modules
- [ ] 🔮 Linux port (system auditing with .NET cross-platform)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ and C# on Windows 11**

[⭐ Star this repo](https://github.com/sauravbhattacharya001/WinSentinel) · [🐛 Report Bug](https://github.com/sauravbhattacharya001/WinSentinel/issues) · [💡 Request Feature](https://github.com/sauravbhattacharya001/WinSentinel/issues)

</div>
