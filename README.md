<div align="center">

# 🛡️ WinSentinel

### Real-time Windows Security Auditing & Remediation

[![Build & Test](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml)
[![Release](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/release.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/releases)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Windows 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows11)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-192%20passing-brightgreen)]()

**13 security audit modules • CLI & GUI • Real-time scoring • One-click fixes • AI chat assistant**

*Your machine's security shouldn't be a mystery. WinSentinel scans, scores, and fixes — all locally.*

[🚀 Quick Start](#-quick-start) · [📦 Install](#-install-msix) · [📖 Docs](https://sauravbhattacharya001.github.io/WinSentinel/) · [🐛 Issues](https://github.com/sauravbhattacharya001/WinSentinel/issues)

---

</div>

## 📸 Sample Audit Output

```
╔══════════════════════════════════════════════════════╗
║           WinSentinel Security Audit Report          ║
║              2026-02-15 22:16:00 PST                 ║
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

> *Real output from a Windows 11 machine — your results will vary based on your configuration.*

---

## ⚡ What Is WinSentinel?

WinSentinel is a **local-first** Windows security auditor built with .NET 8 and WPF. It runs **13 independent audit modules** that scan your system's security posture, produce a **0-100 security score** with letter grade, and offer **actionable remediation** — including one-click PowerShell fix scripts. Use the **WPF GUI** for interactive exploration or the **CLI** for scripting and CI/CD pipelines.

**No cloud. No telemetry. Everything stays on your machine.**

---

## 🔍 The 13 Audit Modules

| Module | What It Scans | Checks |
|:---:|:---|:---|
| 🔥 | **Firewall** | Windows Firewall status, all profile states (Domain/Private/Public), rule analysis, dangerous port exposure (RDP 3389, SMB 445, Telnet 23) |
| 🔄 | **Updates** | Windows Update service status, pending updates count, last successful install date, update source configuration |
| 🛡️ | **Defender** | Real-time protection, cloud protection, behavior monitoring, definition age, tamper protection, PUA detection |
| 👤 | **Accounts** | Local users enumeration, admin account audit, password policies, guest account status, empty passwords check |
| 🌐 | **Network** | Open ports & listening services, SMB/RDP exposure, LLMNR & NetBIOS poisoning vectors, Wi-Fi security, ARP anomalies, IPv6 exposure |
| ⚙️ | **Processes** | Running processes audit, unsigned executable detection, suspicious path analysis, high-privilege process monitoring |
| 🚀 | **Startup** | Startup programs, scheduled tasks, registry Run/RunOnce keys, service startup types |
| 💻 | **System** | OS version & build, Secure Boot status, BitLocker encryption, UAC level, RDP configuration, DEP/NX status |
| 🔒 | **Privacy** | Telemetry level, advertising ID, location tracking, clipboard sync, remote assistance, camera/mic permissions, activity history |

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

# Run the WPF app
dotnet run --project src/WinSentinel.App -p:Platform=x64

# Run tests (192+ tests)
dotnet test -p:Platform=x64
```

### Run Audit from CLI

```powershell
# Quick one-liner — runs all 13 modules and prints results
.\RunAudit.ps1
```

---

## 💻 CLI Mode

WinSentinel includes a full-featured command-line interface (`winsentinel.exe`) for scripting, automation, and CI/CD pipelines.

### Build the CLI

```bash
dotnet build src/WinSentinel.Cli -p:Platform=x64
# Output: src/WinSentinel.Cli/bin/x64/Debug/net8.0-windows/winsentinel.exe
```

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

# Quick score check
winsentinel --score

# Quiet mode — just the score
winsentinel --score --quiet

# CI/CD gate: fail pipeline if score < 90
winsentinel --audit --threshold 90

# Auto-fix all fixable findings
winsentinel --fix-all

# JSON audit saved to file with threshold check
winsentinel --audit --json -o results.json --threshold 85

# View audit history (last 30 days)
winsentinel --history

# View last 7 days of history
winsentinel --history --days 7

# Compare latest two audit runs side-by-side
winsentinel --history --compare

# Show what changed between runs (new/resolved findings)
winsentinel --history --diff

# Export history as JSON
winsentinel --history --json -o history.json

# Export comparison as JSON
winsentinel --history --compare --json -o compare.json
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

## 📦 Install (MSIX)

### One-Command Install

```powershell
# Run as Administrator — imports cert, installs MSIX, done!
.\Install-WinSentinel.ps1
```

### Build MSIX from Source

```powershell
cd src\WinSentinel.Installer
.\Build-Msix.ps1
# Output: dist\WinSentinel.msix
```

### Manual Sideload

1. Enable **Developer Mode** → Settings > Privacy & Security > For Developers
2. Right-click `.msix` → **Install**
3. Or: `Add-AppxPackage -Path dist\WinSentinel.msix`

---

## 🔧 One-Click Fixes

WinSentinel doesn't just find problems — it helps fix them. Included fix scripts run as Administrator and apply security hardening:

```powershell
# Example: Fix network security findings
.\Fix-Network.ps1

# What it does:
#   ✅ Disables LLMNR (credential poisoning risk)
#   ✅ Enables SMB signing (MITM prevention)
#   ✅ Disables NetBIOS over TCP/IP (poisoning risk)
```

> Re-run the audit after applying fixes to see your score improve!

---

## 🏗️ Architecture

```
WinSentinel.sln
│
├── src/
│   ├── WinSentinel.Core/              # 🧠 Security audit engine (class library)
│   │   ├── Audits/                    #    13 audit modules (Firewall, Defender, Network, etc.)
│   │   ├── Models/                    #    AuditResult, Finding, Severity, SecurityReport
│   │   ├── Services/                  #    AuditEngine, AuditOrchestrator, SecurityScorer
│   │   ├── Helpers/                   #    Shell, PowerShell, Registry, WMI helpers
│   │   └── Interfaces/               #    IAuditModule contract
│   │
│   ├── WinSentinel.App/              # 🖥️ WPF desktop application
│   │   ├── Views/                     #    Dashboard, AuditDetail, Chat pages
│   │   ├── ViewModels/                #    MVVM with CommunityToolkit.Mvvm
│   │   ├── Services/                  #    ChatAiService (Ollama + rule-based)
│   │   └── Controls/                  #    Converters & utilities
│   │
│   ├── WinSentinel.Cli/              # 💻 Command-line interface
│   │   ├── Program.cs                 #    Entry point & command handlers
│   │   ├── CliParser.cs               #    Argument parsing
│   │   └── ConsoleFormatter.cs        #    Color-coded terminal output
│   │
│   ├── WinSentinel.Service/          # 🔄 Background monitoring service
│   │   └── SecurityMonitorWorker     #    Continuous security monitoring
│   │
│   └── WinSentinel.Installer/        # 📦 MSIX packaging
│       ├── AppxManifest.xml           #    Package manifest
│       ├── Build-Msix.ps1            #    Automated build + sign script
│       └── Assets/                    #    App icons & logos
│
└── tests/
    └── WinSentinel.Tests/            # ✅ 192+ xUnit tests
        ├── Audits/                    #    Per-module audit tests
        ├── Cli/                       #    CLI argument parsing tests
        ├── Models/                    #    Data model tests
        └── Services/                  #    Engine & scorer tests
```

**Tech Stack:**
- **Runtime:** .NET 8 (LTS)
- **UI:** WPF with MVVM (CommunityToolkit.Mvvm)
- **Language:** C# 12
- **Testing:** xUnit + 192 tests
- **Packaging:** MSIX with code signing
- **CI/CD:** GitHub Actions (build, test, release)
- **AI:** Ollama (local LLM) + built-in rule engine

---

## 🤖 AI Chat Assistant

WinSentinel includes an AI-powered security chat interface with a tiered backend:

1. **Ollama** (local LLM) — Uses llama3, mistral, or phi3 running at `localhost:11434`
2. **Rule-based** — Built-in pattern matching for common security topics

**Example commands:**
```
> Run full audit          → Executes all 9 security modules
> Check firewall          → Runs firewall audit only
> Check defender          → Checks antivirus status
> Security score          → Calculates current score
> How do I enable BitLocker?  → AI-powered guidance
```

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

## ⚙️ CI/CD

WinSentinel uses **GitHub Actions** for automated builds, testing, and releases:

| Workflow | Trigger | What It Does |
|:---|:---|:---|
| **Build & Test** | Push/PR to `main` | Restore → Build → Run 124 tests → Upload results |
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

- 🧪 Additional audit modules (browser security, Docker, WSL)
- 🔧 More one-click fix scripts
- 🎨 UI themes and customization
- 📊 Audit history and trend tracking
- 🌍 Localization / i18n support

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
- [x] Export reports (HTML, JSON, Text)
- [x] System tray background monitoring
- [x] CLI mode for scripting & CI/CD
- [x] CLI audit history, comparison & diff
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
