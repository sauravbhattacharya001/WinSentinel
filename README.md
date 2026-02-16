# 🛡️ WinSentinel

**Windows Security Agent — Local-first security auditing, monitoring, and remediation for Windows machines.**

[![Build](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml)

## Features

- **9 Security Audit Modules** — Comprehensive Windows security assessment
- **Real-time Security Score** — 0-100 score with letter grade and category breakdown
- **Chat Interface** — AI-powered security assistant with natural language
- **Quick Fix Actions** — One-click remediation with PowerShell/CMD commands
- **Local-first** — All analysis runs on your machine, no data leaves
- **MSIX Installer** — Packageable as MSIX for easy deployment and sideloading
- **Portable Mode** — Also runs as a standalone self-contained executable

## Security Audit Modules

| Module | What It Checks |
|--------|---------------|
| 🔥 **Firewall** | Windows Firewall status, profile states, rule analysis, dangerous port exposure |
| 🔄 **Updates** | Windows Update status, pending updates, last install date |
| 🛡️ **Defender** | Windows Defender status, real-time protection, definition freshness |
| 👤 **Accounts** | Local users, admin accounts, password policies, guest account |
| 🌐 **Network** | Open ports, listening services, SMB/RDP exposure, LLMNR/NetBIOS poisoning, Wi-Fi security, ARP anomalies, IPv6 exposure |
| ⚙️ **Processes** | Running processes, unsigned executables, suspicious locations, high-privilege analysis |
| 🚀 **Startup** | Startup items, scheduled tasks, registry run keys |
| 💻 **System** | OS version, Secure Boot, BitLocker, UAC, RDP configuration |
| 🔒 **Privacy** | Telemetry, advertising ID, location tracking, clipboard sync, remote assistance, camera/mic permissions |

## Architecture

```
WinSentinel.sln
├── src/
│   ├── WinSentinel.Core/          # Security audit engine (class library)
│   │   ├── Audits/                # 9 audit modules
│   │   ├── Models/                # AuditResult, Finding, Severity
│   │   ├── Services/              # AuditEngine, SecurityScorer
│   │   ├── Helpers/               # ShellHelper, PowerShellHelper
│   │   └── Interfaces/            # IAuditModule
│   │
│   ├── WinSentinel.App/           # WPF desktop application
│   │   ├── Views/                 # Dashboard, Chat, AuditDetail pages
│   │   ├── ViewModels/            # MVVM view models (CommunityToolkit.Mvvm)
│   │   ├── Services/              # ChatAiService (Ollama/rule-based)
│   │   └── Controls/              # Converters, utilities
│   │
│   └── WinSentinel.Installer/     # MSIX packaging
│       ├── AppxManifest.xml       # Package manifest
│       ├── Build-Msix.ps1         # Automated MSIX build script
│       └── Assets/                # App icons
│
└── tests/
    └── WinSentinel.Tests/         # 124 xUnit tests (unit + integration)
```

## AI Backend (Tiered)

1. **Ollama** — Local LLM (llama3, mistral, phi3) at `http://localhost:11434`
2. **Rule-based** — Built-in pattern matching for common security queries (passwords, ransomware, encryption, VPN, malware, backup, phishing)

## Quick Start

### Prerequisites
- Windows 10/11
- .NET 8 SDK

### Build & Run

```bash
# Clone
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel

# Build
dotnet build WinSentinel.sln -p:Platform=x64

# Run
dotnet run --project src/WinSentinel.App -p:Platform=x64

# Test (124 tests)
dotnet test -p:Platform=x64
```

### Build MSIX Package

```powershell
# Option 1: Automated script
cd src\WinSentinel.Installer
.\Build-Msix.ps1

# Option 2: Manual
dotnet publish src\WinSentinel.App -c Release -r win-x64 --self-contained -o publish\msix-content
# Copy AppxManifest.xml and Assets to publish\msix-content
# Run: makeappx pack /d publish\msix-content /p WinSentinel.msix /o
```

### Install MSIX (Sideload)

1. Enable **Developer Mode** in Windows Settings > Privacy & Security > For Developers
2. Right-click the `.msix` file → **Install**
3. Or run: `Add-AppxPackage -Path WinSentinel.msix`

### Chat Commands

- `Run full audit` — Execute all 9 security modules
- `Check firewall` — Run firewall audit only
- `Check defender` — Check antivirus status
- `Security score` — Calculate current security score
- Ask about passwords, ransomware, encryption, VPNs, backups, phishing, and more

## Security Score

The security score (0-100) is calculated by weighting findings across all modules:

- **Critical** finding: -15 points
- **Warning** finding: -5 points
- **Info** finding: -1 point
- **Pass** finding: +0 (baseline)

Score starts at 100 with deductions applied. Categories are weighted equally. Letter grades: A+ (95+) through F (<40).

## Contributing

This is a private project. Contact the owner for access.

## License

MIT — see [LICENSE](LICENSE)
