# 🛡️ WinSentinel

**Windows Security Agent — Local-first security auditing, monitoring, and remediation for Windows machines.**

[![Build](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/sauravbhattacharya001/WinSentinel/actions/workflows/build.yml)

## Features

- **8 Security Audit Modules** — Comprehensive Windows security assessment
- **Real-time Security Score** — 0-100 score with category breakdown
- **Chat Interface** — AI-powered security assistant with natural language
- **Quick Fix Actions** — One-click remediation for common issues
- **Local-first** — All analysis runs on your machine, no data leaves

## Security Audit Modules

| Module | What It Checks |
|--------|---------------|
| 🔥 **Firewall** | Windows Firewall status, profile states, rule analysis |
| 🔄 **Updates** | Windows Update status, pending updates, last install date |
| 🛡️ **Defender** | Windows Defender status, real-time protection, definition freshness |
| 👤 **Accounts** | Local users, admin accounts, password policies, guest account |
| 🌐 **Network** | Open ports, listening services, SMB/RDP exposure |
| ⚙️ **Processes** | Running processes, unsigned executables, suspicious locations |
| 🚀 **Startup** | Startup items, scheduled tasks, registry run keys |
| 💻 **System** | OS version, Secure Boot, BitLocker, UAC, RDP configuration |

## Architecture

```
WinSentinel.sln
├── WinSentinel.Core/          # Security audit engine (class library)
│   ├── Audits/                # 8 audit modules
│   │   ├── FirewallAudit.cs
│   │   ├── UpdateAudit.cs
│   │   ├── DefenderAudit.cs
│   │   ├── AccountAudit.cs
│   │   ├── NetworkAudit.cs
│   │   ├── ProcessAudit.cs
│   │   ├── StartupAudit.cs
│   │   └── SystemAudit.cs
│   ├── Models/                # AuditResult, Finding, Severity
│   ├── Services/              # AuditEngine, SecurityScorer
│   └── Interfaces/            # IAuditModule
│
└── WinSentinel.App/           # WinUI 3 desktop application
    ├── Views/                 # Dashboard, Chat pages
    ├── ViewModels/            # MVVM view models
    ├── Services/              # AI backend, navigation
    └── Helpers/               # Converters, utilities
```

## AI Backend (Tiered)

1. **Windows Copilot Runtime / Phi Silica** — If available on Windows 11 24H2+
2. **Ollama** — Local LLM fallback (llama3, mistral, phi3)
3. **Rule-based** — Built-in pattern matching for common queries

## Quick Start

### Prerequisites
- Windows 10/11
- .NET 8 SDK
- Visual Studio 2022 17.8+ (with WinUI workload) or `dotnet` CLI

### Build & Run

```bash
# Clone
git clone https://github.com/sauravbhattacharya001/WinSentinel.git
cd WinSentinel

# Build
dotnet build

# Run (requires Windows)
dotnet run --project src/WinSentinel.App
```

### Quick Actions in Chat

- `Run full audit` — Execute all 8 security modules
- `Check firewall` — Run firewall audit only
- `Security score` — Calculate current security score
- `Fix <issue>` — Apply recommended remediation

## Security Score

The security score (0-100) is calculated by weighting findings across all modules:

- **Critical** finding: -15 points
- **Warning** finding: -5 points  
- **Info** finding: -1 point
- **Pass** finding: +0 (baseline)

Score starts at 100 and deductions are applied. Categories are weighted equally.

## Screenshots

*Coming soon — WinUI 3 dashboard with security score, category cards, and chat interface.*

## Contributing

This is a private project. Contact the owner for access.

## License

MIT — see [LICENSE](LICENSE)
