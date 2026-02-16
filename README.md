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
# Automated: build, package, and sign in one step
cd src\WinSentinel.Installer
.\Build-Msix.ps1

# The signed MSIX is output to: dist\WinSentinel.msix
```

### Install (One Command)

```powershell
# Run as Administrator — imports cert, installs MSIX, done!
.\Install-WinSentinel.ps1
```

This script:
1. Finds the MSIX in `dist/` (or downloads from GitHub Releases)
2. Imports the signing certificate to your trusted store
3. Installs the MSIX package
4. WinSentinel appears in your Start menu

### Manual Install (Sideload)

1. Enable **Developer Mode** in Windows Settings > Privacy & Security > For Developers
2. Right-click the `.msix` file → **Install**
3. Or run: `Add-AppxPackage -Path dist\WinSentinel.msix`

### Generate a Code Signing Certificate (Dev)

If you're building from source and need a signing certificate:

```powershell
# 1. Create a self-signed code signing certificate
#    Subject MUST match AppxManifest.xml Publisher: CN=WinSentinel
$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject "CN=WinSentinel" `
    -KeyUsage DigitalSignature `
    -FriendlyName "WinSentinel Code Signing (Dev)" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") `
    -NotAfter (Get-Date).AddYears(5)

# 2. Export as PFX (for signing)
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" `
    -FilePath src\WinSentinel.Installer\certs\WinSentinel-Dev.pfx `
    -Password $password

# 3. Export public cert (for trust import on other machines)
Export-Certificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" `
    -FilePath src\WinSentinel.Installer\certs\WinSentinel-Dev.cer

# 4. Build signed MSIX
cd src\WinSentinel.Installer
.\Build-Msix.ps1 -CertPassword "YourPassword"
```

> **Note:** The `certs/` directory is in `.gitignore` — never commit `.pfx` files!

### GitHub Actions Release

For CI/CD releases, add these secrets to your GitHub repository:
- `CERT_BASE64` — Base64-encoded `.pfx` file (`[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`)
- `CERT_PASSWORD` — Password for the `.pfx` file

Tag a release to trigger: `git tag v1.0.0 && git push origin v1.0.0`

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
