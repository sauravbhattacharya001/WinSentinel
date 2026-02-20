# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in WinSentinel, please report it responsibly:

1. **Email:** Send details to the repository owner via [GitHub profile contact](https://github.com/sauravbhattacharya001)
2. **GitHub Security Advisory:** Use the [private vulnerability reporting](https://github.com/sauravbhattacharya001/WinSentinel/security/advisories/new) feature (preferred)

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- The WinSentinel version(s) affected
- Any proof-of-concept code (if applicable)
- Your suggested fix (if you have one)

### Response timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 1 week
- **Fix (critical):** Within 2 weeks
- **Fix (non-critical):** Within 30 days

## Security Architecture

WinSentinel is a local-first security tool. Understanding its trust boundaries helps reason about its security posture.

### Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│               WinSentinel Agent                  │
│          (runs as SYSTEM via Service)             │
│                                                   │
│  ┌──────────────┐    ┌───────────────────────┐   │
│  │ AutoRemediator│    │ Real-Time Monitors    │   │
│  │ (SYSTEM priv) │    │ (read-only by default)│   │
│  └──────┬───────┘    └───────────────────────┘   │
│         │                                         │
│  ┌──────┴───────┐                                │
│  │ Response     │                                │
│  │ Policy (JSON)│  ← User-editable               │
│  └──────────────┘                                │
│         │ Named Pipe IPC                          │
└─────────┼─────────────────────────────────────────┘
          │
┌─────────┴─────────────────────────────────────────┐
│         WinSentinel Dashboard (WPF)                │
│         (runs as current user)                     │
│         ← Standard user privileges                 │
└───────────────────────────────────────────────────┘
```

### Key Security Properties

| Property | Implementation |
|:---|:---|
| **No network communication** | All data stays local. No telemetry, no cloud APIs, no phone-home. The optional Ollama integration connects only to `localhost`. |
| **Minimal attack surface** | IPC uses named pipes (local-only, no TCP). No web server, no REST API, no open ports. |
| **Principle of least privilege** | Dashboard runs as the current user. Only the agent service (when installed) runs elevated. The CLI can request elevation per-command via UAC. |
| **Defense in depth** | Auto-remediation actions require explicit policy rules. Critical actions (kill process, disable account) default to alert-only unless the user explicitly enables auto-fix. |
| **Full undo support** | Every auto-remediation action records undo metadata. Users can reverse any automated action. |
| **Policy persistence** | Response policies are stored in `%LocalAppData%\WinSentinel\response-policy.json` with user-level ACLs. |

### Data Storage Locations

| Data | Location | Sensitivity |
|:---|:---|:---|
| Audit history (SQLite) | `%LocalAppData%\WinSentinel\audit-history.db` | Medium — contains system configuration snapshots |
| Response policy | `%LocalAppData%\WinSentinel\response-policy.json` | Low — configurable rules |
| Agent journal | `%LocalAppData%\WinSentinel\journal.json` | Medium — contains threat event details |
| Quarantined files | `%LocalAppData%\WinSentinel\Quarantine\` | High — contains potentially malicious files |
| Hosts file backups | `%LocalAppData%\WinSentinel\HostsBackup\` | Low |

### Threat Model Considerations

1. **Local privilege escalation:** The agent runs as SYSTEM. If an attacker gains write access to the agent binary or its configuration directory, they could execute arbitrary code as SYSTEM. Mitigated by: standard Windows file ACLs on the install directory, MSIX packaging with code signing.

2. **IPC message injection:** The named pipe is accessible to any local process. A malicious process could send `RunFix` commands through the pipe. Mitigated by: the agent validates commands against the response policy before executing. Auto-fix actions require explicit policy enablement.

3. **Policy file tampering:** An attacker with user-level access could modify `response-policy.json` to disable alerts or auto-fix. Mitigated by: this is a user-level configuration file by design — the user should be in control of their own policy.

4. **Quarantine escape:** Quarantined files retain their original content. Mitigated by: files are renamed with `.quarantine` extension and stored with metadata in a dedicated directory.

## Secure Development Practices

### For contributors

- **Never log sensitive data** (passwords, tokens, PII) in the agent journal or audit output
- **Validate all IPC input** — treat named pipe messages as untrusted
- **Use parameterized commands** — avoid string interpolation in shell commands passed to `Process.Start`
- **Test with least privilege** — run tests as a standard user, not Administrator
- **Pin dependency versions** — use exact versions in `.csproj` files to prevent supply chain attacks

### Code signing

Release builds are signed with a code signing certificate. The MSIX package uses a self-signed certificate for development; production releases should use a trusted CA certificate. See `src/WinSentinel.Installer/certs/README.md` for certificate management.

## Dependencies

WinSentinel's dependency tree is intentionally small:

| Dependency | Purpose | Risk |
|:---|:---|:---|
| `Microsoft.Extensions.Hosting` | Windows Service lifecycle | Low — Microsoft-maintained |
| `CommunityToolkit.Mvvm` | MVVM framework for WPF | Low — .NET Foundation |
| `Microsoft.Data.Sqlite` | Audit history storage | Low — Microsoft-maintained |
| `Hardcodet.NotifyIcon.Wpf` | System tray icon | Low — widely used |
| `xUnit` | Testing (dev only) | N/A |

No third-party security scanning engines or cloud APIs are used. All security checks use Windows native APIs (WMI, Registry, PowerShell, Event Log).
