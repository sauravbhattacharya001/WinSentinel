# Input Validation & Command Injection Prevention

WinSentinel executes shell commands (PowerShell, `netsh`, `sc`, `net user`) as part of
its auto-remediation and audit workflows.  Because these commands often incorporate
values extracted from external sources — event logs, network connections, WiFi profiles —
they are potential command injection vectors if not properly sanitized.

This document describes the defense-in-depth strategy used to prevent command injection.

## Attack Surface

| Source | Data | Used In | Risk |
|:---|:---|:---|:---|
| Windows Event Log | IP addresses, usernames, service names | `netsh` firewall rules, `net user`, `sc delete` | Attacker-controlled event fields could contain shell metacharacters |
| Network connections | Remote IP addresses | `netsh` firewall block rules | Spoofed or malformed IP strings |
| WiFi profiles | SSID / profile names | `netsh wlan show profile` | Malicious SSIDs can contain arbitrary characters |
| User input (chat) | Process names, file paths | `Stop-Process`, quarantine commands | Direct user input — must be validated |
| Response policy | Fix command templates | PowerShell execution | JSON file editable by local user |

## Defense Layers

### Layer 1: InputSanitizer (Allowlist Validation)

`WinSentinel.Core.Helpers.InputSanitizer` provides type-specific validators that
use **allowlist patterns** (not blocklist).  Each validator returns `null` on invalid
input rather than attempting to "clean" it.

| Method | Allowed Characters | Used For |
|:---|:---|:---|
| `SanitizeIpAddress` | Digits, dots, colons, hex; validated by `IPAddress.TryParse` | Firewall block rules |
| `SanitizeUsername` | Letters, digits, spaces, hyphens, underscores, dots, backslash | `net user` commands |
| `SanitizeDriveLetter` | Single letter + optional colon | `manage-bde` commands |
| `SanitizeFirewallRuleName` | Letters, digits, spaces, hyphens, underscores, dots | `netsh` rule names |
| `SanitizeProcessInput` | Letters, digits, dots, hyphens, underscores (or numeric PID > 4) | `Stop-Process` |
| `ValidateFilePath` | Rejects `..`, UNC, ADS, null bytes, protected paths | Quarantine operations |

**Key design principle:** Validators return `null` on failure, and callers set
`AutoFixable = false` and `FixCommand = null` when validation fails.  This means
a malformed input _disables_ the auto-fix entirely rather than attempting a
"best effort" sanitization.

### Layer 2: Base64-Encoded Commands (ShellHelper)

`ShellHelper.RunPowerShellAsync` and `FixEngine.ExecuteInlineAsync` use PowerShell's
`-EncodedCommand` parameter, which accepts a Base64-encoded UTF-16LE string.  This
**eliminates** the argument-parsing attack surface because the command is never
interpreted as a shell argument string:

```csharp
// Safe: command is Base64-encoded, not interpolated into arguments
Arguments = $"-EncodedCommand {EncodeCommand(command)}"
```

However, `-EncodedCommand` only prevents injection at the process-argument boundary.
If the command string _itself_ contains injected content (e.g., a service name with
embedded PowerShell), the injection still executes inside the PowerShell session.
This is why Layer 1 (input validation before command construction) is critical.

### Layer 3: Dangerous Command Blocklist (CheckDangerousCommand)

`InputSanitizer.CheckDangerousCommand` is a **last-resort safety net** that rejects
commands containing known-dangerous patterns before execution.  It checks for:

- Destructive commands (`format /y`, recursive delete)
- Network exfiltration (`Invoke-WebRequest`, `curl`, `.NET WebClient`)
- Code execution (`Invoke-Expression`, `Add-Type`, `Start-Process -Verb RunAs`)
- Credential access (`mimikatz`, `Get-Credential`, `cmdkey`)
- LOLBins (`certutil -urlcache`, `mshta`, `regsvr32`, `bitsadmin`)
- AMSI bypass attempts
- PowerShell subexpressions (`$(...)`) and backtick escapes
- .NET reflection invocation
- Persistence mechanisms (registry Run keys, `schtasks /create`, `sc create`)

This layer catches injections that might bypass Layer 1 — for example, if a future
code change accidentally interpolates unsanitized data into a fix command.

### Layer 4: Log Injection Prevention

`InputSanitizer.SanitizeForLog` strips CRLF sequences and control characters from
strings before they are written to log files or the agent journal.  This prevents
log forging attacks where injected newlines create fake log entries.

## Validated Command Patterns

### Firewall Block Rules (IP-based)

```
netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}
```

- `{ip}` is validated by `SanitizeIpAddress` → parsed by `IPAddress.TryParse` →
  canonical form (e.g., `::1` not `0:0:0:0:0:0:0:1`)
- If validation fails: `AutoFixable = false`, `FixCommand = null`

### User Account Operations

```
net user "{username}" /delete
net user "{username}" /active:yes
```

- `{username}` is validated by `SanitizeUsername` → allowlist regex
- If validation fails: `AutoFixable = false`, `FixCommand = null`

### Service Deletion

```
sc delete "{serviceName}"
```

- `{serviceName}` is validated by `IsServiceNameSafe` → alphanumeric + safe chars only
- If validation fails: `AutoFixable = false`, `FixCommand = null`

## Testing

- `InputSanitizerTests.cs` covers all validators with valid, invalid, and edge-case inputs
- `FixEngineTests.cs` verifies that dangerous commands are blocked before execution
- `EventLogMonitorModule` tests verify that sanitization failures disable auto-fix

## Adding New Fix Commands

When adding a new auto-fixable finding:

1. **Identify all external data** in the fix command template
2. **Add or use an InputSanitizer method** with an allowlist regex
3. **Set `AutoFixable` conditionally** — only `true` when validation succeeds
4. **Set `FixCommand = null`** when validation fails (never construct a partial command)
5. **Add tests** for both valid and malicious inputs
6. **Consider `CheckDangerousCommand`** — will your command pattern trigger any blocklist rules?
