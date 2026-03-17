# Troubleshooting

Common issues and their solutions when running WinSentinel.

## Installation Issues

### .NET 8.0 not found

```
A fatal error occurred. The required library hostfxr.dll could not be found.
```

**Solution:** Install the [.NET 8.0 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) (x64). If building from source, install the .NET 8.0 SDK instead.

### Installer fails with "Access Denied"

The installer requires **elevated privileges**. Right-click PowerShell → "Run as Administrator", then retry:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-WinSentinel.ps1
```

### Build fails on `net8.0-windows` target

WinSentinel targets `net8.0-windows` which requires the Windows Desktop workload:

```powershell
dotnet workload install microsoft-net-sdk-windowsdesktop
```

## Agent Service Issues

### Service won't start

Check the Windows Event Viewer under **Application** for WinSentinel errors. Common causes:

1. **Port conflict on named pipe** — another instance may be running. Check with:
   ```powershell
   Get-Process -Name WinSentinel* | Stop-Process -Force
   sc.exe start WinSentinel
   ```

2. **Missing configuration** — ensure `appsettings.json` exists in the installation directory.

3. **Insufficient permissions** — the service account needs local admin rights for full audit capabilities.

### Dashboard can't connect to Agent

The dashboard communicates via named pipe (`\\.\pipe\WinSentinel`). Verify:

```powershell
# Check if the agent is running
Get-Service WinSentinel

# Check if the pipe exists
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like '*WinSentinel*' }
```

If the pipe doesn't exist, the agent isn't running or crashed during startup.

## Audit Issues

### Modules report "Access Denied" findings

Some audit modules require elevated privileges to inspect system settings:

- **Firewall audit** — needs admin to query `netsh advfirewall`
- **Defender audit** — needs admin for `Get-MpPreference`
- **User audit** — needs admin for `net user` and group membership

**Solution:** Run the CLI as Administrator or ensure the agent service runs under a privileged account.

### Audit takes too long

Large systems with many network connections, scheduled tasks, or user accounts may take longer. You can:

```powershell
# Run specific modules only
winsentinel audit --modules defender,firewall

# Skip slow modules
winsentinel audit --skip network,startup
```

### Score seems incorrect

WinSentinel scores are weighted by severity. A single Critical finding can drop the score significantly. Review the detailed findings:

```powershell
winsentinel audit --format json --output report.json
```

Then inspect the JSON for high-severity items.

## Auto-Remediation Issues

### Remediation didn't apply

Auto-remediation runs in a sandboxed context with safety checks. It will skip:

- Changes that could break network connectivity
- Disabling services that other software depends on
- Registry changes outside the security scope

Check the agent logs for remediation decisions:

```powershell
Get-Content "$env:ProgramData\WinSentinel\logs\agent.log" -Tail 50
```

### Remediation caused a problem

WinSentinel creates restore points before major remediations. To roll back:

1. Open **System Restore** (`rstrui.exe`)
2. Select the restore point labeled "WinSentinel Auto-Remediation"
3. Follow the wizard

You can also disable auto-remediation:

```powershell
winsentinel config set AutoRemediate false
```

## Logging & Diagnostics

### Enable verbose logging

```powershell
winsentinel audit --verbose
# Or for the agent service, set in appsettings.json:
# "Logging": { "LogLevel": { "Default": "Debug" } }
```

### Collect diagnostic bundle

```powershell
winsentinel diag --output diag-bundle.zip
```

This collects logs, configuration, and system info (sanitized) for bug reports.

## Getting Help

- [Open an issue](https://github.com/sauravbhattacharya001/WinSentinel/issues/new/choose) with logs and system info
- Check [Architecture docs](architecture.md) for understanding internals
- Review [IPC Protocol](ipc-protocol.md) for dashboard/agent communication issues
