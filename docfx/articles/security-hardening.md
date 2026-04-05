# Security Hardening Guide

Best practices for deploying WinSentinel securely in production environments.

## Principle of Least Privilege

### Service Account Configuration

WinSentinel requires local admin for full audit coverage, but you can limit exposure:

```powershell
# Create a dedicated service account
New-LocalUser -Name "WinSentinelSvc" -Description "WinSentinel Service Account" -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "WinSentinelSvc"

# Configure the service to use this account
sc.exe config WinSentinel obj= ".\WinSentinelSvc" password= "<password>"
```

> **Tip:** In domain environments, use a Group Managed Service Account (gMSA) instead of a local account.

### Restricting Module Permissions

Not all modules need admin. For non-privileged scanning:

```powershell
# Run only modules that work without elevation
winsentinel audit --modules browser,startup,privacy --no-elevate
```

## Named Pipe Security

By default, the IPC pipe (`\\.\pipe\WinSentinel`) allows connections from any local user. In multi-user or shared environments, restrict access:

```json
// appsettings.json
{
  "Agent": {
    "IpcSecurity": {
      "AllowedUsers": ["DOMAIN\\AdminUser", ".\\WinSentinelSvc"],
      "AllowedGroups": ["BUILTIN\\Administrators"]
    }
  }
}
```

## Log Protection

### Secure Log Directory

Ensure the log directory is only writable by the service account:

```powershell
$logPath = "$env:ProgramData\WinSentinel\logs"
$acl = Get-Acl $logPath
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "WinSentinelSvc", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($adminRule)
Set-Acl $logPath $acl
```

### Log Rotation

Configure log rotation to prevent disk exhaustion:

```json
{
  "Logging": {
    "File": {
      "MaxSizeMB": 50,
      "MaxFiles": 10,
      "CompressRotated": true
    }
  }
}
```

## Network Considerations

### Firewall Rules for the Agent

If using remote management or centralized reporting, add specific firewall rules rather than broad exceptions:

```powershell
# Allow only the specific port if using HTTP API
New-NetFirewallRule -DisplayName "WinSentinel API" `
    -Direction Inbound -Protocol TCP -LocalPort 5100 `
    -Action Allow -Profile Domain
```

### Disable Unnecessary Endpoints

In standalone mode, disable the HTTP API entirely:

```json
{
  "Agent": {
    "HttpApi": {
      "Enabled": false
    }
  }
}
```

## Auto-Remediation Safety

### Production-Safe Remediation Settings

In production, use conservative remediation settings:

```json
{
  "Remediation": {
    "AutoRemediate": true,
    "RequireApproval": true,
    "MaxSeverity": "Medium",
    "CreateRestorePoint": true,
    "DryRunFirst": true,
    "NotifyOnAction": true
  }
}
```

This ensures:
- Critical and High severity remediations require manual approval
- A restore point is created before each remediation
- A dry run is performed first to preview changes
- Administrators are notified of all remediation actions

### Blocklisted Remediations

Prevent specific remediations that could impact business applications:

```json
{
  "Remediation": {
    "Blocklist": [
      "DisableService:*",
      "ModifyFirewall:AllowInbound",
      "RegistryChange:HKLM\\SOFTWARE\\Policies\\*"
    ]
  }
}
```

## Compliance Audit Trail

For environments requiring audit trails (SOC2, HIPAA, PCI-DSS):

```powershell
# Enable comprehensive audit logging
winsentinel config set AuditTrail.Enabled true
winsentinel config set AuditTrail.IncludeFindings true
winsentinel config set AuditTrail.IncludeRemediations true
winsentinel config set AuditTrail.RetentionDays 365
winsentinel config set AuditTrail.SignReports true
```

Reports are stored in `$env:ProgramData\WinSentinel\audit-trail\` with SHA-256 checksums for tamper detection.

## Update Strategy

Keep WinSentinel up to date with security patches:

```powershell
# Check for updates
winsentinel update check

# Apply updates (requires restart of the agent service)
winsentinel update apply --restart-service
```

In managed environments, use your existing patch management solution (SCCM, Intune, etc.) to distribute WinSentinel updates.
