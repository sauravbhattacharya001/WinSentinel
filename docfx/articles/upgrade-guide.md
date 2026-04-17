# Upgrade Guide

This guide covers upgrading WinSentinel between versions with minimal disruption.

## General Upgrade Process

### CLI / Desktop App

1. **Back up your configuration** before upgrading:
   ```powershell
   Copy-Item -Path "$env:APPDATA\WinSentinel\config.json" -Destination "$env:APPDATA\WinSentinel\config.json.bak"
   ```

2. **Stop the agent** if running:
   ```powershell
   winsentinel agent stop
   ```

3. **Install the new version** using your preferred method:
   - **MSI installer**: Download from [Releases](https://github.com/sauravbhattacharya001/WinSentinel/releases) and run the installer. It handles in-place upgrades.
   - **dotnet tool**: `dotnet tool update -g WinSentinel.Cli`
   - **Manual**: Replace the published binaries and restart.

4. **Restart the agent**:
   ```powershell
   winsentinel agent start
   ```

### Windows Service

1. **Stop the service**:
   ```powershell
   Stop-Service WinSentinel
   ```

2. **Replace binaries** in the installation directory.

3. **Start the service**:
   ```powershell
   Start-Service WinSentinel
   ```

The service will pick up configuration changes on restart. No database migration is needed — WinSentinel stores audit history as JSON files.

### Docker

Pull the latest image and recreate the container:

```bash
docker pull ghcr.io/sauravbhattacharya001/winsentinel:latest
docker compose up -d
```

## Configuration Compatibility

WinSentinel configuration files are forward-compatible. New settings use sensible defaults so existing configs continue to work. Deprecated settings produce warnings in the log but don't cause failures.

If a breaking configuration change is required, WinSentinel will:
1. Log a clear error message with the required change
2. Document the migration in the release notes

## Checking Your Version

```powershell
winsentinel --version
```

Compare with the [latest release](https://github.com/sauravbhattacharya001/WinSentinel/releases/latest) to see if an upgrade is available.

## Rollback

If an upgrade causes issues:

1. Stop the service/agent
2. Restore the previous binaries
3. Restore the configuration backup
4. Start the service/agent

Audit history is never deleted during upgrades, so no data loss occurs on rollback.
