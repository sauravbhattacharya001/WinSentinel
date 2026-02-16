# Install-Agent.ps1 — WinSentinel Agent Windows Service Installer
# Run as Administrator!
#
# Usage:
#   .\Install-Agent.ps1 -Install       # Install and start the service
#   .\Install-Agent.ps1 -Uninstall     # Stop and remove the service
#   .\Install-Agent.ps1 -Status        # Check service status

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status
)

$ServiceName = "WinSentinel.Agent"
$DisplayName = "WinSentinel Security Agent"
$Description = "WinSentinel always-on security monitoring agent. Performs scheduled audits, real-time threat detection, and autonomous security responses."

# Find the agent executable
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentExe = Join-Path $ScriptDir "src\WinSentinel.Agent\bin\Release\net8.0-windows\WinSentinel.Agent.exe"

# Fallback paths
if (-not (Test-Path $AgentExe)) {
    $AgentExe = Join-Path $ScriptDir "src\WinSentinel.Agent\bin\Debug\net8.0-windows\WinSentinel.Agent.exe"
}
if (-not (Test-Path $AgentExe)) {
    # Try x64 platform build
    $AgentExe = Join-Path $ScriptDir "src\WinSentinel.Agent\bin\x64\Release\net8.0-windows\WinSentinel.Agent.exe"
}
if (-not (Test-Path $AgentExe)) {
    $AgentExe = Join-Path $ScriptDir "src\WinSentinel.Agent\bin\x64\Debug\net8.0-windows\WinSentinel.Agent.exe"
}

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Status {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "`n  WinSentinel Agent Service" -ForegroundColor Cyan
        Write-Host "  =========================" -ForegroundColor Cyan
        Write-Host "  Name:    $($service.ServiceName)"
        Write-Host "  Display: $($service.DisplayName)"
        Write-Host "  Status:  $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Yellow' })
        Write-Host "  Startup: $($service.StartType)"
        Write-Host ""
    } else {
        Write-Host "`n  WinSentinel Agent is NOT installed as a service." -ForegroundColor Yellow
        Write-Host ""
    }
}

function Install-Agent {
    if (-not (Test-Administrator)) {
        Write-Host "`n  ERROR: Run this script as Administrator!" -ForegroundColor Red
        Write-Host "  Right-click PowerShell > Run as Administrator`n"
        exit 1
    }

    if (-not (Test-Path $AgentExe)) {
        Write-Host "`n  ERROR: Agent executable not found!" -ForegroundColor Red
        Write-Host "  Build first: dotnet build src/WinSentinel.Agent -c Release"
        Write-Host "  Expected: $AgentExe`n"
        exit 1
    }

    # Check if already installed
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "`n  Service already exists. Stopping..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    Write-Host "`n  Installing WinSentinel Agent service..." -ForegroundColor Cyan
    Write-Host "  Executable: $AgentExe"

    # Create the service
    sc.exe create $ServiceName `
        binpath= "`"$AgentExe`"" `
        start= auto `
        DisplayName= "`"$DisplayName`"" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to create service! Exit code: $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }

    # Set description
    sc.exe description $ServiceName "`"$Description`"" | Out-Null

    # Configure recovery (restart on failure)
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    # Start the service
    Write-Host "  Starting service..." -ForegroundColor Cyan
    Start-Service -Name $ServiceName

    Start-Sleep -Seconds 2
    Show-Status

    Write-Host "  WinSentinel Agent installed and running!" -ForegroundColor Green
    Write-Host ""
}

function Uninstall-Agent {
    if (-not (Test-Administrator)) {
        Write-Host "`n  ERROR: Run this script as Administrator!" -ForegroundColor Red
        exit 1
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "`n  Service is not installed." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  Stopping WinSentinel Agent service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host "  Removing service..." -ForegroundColor Yellow
    sc.exe delete $ServiceName | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  WinSentinel Agent service removed." -ForegroundColor Green
    } else {
        Write-Host "  Failed to remove service. Try rebooting and running again." -ForegroundColor Red
    }
    Write-Host ""
}

# Main
if ($Install) {
    Install-Agent
} elseif ($Uninstall) {
    Uninstall-Agent
} elseif ($Status) {
    Show-Status
} else {
    Write-Host "`n  WinSentinel Agent Service Installer" -ForegroundColor Cyan
    Write-Host "  ====================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Usage:"
    Write-Host "    .\Install-Agent.ps1 -Install     Install and start the service"
    Write-Host "    .\Install-Agent.ps1 -Uninstall   Stop and remove the service"
    Write-Host "    .\Install-Agent.ps1 -Status      Check service status"
    Write-Host ""
    Show-Status
}
