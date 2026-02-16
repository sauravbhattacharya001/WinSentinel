<#
.SYNOPSIS
    Installs WinSentinel on Windows. One command to go from zero to installed.
.DESCRIPTION
    Downloads the latest WinSentinel MSIX from GitHub Releases (or uses a local file),
    imports the dev certificate to TrustedPeople store, and installs the MSIX package.
    Requires Administrator privileges for certificate import.
.PARAMETER MsixPath
    Path to a local .msix file. If not specified, downloads from GitHub Releases.
.PARAMETER CertPath
    Path to the .cer certificate file. If not specified, extracts from the MSIX signer
    or looks in src/WinSentinel.Installer/certs/WinSentinel-Dev.cer.
.PARAMETER SkipCertImport
    Skip importing the certificate (use if cert is already trusted).
.PARAMETER GitHubRepo
    GitHub repository in owner/repo format. Default: sauravbhattacharya001/WinSentinel
.PARAMETER Force
    Force reinstall even if already installed.
#>
#Requires -RunAsAdministrator
param(
    [string]$MsixPath = "",
    [string]$CertPath = "",
    [switch]$SkipCertImport,
    [string]$GitHubRepo = "sauravbhattacharya001/WinSentinel",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  WinSentinel Installer" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Determine script location for relative paths
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Get-Location }
$RepoRoot = $ScriptDir  # Assumes script is in repo root; adjust if moved

# --- Step 1: Get the MSIX file ---
Write-Host "[1/3] Locating MSIX package..." -ForegroundColor Yellow

if ($MsixPath -and (Test-Path $MsixPath)) {
    Write-Host "  Using local MSIX: $MsixPath" -ForegroundColor Green
}
elseif ($MsixPath) {
    Write-Error "Specified MSIX file not found: $MsixPath"
    exit 1
}
else {
    # Try local dist folder first
    $localMsix = Join-Path $RepoRoot "dist\WinSentinel.msix"
    if (Test-Path $localMsix) {
        Write-Host "  Found local MSIX: $localMsix" -ForegroundColor Green
        $MsixPath = $localMsix
    }
    else {
        # Download from GitHub Releases
        Write-Host "  Downloading latest release from GitHub..." -ForegroundColor DarkYellow
        
        try {
            $releaseUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"
            $headers = @{ "Accept" = "application/vnd.github.v3+json"; "User-Agent" = "WinSentinel-Installer" }
            $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers
            
            $msixAsset = $release.assets | Where-Object { $_.name -like "*.msix" } | Select-Object -First 1
            if (-not $msixAsset) {
                Write-Error "No .msix asset found in latest release. Build locally with Build-Msix.ps1 first."
                exit 1
            }
            
            $downloadDir = Join-Path $env:TEMP "WinSentinel-Install"
            New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
            $MsixPath = Join-Path $downloadDir $msixAsset.name
            
            Write-Host "  Downloading: $($msixAsset.name) ($([math]::Round($msixAsset.size / 1MB, 1)) MB)..." -ForegroundColor DarkGray
            Invoke-WebRequest -Uri $msixAsset.browser_download_url -OutFile $MsixPath -UseBasicParsing
            Write-Host "  Downloaded to: $MsixPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to download from GitHub: $_"
            Write-Host ""
            Write-Host "  Build locally instead:" -ForegroundColor Yellow
            Write-Host "    cd src\WinSentinel.Installer" -ForegroundColor Gray
            Write-Host "    .\Build-Msix.ps1" -ForegroundColor Gray
            Write-Host "    cd ..\.." -ForegroundColor Gray
            Write-Host "    .\Install-WinSentinel.ps1" -ForegroundColor Gray
            exit 1
        }
    }
}

# --- Step 2: Import certificate ---
if (-not $SkipCertImport) {
    Write-Host "[2/3] Importing code signing certificate..." -ForegroundColor Yellow
    
    # Find the certificate
    if (-not $CertPath -or -not (Test-Path $CertPath)) {
        # Look in standard locations
        $certLocations = @(
            (Join-Path $RepoRoot "src\WinSentinel.Installer\certs\WinSentinel-Dev.cer"),
            (Join-Path $ScriptDir "certs\WinSentinel-Dev.cer"),
            (Join-Path $ScriptDir "WinSentinel-Dev.cer")
        )
        
        foreach ($loc in $certLocations) {
            if (Test-Path $loc) {
                $CertPath = $loc
                break
            }
        }
    }
    
    if ($CertPath -and (Test-Path $CertPath)) {
        Write-Host "  Importing certificate: $CertPath" -ForegroundColor DarkGray
        
        # Import to TrustedPeople store (allows sideloading without dev mode)
        try {
            Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\TrustedPeople" | Out-Null
            Write-Host "  Certificate imported to TrustedPeople store" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not import to TrustedPeople: $_"
            Write-Host "  Trying CurrentUser store instead..." -ForegroundColor DarkYellow
            Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\CurrentUser\TrustedPeople" | Out-Null
            Write-Host "  Certificate imported to CurrentUser\TrustedPeople" -ForegroundColor Green
        }
        
        # Also import to Root if needed for full trust chain
        try {
            Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  Certificate also imported to Trusted Root CA" -ForegroundColor Green
        }
        catch {
            # Not critical - TrustedPeople should suffice for sideloading
        }
    }
    else {
        Write-Warning "Certificate file not found. The MSIX may fail to install if not trusted."
        Write-Warning "Generate one with: New-SelfSignedCertificate (see README.md)"
        Write-Host ""
        
        # Try to enable developer mode as fallback
        Write-Host "  Attempting to enable Developer Mode as fallback..." -ForegroundColor DarkYellow
        try {
            $devModeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
            if (-not (Test-Path $devModeKey)) {
                New-Item -Path $devModeKey -Force | Out-Null
            }
            Set-ItemProperty -Path $devModeKey -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord
            Set-ItemProperty -Path $devModeKey -Name "AllowAllTrustedApps" -Value 1 -Type DWord
            Write-Host "  Developer Mode enabled" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not enable Developer Mode: $_"
        }
    }
} else {
    Write-Host "[2/3] Skipping certificate import" -ForegroundColor DarkYellow
}

# --- Step 3: Install the MSIX ---
Write-Host "[3/3] Installing WinSentinel..." -ForegroundColor Yellow

# Remove existing installation if Force
if ($Force) {
    $existing = Get-AppxPackage -Name "WinSentinel.SecurityAgent" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Removing existing installation..." -ForegroundColor DarkYellow
        Remove-AppxPackage -Package $existing.PackageFullName
        Write-Host "  Removed: $($existing.PackageFullName)" -ForegroundColor DarkGray
    }
}

try {
    Add-AppxPackage -Path $MsixPath -ForceApplicationShutdown
    Write-Host "  WinSentinel installed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Installation failed: $_"
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    1. Make sure the certificate is trusted (re-run without -SkipCertImport)" -ForegroundColor Gray
    Write-Host "    2. Enable Developer Mode: Settings > Privacy & Security > For Developers" -ForegroundColor Gray
    Write-Host "    3. Try: Add-AppxPackage -Path '$MsixPath' -AllowUnsigned" -ForegroundColor Gray
    exit 1
}

# --- Verify installation ---
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
$installed = Get-AppxPackage -Name "WinSentinel.SecurityAgent" -ErrorAction SilentlyContinue
if ($installed) {
    Write-Host "  ✅ WinSentinel is installed!" -ForegroundColor Green
    Write-Host "  Package: $($installed.PackageFullName)" -ForegroundColor DarkGray
    Write-Host "  Version: $($installed.Version)" -ForegroundColor DarkGray
    Write-Host "  Location: $($installed.InstallLocation)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Launch from Start Menu or run:" -ForegroundColor Cyan
    Write-Host "    explorer.exe shell:appsFolder\$($installed.PackageFamilyName)!WinSentinel" -ForegroundColor Gray
} else {
    Write-Warning "Installation verification failed. Package not found."
}
Write-Host "=====================================" -ForegroundColor Cyan
