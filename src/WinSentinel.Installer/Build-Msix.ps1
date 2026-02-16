<#
.SYNOPSIS
    Builds and signs WinSentinel MSIX package.
.DESCRIPTION
    Publishes WinSentinel.App as a self-contained x64 application,
    packages it into an MSIX using makeappx.exe, and signs it with
    SignTool using a code signing certificate.
.PARAMETER Configuration
    Build configuration (Debug or Release). Default: Release.
.PARAMETER SelfContained
    Whether to produce a self-contained deployment. Default: true.
.PARAMETER SkipBuild
    Skip the dotnet publish step (use existing publish output).
.PARAMETER CertPath
    Path to the .pfx code signing certificate. Default: certs/WinSentinel-Dev.pfx
    Can also be set via WINSENTINEL_CERT_PATH env var.
.PARAMETER CertPassword
    Password for the .pfx certificate. Default: WinSentinel2026!
    Can also be set via WINSENTINEL_CERT_PASSWORD env var.
.PARAMETER SkipSign
    Skip the signing step (produces unsigned MSIX).
#>
param(
    [string]$Configuration = "Release",
    [switch]$SelfContained = $true,
    [switch]$SkipBuild,
    [string]$CertPath = "",
    [string]$CertPassword = "",
    [switch]$SkipSign
)

$ErrorActionPreference = "Stop"

# Paths
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$AppProject = Join-Path $RepoRoot "src\WinSentinel.App\WinSentinel.App.csproj"
$InstallerDir = Join-Path $RepoRoot "src\WinSentinel.Installer"
$PublishDir = Join-Path $RepoRoot "publish\msix-content"
$OutputDir = Join-Path $RepoRoot "publish"
$DistDir = Join-Path $RepoRoot "dist"
$MsixPath = Join-Path $DistDir "WinSentinel.msix"

# Resolve certificate path & password (param > env > default)
if (-not $CertPath) {
    $CertPath = if ($env:WINSENTINEL_CERT_PATH) { $env:WINSENTINEL_CERT_PATH }
                else { Join-Path $InstallerDir "certs\WinSentinel-Dev.pfx" }
}
if (-not $CertPassword) {
    $CertPassword = if ($env:WINSENTINEL_CERT_PASSWORD) { $env:WINSENTINEL_CERT_PASSWORD }
                    else { "WinSentinel2026!" }
}

# Find makeappx.exe (checks Windows SDK install + NuGet cache)
function Find-SdkTool {
    param([string]$ToolName)
    
    # Check Windows SDK installation
    $sdkBases = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    )
    
    foreach ($base in $sdkBases) {
        if (Test-Path $base) {
            $found = Get-ChildItem $base -Recurse -Filter $ToolName -ErrorAction SilentlyContinue |
                     Where-Object { $_.Directory.Name -eq "x64" } |
                     Sort-Object { $_.Directory.Parent.Name } -Descending |
                     Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    
    # Check NuGet cache (Microsoft.Windows.SDK.BuildTools package)
    $nugetCache = "$env:USERPROFILE\.nuget\packages\microsoft.windows.sdk.buildtools"
    if (Test-Path $nugetCache) {
        $found = Get-ChildItem $nugetCache -Recurse -Filter $ToolName -ErrorAction SilentlyContinue |
                 Where-Object { $_.Directory.Name -eq "x64" } |
                 Sort-Object { $_.Directory.Parent.Name } -Descending |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    
    return $null
}

function Restore-SdkBuildTools {
    Write-Host "  SDK tools not found. Restoring via NuGet..." -ForegroundColor DarkYellow
    $tempDir = Join-Path $OutputDir "temp-sdk"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    $tempProj = Join-Path $tempDir "temp.csproj"
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Library</OutputType></PropertyGroup>
  <ItemGroup><PackageReference Include="Microsoft.Windows.SDK.BuildTools" Version="10.0.22621.756" /></ItemGroup>
</Project>
"@ | Set-Content $tempProj -Encoding UTF8
    
    & dotnet restore $tempProj --verbosity quiet 2>$null
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  WinSentinel MSIX Builder" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Ensure dist directory exists
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

# Step 1: Publish the app
if (-not $SkipBuild) {
    Write-Host "[1/5] Publishing WinSentinel.App ($Configuration, x64)..." -ForegroundColor Yellow
    
    # Clean publish directory
    if (Test-Path $PublishDir) { Remove-Item $PublishDir -Recurse -Force }
    
    $publishArgs = @(
        "publish", $AppProject,
        "-c", $Configuration,
        "-r", "win-x64",
        "-p:Platform=x64",
        "--self-contained", $SelfContained.ToString().ToLower(),
        "-o", $PublishDir,
        "-p:PublishSingleFile=false",
        "-p:IncludeNativeLibrariesForSelfExtract=false"
    )
    
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet publish failed with exit code $LASTEXITCODE"
        exit 1
    }
    Write-Host "  Published to: $PublishDir" -ForegroundColor Green
} else {
    Write-Host "[1/5] Skipping build (using existing publish output)..." -ForegroundColor DarkYellow
    if (-not (Test-Path $PublishDir)) {
        Write-Error "Publish directory not found: $PublishDir. Run without -SkipBuild first."
        exit 1
    }
}

# Step 2: Copy MSIX assets
Write-Host "[2/5] Copying MSIX manifest and assets..." -ForegroundColor Yellow

# Copy AppxManifest.xml
Copy-Item (Join-Path $InstallerDir "AppxManifest.xml") (Join-Path $PublishDir "AppxManifest.xml") -Force

# Copy Assets
$assetsSource = Join-Path $InstallerDir "Assets"
$assetsDest = Join-Path $PublishDir "Assets"
if (-not (Test-Path $assetsDest)) { New-Item -ItemType Directory -Path $assetsDest -Force | Out-Null }
Copy-Item "$assetsSource\*" $assetsDest -Force -Recurse

# Create a mapping file for makeappx
$mappingFile = Join-Path $OutputDir "mapping.txt"
$mappingContent = @("[Files]")

Get-ChildItem $PublishDir -Recurse -File | ForEach-Object {
    $relativePath = $_.FullName.Substring($PublishDir.Length + 1)
    $mappingContent += "`"$($_.FullName)`" `"$relativePath`""
}

$mappingContent -join "`n" | Set-Content $mappingFile -Encoding UTF8
Write-Host "  Created mapping file with $($mappingContent.Count - 1) files" -ForegroundColor Green

# Step 3: Package with makeappx
Write-Host "[3/5] Creating MSIX package..." -ForegroundColor Yellow

$makeAppx = Find-SdkTool "makeappx.exe"
if (-not $makeAppx) {
    Restore-SdkBuildTools
    $makeAppx = Find-SdkTool "makeappx.exe"
}

if (-not $makeAppx) {
    Write-Warning "makeappx.exe not found! Install Windows 10/11 SDK."
    Write-Warning "  winget install Microsoft.WindowsSDK.10.0.22621"
    Write-Warning ""
    Write-Warning "Creating portable ZIP as fallback..."
    
    $zipPath = Join-Path $DistDir "WinSentinel-portable-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$PublishDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Host "  Created: $zipPath" -ForegroundColor Green
    exit 0
}

Write-Host "  Using: $makeAppx" -ForegroundColor DarkGray

# Remove existing MSIX
if (Test-Path $MsixPath) { Remove-Item $MsixPath -Force }

& $makeAppx pack /f $mappingFile /p $MsixPath /o
if ($LASTEXITCODE -ne 0) {
    Write-Error "makeappx pack failed with exit code $LASTEXITCODE"
    exit 1
}

Write-Host "  Created: $MsixPath" -ForegroundColor Green

# Step 4: Sign the MSIX
if (-not $SkipSign) {
    Write-Host "[4/5] Signing MSIX package..." -ForegroundColor Yellow
    
    if (-not (Test-Path $CertPath)) {
        Write-Warning "Certificate not found at: $CertPath"
        Write-Warning "Run with -SkipSign to create an unsigned package, or provide -CertPath."
        Write-Warning ""
        Write-Warning "To generate a dev certificate:"
        Write-Warning '  $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=WinSentinel" \'
        Write-Warning '    -KeyUsage DigitalSignature -FriendlyName "WinSentinel Dev" \'
        Write-Warning '    -CertStoreLocation "Cert:\CurrentUser\My" \'
        Write-Warning '    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")'
        exit 1
    }
    
    $signTool = Find-SdkTool "signtool.exe"
    if (-not $signTool) {
        Write-Error "signtool.exe not found! Install Windows 10/11 SDK."
        exit 1
    }
    
    Write-Host "  Using: $signTool" -ForegroundColor DarkGray
    
    & $signTool sign /fd SHA256 /a /f $CertPath /p $CertPassword $MsixPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "signtool sign failed with exit code $LASTEXITCODE"
        exit 1
    }
    
    Write-Host "  MSIX signed successfully!" -ForegroundColor Green
} else {
    Write-Host "[4/5] Skipping signing (unsigned MSIX)..." -ForegroundColor DarkYellow
}

# Step 5: Summary
Write-Host ""
Write-Host "[5/5] Build complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan

$msixSize = (Get-Item $MsixPath).Length / 1MB
Write-Host "  MSIX Package: $MsixPath" -ForegroundColor White
Write-Host "  Size: $([math]::Round($msixSize, 1)) MB" -ForegroundColor White
Write-Host "  Signed: $(-not $SkipSign)" -ForegroundColor White
Write-Host ""
Write-Host "  To install:" -ForegroundColor Cyan
Write-Host "    .\Install-WinSentinel.ps1" -ForegroundColor Gray
Write-Host "    Or: Add-AppxPackage -Path `"$MsixPath`"" -ForegroundColor Gray
Write-Host ""
