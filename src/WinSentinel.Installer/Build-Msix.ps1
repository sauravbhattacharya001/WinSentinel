<#
.SYNOPSIS
    Builds WinSentinel MSIX package.
.DESCRIPTION
    Publishes WinSentinel.App as a self-contained x64 application,
    then packages it into an MSIX using makeappx.exe from the Windows SDK.
.PARAMETER Configuration
    Build configuration (Debug or Release). Default: Release.
.PARAMETER SelfContained
    Whether to produce a self-contained deployment. Default: true.
.PARAMETER SkipBuild
    Skip the dotnet publish step (use existing publish output).
#>
param(
    [string]$Configuration = "Release",
    [switch]$SelfContained = $true,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

# Paths
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$AppProject = Join-Path $RepoRoot "src\WinSentinel.App\WinSentinel.App.csproj"
$InstallerDir = Join-Path $RepoRoot "src\WinSentinel.Installer"
$PublishDir = Join-Path $RepoRoot "publish\msix-content"
$OutputDir = Join-Path $RepoRoot "publish"
$MsixPath = Join-Path $OutputDir "WinSentinel.msix"

# Find makeappx.exe (checks Windows SDK install + NuGet cache)
function Find-MakeAppx {
    # Check Windows SDK installation
    $sdkBases = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    )
    
    foreach ($base in $sdkBases) {
        if (Test-Path $base) {
            $found = Get-ChildItem $base -Recurse -Filter "makeappx.exe" -ErrorAction SilentlyContinue |
                     Sort-Object { $_.Directory.Name } -Descending |
                     Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    
    # Check NuGet cache (Microsoft.Windows.SDK.BuildTools package)
    $nugetCache = "$env:USERPROFILE\.nuget\packages\microsoft.windows.sdk.buildtools"
    if (Test-Path $nugetCache) {
        $found = Get-ChildItem $nugetCache -Recurse -Filter "makeappx.exe" -ErrorAction SilentlyContinue |
                 Where-Object { $_.Directory.Name -eq "x64" } |
                 Sort-Object { $_.Directory.Parent.Name } -Descending |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    
    # Try restoring the NuGet package
    Write-Host "  makeappx.exe not found. Restoring SDK build tools via NuGet..." -ForegroundColor DarkYellow
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
    
    # Try NuGet cache again
    if (Test-Path $nugetCache) {
        $found = Get-ChildItem $nugetCache -Recurse -Filter "makeappx.exe" -ErrorAction SilentlyContinue |
                 Where-Object { $_.Directory.Name -eq "x64" } |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    
    return $null
}

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  WinSentinel MSIX Builder" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Publish the app
if (-not $SkipBuild) {
    Write-Host "[1/4] Publishing WinSentinel.App ($Configuration, x64)..." -ForegroundColor Yellow
    
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
    Write-Host "[1/4] Skipping build (using existing publish output)..." -ForegroundColor DarkYellow
    if (-not (Test-Path $PublishDir)) {
        Write-Error "Publish directory not found: $PublishDir. Run without -SkipBuild first."
        exit 1
    }
}

# Step 2: Copy MSIX assets
Write-Host "[2/4] Copying MSIX manifest and assets..." -ForegroundColor Yellow

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
Write-Host "[3/4] Creating MSIX package..." -ForegroundColor Yellow

$makeAppx = Find-MakeAppx
if (-not $makeAppx) {
    Write-Warning "makeappx.exe not found! Install Windows 10/11 SDK."
    Write-Warning "  winget install Microsoft.WindowsSDK.10.0.22621"
    Write-Warning ""
    Write-Warning "Alternative: The published app files are in:"
    Write-Warning "  $PublishDir"
    Write-Warning ""
    Write-Warning "You can manually package with:"
    Write-Warning "  makeappx pack /f `"$mappingFile`" /p `"$MsixPath`" /o"
    
    # Still create a portable ZIP as fallback
    Write-Host "[3/4] Creating portable ZIP instead..." -ForegroundColor DarkYellow
    $zipPath = Join-Path $OutputDir "WinSentinel-portable-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$PublishDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Host "  Created: $zipPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Portable ZIP created. Run WinSentinel.App.exe from the extracted folder." -ForegroundColor Cyan
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

# Step 4: Summary
Write-Host ""
Write-Host "[4/4] Build complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan

$msixSize = (Get-Item $MsixPath).Length / 1MB
Write-Host "  MSIX Package: $MsixPath" -ForegroundColor White
Write-Host "  Size: $([math]::Round($msixSize, 1)) MB" -ForegroundColor White
Write-Host ""
Write-Host "  To install (sideload):" -ForegroundColor Cyan
Write-Host "    1. Enable Developer Mode in Windows Settings" -ForegroundColor Gray
Write-Host "    2. Right-click the .msix file > Install" -ForegroundColor Gray
Write-Host "    3. Or: Add-AppxPackage -Path `"$MsixPath`"" -ForegroundColor Gray
Write-Host ""
Write-Host "  To sign for distribution:" -ForegroundColor Cyan
Write-Host "    signtool sign /fd SHA256 /a /f cert.pfx /p password `"$MsixPath`"" -ForegroundColor Gray
Write-Host ""
