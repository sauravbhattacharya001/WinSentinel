#!/usr/bin/env pwsh
# WinSentinel "no Pro code in OSS core" CI guard.
#
# Rationale: WinSentinel ships an MIT-licensed core. Pro features live in a
# separate private repo (winsentinel-pro) and are delivered as signed plugins
# discovered at runtime by PluginHost. The license boundary in this repo MUST
# stay exactly two narrow surfaces:
#
#   * PluginHost — gates which plugins LOAD.
#   * ProCommandHandler — exposes `winsentinel pro {status|activate|...}`.
#
# Anything else referencing license state, or any concrete plugin
# implementation, is a layering violation: it leaks closed-source value into
# the OSS core, or it cements an inline `if (pro) { fancy thing }` branch
# that is exactly what the plugin architecture exists to prevent.
#
# This script enforces both: no banned class/method names in core sources,
# and no license-state checks outside the two whitelisted files.
#
# Exit 0 = clean, exit 1 = violation. Wired into .github/workflows/ci.yml.

$ErrorActionPreference = 'Stop'

# Resolve repo root from script location so the script works from any cwd.
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$srcRoot  = Join-Path $repoRoot 'src'

if (-not (Test-Path $srcRoot)) {
    Write-Error "src/ not found at $srcRoot"
    exit 2
}

# ----- Rule 1: forbidden concrete Pro class/method names -----------------
# These names belong to plugins (in winsentinel-pro), not to core. Their
# appearance in src/ means a Pro feature has been smuggled into the OSS repo.
$forbiddenNames = @(
    'PdfExporter',
    'PdfReport',
    'MonitorDaemon',
    'RealtimeMonitor',
    'ScheduledScanner',
    'FleetClient',
    'FleetUpload',
    'ComplianceMapperImpl'
)

# Files allowed to mention any of the names above (none today). The interface
# surface lives under src/WinSentinel.Core/Plugins/ and uses INTERFACE names
# (IMonitorDaemon, IFleetSink, …) so the names above never legitimately appear.
$pluginInterfaceDir = (Join-Path $srcRoot 'WinSentinel.Core\Plugins')

# ----- Rule 2: no inline license branching outside whitelist -------------
# License state may only be consulted by:
#   * Licensing/* (the source of truth)
#   * Plugins/PluginHost.cs (gates plugin LOADING)
#   * WinSentinel.Cli/ProCommandHandler.cs (CLI surface)
# A match anywhere else means someone wrote `if (LicenseManager.GetStatus()...)`
# in feature code — i.e. fenced off Pro behavior inline, which is exactly the
# anti-pattern the plugin architecture replaces.
$licenseRefPatterns = @(
    'LicenseManager\.IsPro\b',
    'LicenseManager\.TryRequirePro\b',
    'LicenseManager\.GetStatus\b',
    '\.TryRequirePro\('
)
$licenseWhitelist = @(
    (Join-Path $srcRoot 'WinSentinel.Core\Plugins\PluginHost.cs'),
    (Join-Path $srcRoot 'WinSentinel.Cli\ProCommandHandler.cs')
)
# Anything inside Licensing/ is intrinsically whitelisted (it owns the type).
$licensingDir = (Join-Path $srcRoot 'WinSentinel.Core\Licensing')

# ----- Rule 3: no IWinSentinelPlugin implementations under src/ ----------
# Plugins are out-of-tree. The only IWinSentinelPlugin impl in this repo
# is the synthetic test stub under tests/WinSentinel.TestPlugin/.
$pluginImplPattern = ':\s*[A-Za-z0-9_<>, ]*IWinSentinelPlugin\b'

$violations = New-Object System.Collections.Generic.List[string]
$scanned = 0

$csFiles = Get-ChildItem -Path $srcRoot -Recurse -File -Filter *.cs -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '[\\/](bin|obj)[\\/]'
    }

foreach ($file in $csFiles) {
    $scanned++
    $isPluginInterfaceFile = $file.FullName.StartsWith($pluginInterfaceDir, [System.StringComparison]::OrdinalIgnoreCase)
    $isLicensingFile = $file.FullName.StartsWith($licensingDir, [System.StringComparison]::OrdinalIgnoreCase)
    $isLicenseWhitelisted = $licenseWhitelist -contains $file.FullName

    $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    if (-not $lines) { continue }
    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++

        # Rule 1: forbidden concrete names (skip the interfaces directory only).
        if (-not $isPluginInterfaceFile) {
            foreach ($name in $forbiddenNames) {
                if ($line -cmatch "\b$name\b") {
                    $violations.Add("[forbidden-name:$name] $($file.FullName):$lineNum  $line")
                }
            }
        }

        # Rule 2: inline license refs outside whitelist.
        if (-not ($isLicensingFile -or $isLicenseWhitelisted)) {
            foreach ($pat in $licenseRefPatterns) {
                if ($line -match $pat) {
                    $violations.Add("[inline-license-ref] $($file.FullName):$lineNum  $line")
                }
            }
        }

        # Rule 3: IWinSentinelPlugin implementation under src/ (interface
        # declaration itself lives in Plugins/ and starts with `interface`).
        if ($line -match $pluginImplPattern -and $line -notmatch 'interface\s+IWinSentinelPlugin') {
            $violations.Add("[plugin-impl-in-core] $($file.FullName):$lineNum  $line")
        }
    }
}

# Rule 3b: also fail if any csproj under src/ has IsPlugin metadata or directly
# packs against the manifest (defensive — we don't ship a plugin csproj here).
foreach ($csproj in Get-ChildItem -Path $srcRoot -Recurse -File -Filter *.csproj) {
    $content = Get-Content -LiteralPath $csproj.FullName -Raw
    if ($content -match '<EmbeddedResource[^>]*plugin\.json') {
        $violations.Add("[plugin-manifest-in-core] $($csproj.FullName)  embeds plugin.json (plugins must live in their own repo)")
    }
}

if ($violations.Count -gt 0) {
    Write-Host "check-no-pro-code: $($violations.Count) violation(s) found"
    foreach ($v in $violations) { Write-Host "  $v" }
    exit 1
}

Write-Host "check-no-pro-code: OK, $scanned files scanned"
exit 0
