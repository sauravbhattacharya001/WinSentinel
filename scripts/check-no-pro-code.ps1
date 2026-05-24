#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Hard-isolation guard: fails CI if Pro-feature concrete class/method names
  leak into the free MIT core.

.DESCRIPTION
  Pro features (PDF reports, real-time monitoring, scheduled scans, fleet
  upload, advanced compliance mapping) ship from a separate private repo
  as signed plugin DLLs. This repo only contains the interfaces in
  src/WinSentinel.Core/Plugins/ and src/WinSentinel.Core/Licensing/.

  This script greps the tree for forbidden identifiers and exits non-zero
  if any are found outside the allowlisted folders.

  Run from repo root:
    pwsh -File scripts/check-no-pro-code.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Forbidden as concrete class/method names anywhere in the repo. The
# matching interfaces (IReportExporter, IMonitorDaemon, IScheduledScan,
# IFleetSink, IComplianceMapper) are fine and live under Plugins/.
$Forbidden = @(
    'PdfExporter',
    'PdfReport',
    'MonitorDaemon',
    'RealtimeMonitor',
    'ScheduledScanner',
    'FleetClient',
    'FleetUpload'
)

# ComplianceMapper is special: the free core already has a built-in
# Services/ComplianceMapper.cs that predates this isolation rule and
# implements only a tiny mapping. New PRs must not extend it; richer
# compliance work goes into Pro plugins via IComplianceMapper. Treat
# uses of "ComplianceMapper" as forbidden everywhere EXCEPT the existing
# files listed below.
$ComplianceMapperAllowlist = @(
    'src/WinSentinel.Core/Services/ComplianceMapper.cs',
    'src/WinSentinel.Core/Services/ComplianceTrendTracker.cs',
    'src/WinSentinel.Core/Services/ComplianceProfileService.cs',
    'tests/WinSentinel.Tests/ComplianceMapperTests.cs'
)

# Folders where forbidden tokens are allowed (interface definitions and
# this script itself).
$AllowedPathPrefixes = @(
    'src/WinSentinel.Core/Plugins/',
    'scripts/check-no-pro-code.ps1',
    'docs/plugin-key-setup.md',
    'CONTRIBUTING.md'
)

function Test-PathAllowed {
    param([string]$RelPath)
    foreach ($prefix in $AllowedPathPrefixes) {
        if ($RelPath -like "$prefix*") { return $true }
        if ($RelPath -eq $prefix)      { return $true }
    }
    return $false
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repoRoot
try {
    $violations = @()

    $files = Get-ChildItem -Recurse -File `
        -Include *.cs,*.csproj `
        -Exclude *.g.cs `
        | Where-Object {
            $_.FullName -notmatch '[\\/](bin|obj|nupkg|nupkg-ci|artifacts|TestResults|CoverageReport)[\\/]'
        }

    foreach ($f in $files) {
        $rel = ($f.FullName.Substring($repoRoot.Length + 1)) -replace '\\','/'
        if (Test-PathAllowed -RelPath $rel) { continue }

        $tokens = @($Forbidden)
        if ($rel -notin $ComplianceMapperAllowlist) {
            $tokens += 'ComplianceMapper'
        }

        $lineNum = 0
        foreach ($line in Get-Content -LiteralPath $f.FullName) {
            $lineNum++
            foreach ($t in $tokens) {
                if ($line -cmatch "\b$t\b") {
                    # Allow interface references like IReportExporter, IMonitorDaemon, etc.
                    # The token list intentionally excludes the "I" prefix forms.
                    $violations += [pscustomobject]@{
                        File   = $rel
                        Line   = $lineNum
                        Token  = $t
                        Text   = $line.Trim()
                    }
                }
            }
        }
    }

    if ($violations.Count -gt 0) {
        Write-Host ""
        Write-Host "Pro-feature isolation violation: forbidden tokens found in free core." -ForegroundColor Red
        Write-Host ""
        foreach ($v in $violations) {
            Write-Host ("  {0}:{1}  [{2}]" -f $v.File, $v.Line, $v.Token) -ForegroundColor Yellow
            Write-Host ("    {0}" -f $v.Text) -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "Pro features must ship as signed plugins from the private repo." -ForegroundColor Red
        Write-Host "See CONTRIBUTING.md > 'Pro features are out-of-tree'." -ForegroundColor Red
        exit 1
    }

    Write-Host "check-no-pro-code: OK ($($files.Count) files scanned, 0 violations)." -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
