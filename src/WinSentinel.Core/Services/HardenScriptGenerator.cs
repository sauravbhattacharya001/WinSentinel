using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a reviewable PowerShell hardening script from audit findings.
/// The script groups fixes by module, adds explanatory comments, and includes
/// optional confirmation prompts so users can review before executing.
/// </summary>
public class HardenScriptGenerator
{
    /// <summary>
    /// Generate a PowerShell hardening script from a security report.
    /// </summary>
    public string Generate(SecurityReport report, HardenScriptOptions? options = null)
    {
        options ??= new HardenScriptOptions();

        var fixableFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity is Severity.Critical or Severity.Warning)
            .Where(f => !string.IsNullOrWhiteSpace(f.FixCommand))
            .ToList();

        if (options.IncludeInfo)
        {
            var infoFixable = report.Results
                .SelectMany(r => r.Findings)
                .Where(f => f.Severity == Severity.Info && !string.IsNullOrWhiteSpace(f.FixCommand))
                .ToList();
            fixableFindings.AddRange(infoFixable);
        }

        var grouped = fixableFindings
            .GroupBy(f => f.Category)
            .OrderByDescending(g => g.Any(f => f.Severity == Severity.Critical))
            .ThenBy(g => g.Key)
            .ToList();

        var sb = new StringBuilder();

        // Header
        sb.AppendLine("#Requires -RunAsAdministrator");
        sb.AppendLine("<#");
        sb.AppendLine(".SYNOPSIS");
        sb.AppendLine("    WinSentinel Hardening Script");
        sb.AppendLine();
        sb.AppendLine(".DESCRIPTION");
        sb.AppendLine($"    Auto-generated from WinSentinel audit on {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"    Machine: {Environment.MachineName}");
        sb.AppendLine($"    Current Score: {report.SecurityScore}/100 ({SecurityScorer.GetGrade(report.SecurityScore)})");
        sb.AppendLine($"    Fixable Issues: {fixableFindings.Count} ({fixableFindings.Count(f => f.Severity == Severity.Critical)} critical, {fixableFindings.Count(f => f.Severity == Severity.Warning)} warning)");
        sb.AppendLine();
        sb.AppendLine("    REVIEW THIS SCRIPT BEFORE RUNNING. Each section can be toggled independently.");
        sb.AppendLine("    Some fixes may require a reboot to take effect.");
        sb.AppendLine();
        sb.AppendLine(".NOTES");
        sb.AppendLine("    Run with: .\\harden.ps1");
        if (options.Interactive)
            sb.AppendLine("    Mode: Interactive (prompts before each fix)");
        else if (options.DryRun)
            sb.AppendLine("    Mode: Dry-run (shows what would be executed)");
        else
            sb.AppendLine("    Mode: Automatic (executes all fixes)");
        sb.AppendLine("#>");
        sb.AppendLine();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$script:FixesApplied = 0");
        sb.AppendLine("$script:FixesFailed = 0");
        sb.AppendLine("$script:FixesSkipped = 0");
        sb.AppendLine("$script:Aborted = $false");
        sb.AppendLine();

        // Banner
        sb.AppendLine("Write-Host ''");
        sb.AppendLine("Write-Host '  ╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan");
        sb.AppendLine("Write-Host '  ║      🛡️  WinSentinel Hardening Script            ║' -ForegroundColor Cyan");
        sb.AppendLine("Write-Host '  ╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan");
        sb.AppendLine($"Write-Host '  Generated: {DateTimeOffset.Now:yyyy-MM-dd HH:mm} | Fixes: {fixableFindings.Count}' -ForegroundColor DarkGray");
        sb.AppendLine("Write-Host ''");
        sb.AppendLine();

        // Helper function
        sb.AppendLine("function Invoke-Fix {");
        sb.AppendLine("    param([string]$Title, [string]$Severity, [string]$Description, [scriptblock]$Fix)");
        sb.AppendLine("    if ($script:Aborted) { return }");
        sb.AppendLine();
        sb.AppendLine("    $sevColor = switch ($Severity) {");
        sb.AppendLine("        'Critical' { 'Red' }");
        sb.AppendLine("        'Warning'  { 'Yellow' }");
        sb.AppendLine("        'Info'     { 'Cyan' }");
        sb.AppendLine("        default    { 'Gray' }");
        sb.AppendLine("    }");
        sb.AppendLine();

        if (options.DryRun)
        {
            sb.AppendLine("    Write-Host '  [DRY-RUN] ' -NoNewline -ForegroundColor Magenta");
            sb.AppendLine("    Write-Host \"[$Severity] \" -NoNewline -ForegroundColor $sevColor");
            sb.AppendLine("    Write-Host $Title -ForegroundColor White");
            sb.AppendLine("    Write-Host \"           $Description\" -ForegroundColor DarkGray");
            sb.AppendLine("    Write-Host \"           Command: $($Fix.ToString().Trim())\" -ForegroundColor DarkGray");
            sb.AppendLine("    $script:FixesSkipped++");
        }
        else
        {
            if (options.Interactive)
            {
                sb.AppendLine("    Write-Host ''");
                sb.AppendLine("    Write-Host \"  [$Severity] \" -NoNewline -ForegroundColor $sevColor");
                sb.AppendLine("    Write-Host $Title -ForegroundColor White");
                sb.AppendLine("    Write-Host \"  $Description\" -ForegroundColor DarkGray");
                sb.AppendLine("    $response = Read-Host '  Apply this fix? (y/N/q)'");
                sb.AppendLine("    if ($response -eq 'q') {");
                sb.AppendLine("        Write-Host '  Aborted by user.' -ForegroundColor Yellow");
                sb.AppendLine("        $script:Aborted = $true");
                sb.AppendLine("        return");
                sb.AppendLine("    }");
                sb.AppendLine("    if ($response -ne 'y' -and $response -ne 'Y') {");
                sb.AppendLine("        Write-Host '  Skipped.' -ForegroundColor DarkGray");
                sb.AppendLine("        $script:FixesSkipped++");
                sb.AppendLine("        return");
                sb.AppendLine("    }");
            }

            sb.AppendLine("    try {");
            sb.AppendLine("        & $Fix");
            sb.AppendLine("        Write-Host '  ✓ ' -NoNewline -ForegroundColor Green");
            sb.AppendLine("        Write-Host $Title -ForegroundColor White");
            sb.AppendLine("        $script:FixesApplied++");
            sb.AppendLine("    }");
            sb.AppendLine("    catch {");
            sb.AppendLine("        Write-Host '  ✗ ' -NoNewline -ForegroundColor Red");
            sb.AppendLine("        Write-Host \"$Title - $($_.Exception.Message)\" -ForegroundColor White");
            sb.AppendLine("        $script:FixesFailed++");
            sb.AppendLine("    }");
        }
        sb.AppendLine("}");
        sb.AppendLine();

        if (fixableFindings.Count == 0)
        {
            sb.AppendLine("Write-Host '  ✓ No fixable findings - system is already secure!' -ForegroundColor Green");
            sb.AppendLine("Write-Host ''");
            return sb.ToString();
        }

        // Generate fix sections
        int sectionNum = 0;
        foreach (var group in grouped)
        {
            sectionNum++;
            var critCount = group.Count(f => f.Severity == Severity.Critical);
            var warnCount = group.Count(f => f.Severity == Severity.Warning);

            sb.AppendLine($"# ── Section {sectionNum}: {group.Key} ({group.Count()} fixes) ──");
            sb.AppendLine($"Write-Host '  ━━━ {EscapePs(group.Key)} ({group.Count()} fixes) ━━━' -ForegroundColor Cyan");
            sb.AppendLine();

            var ordered = group
                .OrderByDescending(f => f.Severity == Severity.Critical ? 2 : f.Severity == Severity.Warning ? 1 : 0)
                .ToList();

            foreach (var finding in ordered)
            {
                var desc = EscapePs(finding.Description);
                var title = EscapePs(finding.Title);
                var fixCmd = finding.FixCommand!.Trim();

                sb.AppendLine($"# {finding.Severity}: {finding.Title}");
                if (!string.IsNullOrWhiteSpace(finding.Remediation))
                    sb.AppendLine($"# Remediation: {finding.Remediation}");
                sb.AppendLine($"Invoke-Fix -Title '{title}' -Severity '{finding.Severity}' -Description '{desc}' -Fix {{");
                sb.AppendLine($"    {fixCmd}");
                sb.AppendLine("}");
                sb.AppendLine();
            }
        }

        // Summary
        sb.AppendLine("# ── Summary ──");
        sb.AppendLine("Write-Host ''");
        sb.AppendLine("Write-Host '  ══════════════════════════════════════════' -ForegroundColor Cyan");
        sb.AppendLine("Write-Host '  Summary' -ForegroundColor Cyan");
        sb.AppendLine("Write-Host '  ──────────────────────────────────────────' -ForegroundColor DarkGray");
        sb.AppendLine("Write-Host \"  Applied:  $script:FixesApplied\" -ForegroundColor Green");
        sb.AppendLine("Write-Host \"  Failed:   $script:FixesFailed\" -ForegroundColor Red");
        sb.AppendLine("Write-Host \"  Skipped:  $script:FixesSkipped\" -ForegroundColor Yellow");
        sb.AppendLine("Write-Host ''");
        sb.AppendLine("if ($script:FixesApplied -gt 0) {");
        sb.AppendLine("    Write-Host '  Run \"winsentinel --score\" to check your new security score.' -ForegroundColor DarkGray");
        sb.AppendLine("    Write-Host '  Some changes may require a reboot.' -ForegroundColor DarkGray");
        sb.AppendLine("}");
        sb.AppendLine("Write-Host ''");

        return sb.ToString();
    }

    private static string EscapePs(string s)
    {
        return s.Replace("'", "''").Replace("\r", "").Replace("\n", " ");
    }
}

/// <summary>
/// Options for hardening script generation.
/// </summary>
public class HardenScriptOptions
{
    /// <summary>Prompt before each fix (default: true).</summary>
    public bool Interactive { get; set; } = true;

    /// <summary>Show what would be done without executing.</summary>
    public bool DryRun { get; set; }

    /// <summary>Include Info-severity fixes (default: false).</summary>
    public bool IncludeInfo { get; set; }
}
