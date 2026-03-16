using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class HardenScriptGeneratorTests
{
    private readonly HardenScriptGenerator _generator = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport CreateEmptyReport(int score = 85) => new()
    {
        SecurityScore = score,
        GeneratedAt = new DateTimeOffset(2026, 3, 15, 10, 0, 0, TimeSpan.Zero)
    };

    private static SecurityReport CreateReportWithFindings(params Finding[] findings)
    {
        var report = CreateEmptyReport(60);
        var result = new AuditResult
        {
            ModuleName = "TestAudit",
            Category = "Test",
            StartTime = report.GeneratedAt,
            EndTime = report.GeneratedAt.AddSeconds(1)
        };
        foreach (var f in findings)
            result.Findings.Add(f);
        report.Results.Add(result);
        return report;
    }

    // ── Empty Report ─────────────────────────────────────────────────

    [Fact]
    public void Generate_EmptyReport_ProducesNoFixableMessage()
    {
        var report = CreateEmptyReport();
        var script = _generator.Generate(report);

        Assert.Contains("No fixable findings", script);
        Assert.Contains("system is already secure", script);
    }

    [Fact]
    public void Generate_EmptyReport_IncludesHeader()
    {
        var report = CreateEmptyReport();
        var script = _generator.Generate(report);

        Assert.Contains("#Requires -RunAsAdministrator", script);
        Assert.Contains("WinSentinel Hardening Script", script);
    }

    // ── Findings Without FixCommand Are Skipped ─────────────────────

    [Fact]
    public void Generate_FindingsWithoutFixCommand_AreSkipped()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("No Fix", "No fix available", "Firewall")
        );

        var script = _generator.Generate(report);
        Assert.Contains("No fixable findings", script);
    }

    // ── Critical and Warning Findings Are Included ──────────────────

    [Fact]
    public void Generate_CriticalFinding_IncludedInScript()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("Firewall Disabled", "Windows Firewall is off", "Firewall",
                fixCommand: "Set-NetFirewallProfile -All -Enabled True")
        );

        var script = _generator.Generate(report);
        Assert.Contains("Firewall Disabled", script);
        Assert.Contains("Set-NetFirewallProfile -All -Enabled True", script);
        Assert.Contains("Invoke-Fix", script);
    }

    [Fact]
    public void Generate_WarningFinding_IncludedInScript()
    {
        var report = CreateReportWithFindings(
            Finding.Warning("Weak Password Policy", "Min length is 4", "Accounts",
                fixCommand: "net accounts /minpwlen:12")
        );

        var script = _generator.Generate(report);
        Assert.Contains("Weak Password Policy", script);
        Assert.Contains("net accounts /minpwlen:12", script);
    }

    // ── Info Findings Excluded By Default ────────────────────────────

    [Fact]
    public void Generate_InfoFinding_ExcludedByDefault()
    {
        var report = CreateReportWithFindings(
            Finding.Info("Telemetry Enabled", "Windows telemetry is on", "Privacy",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\...' -Name AllowTelemetry -Value 0")
        );

        var script = _generator.Generate(report);
        Assert.Contains("No fixable findings", script);
    }

    [Fact]
    public void Generate_InfoFinding_IncludedWhenOptionSet()
    {
        var report = CreateReportWithFindings(
            Finding.Info("Telemetry Enabled", "Windows telemetry is on", "Privacy",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\...' -Name AllowTelemetry -Value 0")
        );

        var script = _generator.Generate(report, new HardenScriptOptions { IncludeInfo = true });
        Assert.Contains("Telemetry Enabled", script);
    }

    // ── Interactive Mode ─────────────────────────────────────────────

    [Fact]
    public void Generate_InteractiveMode_ContainsPrompt()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("Test Fix", "Desc", "Category", fixCommand: "echo fix")
        );

        var script = _generator.Generate(report, new HardenScriptOptions { Interactive = true });
        Assert.Contains("Apply this fix? (y/N/q)", script);
        Assert.Contains("Mode: Interactive", script);
    }

    // ── DryRun Mode ──────────────────────────────────────────────────

    [Fact]
    public void Generate_DryRunMode_ContainsDryRunMarker()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("Test Fix", "Desc", "Category", fixCommand: "echo fix")
        );

        var script = _generator.Generate(report, new HardenScriptOptions { DryRun = true, Interactive = false });
        Assert.Contains("[DRY-RUN]", script);
        Assert.Contains("Mode: Dry-run", script);
    }

    // ── Automatic Mode ───────────────────────────────────────────────

    [Fact]
    public void Generate_AutomaticMode_NoPromptNoDryRun()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("Test Fix", "Desc", "Category", fixCommand: "echo fix")
        );

        var script = _generator.Generate(report, new HardenScriptOptions { Interactive = false, DryRun = false });
        Assert.Contains("Mode: Automatic", script);
        Assert.DoesNotContain("Apply this fix?", script);
        Assert.DoesNotContain("[DRY-RUN]", script);
    }

    // ── Multiple Categories Grouped ──────────────────────────────────

    [Fact]
    public void Generate_MultipleCategories_GroupedBySections()
    {
        var report = CreateEmptyReport(40);

        var fwResult = new AuditResult { ModuleName = "FirewallAudit", Category = "Firewall" };
        fwResult.Findings.Add(Finding.Critical("FW Off", "FW disabled", "Firewall", fixCommand: "Enable-Firewall"));

        var acctResult = new AuditResult { ModuleName = "AccountAudit", Category = "Accounts" };
        acctResult.Findings.Add(Finding.Warning("Bad PW", "Weak", "Accounts", fixCommand: "Set-PW"));

        report.Results.Add(fwResult);
        report.Results.Add(acctResult);

        var script = _generator.Generate(report);

        Assert.Contains("Section 1:", script);
        Assert.Contains("Section 2:", script);
        Assert.Contains("Firewall", script);
        Assert.Contains("Accounts", script);
    }

    // ── Critical Findings Sorted Before Warnings ─────────────────────

    [Fact]
    public void Generate_CriticalCategoryAppearsFirst()
    {
        var report = CreateEmptyReport(30);

        var warnResult = new AuditResult { ModuleName = "AcctAudit", Category = "Accounts" };
        warnResult.Findings.Add(Finding.Warning("Warn1", "W", "Accounts", fixCommand: "fix-w"));

        var critResult = new AuditResult { ModuleName = "FWAudit", Category = "Firewall" };
        critResult.Findings.Add(Finding.Critical("Crit1", "C", "Firewall", fixCommand: "fix-c"));

        report.Results.Add(warnResult);
        report.Results.Add(critResult);

        var script = _generator.Generate(report);

        var critIdx = script.IndexOf("Firewall");
        var warnIdx = script.IndexOf("Accounts");
        Assert.True(critIdx < warnIdx, "Critical category should appear before warning-only category");
    }

    // ── Summary Section ──────────────────────────────────────────────

    [Fact]
    public void Generate_IncludesSummarySection()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("Fix1", "D", "Cat", fixCommand: "cmd1")
        );

        var script = _generator.Generate(report);
        Assert.Contains("Summary", script);
        Assert.Contains("Applied:", script);
        Assert.Contains("Failed:", script);
        Assert.Contains("Skipped:", script);
        Assert.Contains("winsentinel --score", script);
    }

    // ── Single Quote Escaping ────────────────────────────────────────

    [Fact]
    public void Generate_SingleQuotesInTitle_AreEscaped()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("User's Firewall", "It's disabled", "Network",
                fixCommand: "echo 'fix'")
        );

        var script = _generator.Generate(report);
        // PowerShell escapes single quotes by doubling them
        Assert.Contains("User''s Firewall", script);
        Assert.Contains("It''s disabled", script);
    }

    // ── Score and Machine Info in Header ──────────────────────────────

    [Fact]
    public void Generate_HeaderIncludesScoreAndMachine()
    {
        var report = CreateEmptyReport(72);
        var script = _generator.Generate(report);

        Assert.Contains("Current Score: 72/100", script);
        Assert.Contains($"Machine: {Environment.MachineName}", script);
    }

    // ── Remediation Comment ──────────────────────────────────────────

    [Fact]
    public void Generate_FindingWithRemediation_IncludesComment()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("SMBv1", "SMBv1 enabled", "Network",
                remediation: "Disable SMBv1 via PowerShell",
                fixCommand: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
        );

        var script = _generator.Generate(report);
        Assert.Contains("# Remediation: Disable SMBv1 via PowerShell", script);
    }

    // ── Fixable Count in Header ──────────────────────────────────────

    [Fact]
    public void Generate_FixableCountInHeader()
    {
        var report = CreateReportWithFindings(
            Finding.Critical("C1", "D1", "Cat", fixCommand: "fix1"),
            Finding.Warning("W1", "D2", "Cat", fixCommand: "fix2"),
            Finding.Critical("C2", "D3", "Cat", fixCommand: "fix3")
        );

        var script = _generator.Generate(report);
        Assert.Contains("Fixable Issues: 3", script);
        Assert.Contains("2 critical", script);
        Assert.Contains("1 warning", script);
    }

    // ── Default Options ──────────────────────────────────────────────

    [Fact]
    public void DefaultOptions_InteractiveTrue_DryRunFalse_IncludeInfoFalse()
    {
        var opts = new HardenScriptOptions();
        Assert.True(opts.Interactive);
        Assert.False(opts.DryRun);
        Assert.False(opts.IncludeInfo);
    }

    // ── Pass Findings Are Never Included ─────────────────────────────

    [Fact]
    public void Generate_PassFindings_NeverIncluded()
    {
        var report = CreateReportWithFindings(
            Finding.Pass("All Good", "Firewall on", "Firewall", fixCommand: "echo noop")
        );

        var script = _generator.Generate(report);
        Assert.Contains("No fixable findings", script);
    }

    // ── ErrorActionPreference Set ────────────────────────────────────

    [Fact]
    public void Generate_SetsErrorActionPreference()
    {
        var report = CreateEmptyReport();
        var script = _generator.Generate(report);
        Assert.Contains("$ErrorActionPreference = 'Stop'", script);
    }

    // ── Banner ───────────────────────────────────────────────────────

    [Fact]
    public void Generate_IncludesBanner()
    {
        var report = CreateEmptyReport();
        var script = _generator.Generate(report);
        Assert.Contains("WinSentinel Hardening Script", script);
        Assert.Contains("Cyan", script);
    }
}
