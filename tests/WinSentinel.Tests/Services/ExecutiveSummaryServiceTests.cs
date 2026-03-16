using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ExecutiveSummaryServiceTests
{
    private static SecurityReport CreateTestReport(int score, List<AuditResult>? results = null)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = results ?? new List<AuditResult>()
        };
    }

    private static AuditResult CreateModule(string category, params (string title, Severity sev, string? fix)[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = category + "Audit",
            Category = category,
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1),
            Findings = findings.Select(f => new Finding
            {
                Title = f.title,
                Severity = f.sev,
                Description = $"{f.title} description",
                Remediation = $"Fix {f.title}",
                FixCommand = f.fix
            }).ToList()
        };
        return result;
    }

    [Fact]
    public void Generate_EmptyReport_ReturnsValidSummary()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(100);

        var summary = service.Generate(report);

        Assert.Equal(100, summary.Score);
        Assert.NotEmpty(summary.Grade);
        Assert.NotEmpty(summary.Verdict);
        Assert.Empty(summary.TopRisks);
        Assert.Empty(summary.Modules);
        Assert.Equal(0, summary.TotalFindings);
        Assert.Null(summary.Trend);
    }

    [Fact]
    public void Generate_WithFindings_PopulatesTopRisks()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(65, new List<AuditResult>
        {
            CreateModule("Firewall",
                ("Firewall Disabled", Severity.Critical, "Enable-NetFirewall"),
                ("Rule Too Broad", Severity.Warning, null)),
            CreateModule("Updates",
                ("Pending Updates", Severity.Warning, "Install-WindowsUpdate")),
            CreateModule("Defender",
                ("Real-time Off", Severity.Critical, "Set-MpPreference"))
        });

        var summary = service.Generate(report);

        Assert.Equal(65, summary.Score);
        Assert.Equal(3, summary.ModulesScanned);
        Assert.True(summary.TopRisks.Count <= 5);
        Assert.True(summary.TopRisks.Count > 0);
        // Critical findings should be first
        Assert.Equal("Critical", summary.TopRisks[0].Severity);
    }

    [Fact]
    public void Generate_HighScore_PositiveVerdict()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(95, new List<AuditResult>
        {
            CreateModule("Firewall", ("Check OK", Severity.Pass, null))
        });

        var summary = service.Generate(report);

        Assert.Contains("strong", summary.Verdict.ToLower());
    }

    [Fact]
    public void Generate_LowScore_NegativeVerdict()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(40, new List<AuditResult>
        {
            CreateModule("Firewall",
                ("Critical Issue 1", Severity.Critical, null),
                ("Critical Issue 2", Severity.Critical, null),
                ("Critical Issue 3", Severity.Critical, null),
                ("Critical Issue 4", Severity.Critical, null),
                ("Critical Issue 5", Severity.Critical, null),
                ("Critical Issue 6", Severity.Critical, null))
        });

        var summary = service.Generate(report);

        Assert.Contains("immediate", summary.Verdict.ToLower());
    }

    [Fact]
    public void Generate_WithTrend_IncludesTrendSnapshot()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(80);
        var trend = new ScoreTrendSummary
        {
            CurrentScore = 80,
            PreviousScore = 70,
            TotalScans = 5,
            AverageScore = 75.0
        };

        var summary = service.Generate(report, trend);

        Assert.NotNull(summary.Trend);
        Assert.Equal(10, summary.Trend!.ScoreChange);
        Assert.Equal("improving", summary.Trend.Direction);
        Assert.Equal(70, summary.Trend.PreviousScore);
    }

    [Fact]
    public void Generate_NoTrendWithSingleScan_TrendIsNull()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(80);
        var trend = new ScoreTrendSummary
        {
            CurrentScore = 80,
            TotalScans = 1,
            AverageScore = 80.0
        };

        var summary = service.Generate(report, trend);

        Assert.Null(summary.Trend);
    }

    [Fact]
    public void Generate_ModuleHealth_OrderedByScore()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(70, new List<AuditResult>
        {
            CreateModule("Firewall", ("Issue A", Severity.Critical, null)),
            CreateModule("Defender", ("Pass", Severity.Pass, null)),
            CreateModule("Updates", ("Warn", Severity.Warning, null))
        });

        var summary = service.Generate(report);

        // Should be ordered ascending by score (worst first)
        Assert.Equal(3, summary.Modules.Count);
        Assert.True(summary.Modules[0].Score <= summary.Modules[1].Score);
    }

    [Fact]
    public void Generate_Strengths_ContainsPerfectModules()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(90, new List<AuditResult>
        {
            CreateModule("Firewall", ("All good", Severity.Pass, null)),
            CreateModule("Defender", ("Bad thing", Severity.Critical, null))
        });

        var summary = service.Generate(report);

        Assert.Contains("Firewall", summary.Strengths);
        Assert.DoesNotContain("Defender", summary.Strengths);
    }

    [Fact]
    public void Generate_ActionItems_IncludesAutoFixSuggestion()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(60, new List<AuditResult>
        {
            CreateModule("Firewall",
                ("Firewall Off", Severity.Critical, "Enable-NetFirewall"),
                ("Bad Rule", Severity.Warning, "Remove-NetFirewallRule"))
        });

        var summary = service.Generate(report);

        Assert.True(summary.ActionItems.Count > 0);
        Assert.Contains(summary.ActionItems, a => a.Action.Contains("--harden"));
    }

    [Fact]
    public void RenderText_ProducesNonEmptyOutput()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(75, new List<AuditResult>
        {
            CreateModule("Firewall", ("Issue", Severity.Warning, null))
        });
        var summary = service.Generate(report);

        var text = ExecutiveSummaryService.RenderText(summary);

        Assert.NotEmpty(text);
        Assert.Contains("EXECUTIVE SECURITY SUMMARY", text);
        Assert.Contains("75/100", text);
        Assert.Contains("MODULE HEALTH", text);
    }

    [Fact]
    public void RenderHtml_ProducesValidHtml()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(85, new List<AuditResult>
        {
            CreateModule("Firewall", ("Pass", Severity.Pass, null))
        });
        var summary = service.Generate(report);

        var html = ExecutiveSummaryService.RenderHtml(summary);

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("Executive Security Summary", html);
        Assert.Contains("85/100", html);
    }

    [Fact]
    public void Generate_TopRisks_LimitedToFive()
    {
        var service = new ExecutiveSummaryService();
        var findings = Enumerable.Range(1, 10)
            .Select(i => ($"Finding {i}", Severity.Warning, (string?)null))
            .ToArray();
        var report = CreateTestReport(50, new List<AuditResult>
        {
            CreateModule("Firewall", findings)
        });

        var summary = service.Generate(report);

        Assert.Equal(5, summary.TopRisks.Count);
    }

    [Fact]
    public void Generate_TopRisks_HasAutoFixFlag()
    {
        var service = new ExecutiveSummaryService();
        var report = CreateTestReport(60, new List<AuditResult>
        {
            CreateModule("Firewall",
                ("Fixable Issue", Severity.Critical, "some-fix-command"),
                ("Manual Issue", Severity.Critical, null))
        });

        var summary = service.Generate(report);

        var fixable = summary.TopRisks.FirstOrDefault(r => r.Title == "Fixable Issue");
        var manual = summary.TopRisks.FirstOrDefault(r => r.Title == "Manual Issue");
        Assert.NotNull(fixable);
        Assert.NotNull(manual);
        Assert.True(fixable!.HasAutoFix);
        Assert.False(manual!.HasAutoFix);
    }
}
