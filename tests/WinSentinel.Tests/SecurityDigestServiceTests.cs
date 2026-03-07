using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class SecurityDigestServiceTests
{
    private SecurityReport CreateReport(int criticals = 0, int warnings = 2, int infos = 1, int passes = 5)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticals; i++)
            findings.Add(Finding.Critical($"Critical Issue {i + 1}", "Desc", "Firewall", "Fix it"));
        for (int i = 0; i < warnings; i++)
            findings.Add(Finding.Warning($"Warning Issue {i + 1}", "Desc", "Network", "Review it", "Set-Something"));
        for (int i = 0; i < infos; i++)
            findings.Add(Finding.Info($"Info Issue {i + 1}", "Desc", "System"));
        for (int i = 0; i < passes; i++)
            findings.Add(Finding.Pass($"Pass {i + 1}", "OK", "System"));

        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test Category",
            Findings = findings,
            Success = true,
            StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
            EndTime = DateTimeOffset.UtcNow
        };

        var report = new SecurityReport { Results = new List<AuditResult> { result } };
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    private List<AuditRunRecord> CreateHistory(params int[] scores)
    {
        var runs = new List<AuditRunRecord>();
        var baseDate = DateTimeOffset.UtcNow.AddDays(-scores.Length);
        for (int i = 0; i < scores.Length; i++)
        {
            runs.Add(new AuditRunRecord
            {
                Id = i + 1,
                Timestamp = baseDate.AddDays(i),
                OverallScore = scores[i],
                Grade = SecurityScorer.GetGrade(scores[i]),
                TotalFindings = 5,
                CriticalCount = scores[i] < 50 ? 2 : 0,
                WarningCount = scores[i] < 80 ? 3 : 1,
                InfoCount = 1,
                PassCount = 3,
            });
        }
        return runs;
    }

    [Fact]
    public void Generate_BasicReport_ReturnsDigest()
    {
        var service = new SecurityDigestService();
        var report = CreateReport();
        var digest = service.Generate(report);

        Assert.NotNull(digest);
        Assert.Equal(Environment.MachineName, digest.MachineName);
        Assert.True(digest.Score >= 0 && digest.Score <= 100);
        Assert.NotEmpty(digest.Grade);
        Assert.NotEmpty(digest.Assessment);
        Assert.NotEmpty(digest.NextSteps);
    }

    [Fact]
    public void Generate_WithCriticalFindings_HighlightsInTopRisks()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(criticals: 3, warnings: 2);
        var digest = service.Generate(report);

        Assert.True(digest.CriticalCount == 3);
        Assert.True(digest.TopRisks.Count > 0);
        Assert.Equal(Severity.Critical, digest.TopRisks[0].Severity);
        Assert.Contains("ATTENTION", digest.Assessment);
    }

    [Fact]
    public void Generate_WithHistory_IncludesTrend()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(warnings: 1);
        var history = CreateHistory(70, 75, 80, 85);
        var digest = service.Generate(report, history);

        Assert.NotNull(digest.Trend);
        Assert.Equal("Improving", digest.Trend!.Direction);
        Assert.Equal(5, digest.Trend.ScoreChange);
        Assert.Equal(4, digest.Trend.TotalScans);
        Assert.Equal(85, digest.Trend.BestScore);
        Assert.Equal(70, digest.Trend.WorstScore);
    }

    [Fact]
    public void Generate_DecliningTrend_ShowsWarning()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(criticals: 1, warnings: 3);
        var history = CreateHistory(90, 85, 80, 70);
        var digest = service.Generate(report, history);

        Assert.NotNull(digest.Trend);
        Assert.Equal("Declining", digest.Trend!.Direction);
        Assert.True(digest.Trend.ScoreChange < 0);
        Assert.Contains(digest.NextSteps, s => s.Contains("dropped"));
    }

    [Fact]
    public void Generate_NoHistory_TrendIsNull()
    {
        var service = new SecurityDigestService();
        var report = CreateReport();
        var digest = service.Generate(report, null);

        Assert.Null(digest.Trend);
    }

    [Fact]
    public void Generate_SingleHistoryEntry_TrendIsNull()
    {
        var service = new SecurityDigestService();
        var report = CreateReport();
        var history = CreateHistory(80);
        var digest = service.Generate(report, history);

        Assert.Null(digest.Trend);
    }

    [Fact]
    public void Generate_HighScore_SuggestsBaseline()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(criticals: 0, warnings: 0, infos: 1, passes: 10);
        var digest = service.Generate(report);

        Assert.True(digest.Score >= 90);
        Assert.Contains(digest.NextSteps, s => s.Contains("baseline"));
    }

    [Fact]
    public void Generate_ModuleBreakdown_SortedByScore()
    {
        var findings1 = new List<Finding>
        {
            Finding.Critical("Bad thing", "Desc", "Firewall"),
            Finding.Critical("Worse thing", "Desc", "Firewall"),
        };
        var findings2 = new List<Finding>
        {
            Finding.Pass("Good", "OK", "Network"),
        };

        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new() { ModuleName = "FirewallAudit", Category = "Firewall", Findings = findings1, Success = true, StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow },
                new() { ModuleName = "NetworkAudit", Category = "Network", Findings = findings2, Success = true, StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow },
            }
        };
        report.SecurityScore = SecurityScorer.CalculateScore(report);

        var service = new SecurityDigestService();
        var digest = service.Generate(report);

        Assert.Equal(2, digest.ModuleBreakdown.Count);
        // Worst module first
        Assert.True(digest.ModuleBreakdown[0].Score <= digest.ModuleBreakdown[1].Score);
    }

    [Fact]
    public void Generate_TopRisks_MaxFive()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(criticals: 4, warnings: 5);
        var digest = service.Generate(report);

        Assert.True(digest.TopRisks.Count <= 5);
    }

    [Fact]
    public void Generate_AutoFixable_MentionedInNextSteps()
    {
        var service = new SecurityDigestService();
        var report = CreateReport(warnings: 3); // warnings have FixCommand set
        var digest = service.Generate(report);

        Assert.Contains(digest.NextSteps, s => s.Contains("fix-all") || s.Contains("auto-fix"));
    }
}
