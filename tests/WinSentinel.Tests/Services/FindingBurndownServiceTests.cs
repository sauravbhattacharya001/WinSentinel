using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FindingBurndownServiceTests
{
    private static List<AuditRunRecord> CreateMockRuns(params (int total, int critical, int warning, int info, int score, int daysAgo)[] specs)
    {
        var runs = new List<AuditRunRecord>();
        foreach (var (total, critical, warning, info, score, daysAgo) in specs)
        {
            runs.Add(new AuditRunRecord
            {
                Id = runs.Count + 1,
                Timestamp = DateTimeOffset.UtcNow.AddDays(-daysAgo),
                TotalFindings = total,
                CriticalCount = critical,
                WarningCount = warning,
                InfoCount = info,
                OverallScore = score,
                Grade = score >= 80 ? "A" : score >= 60 ? "B" : "C"
            });
        }
        return runs;
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnsNoData()
    {
        var service = new FindingBurndownService();
        var result = service.Analyze([], new BurndownOptions());
        Assert.False(result.HasData);
    }

    [Fact]
    public void Analyze_SingleRun_HasDataButNoVelocity()
    {
        var runs = CreateMockRuns((10, 2, 5, 3, 70, 0));
        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        Assert.True(result.HasData);
        Assert.Single(result.DataPoints);
        Assert.Equal(0, result.Velocity.AverageDailyReduction);
    }

    [Fact]
    public void Analyze_ImprovingTrend_PositiveVelocity()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 30),
            (15, 3, 8, 4, 60, 20),
            (10, 2, 5, 3, 70, 10),
            (5, 1, 2, 2, 85, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        Assert.True(result.HasData);
        Assert.True(result.Velocity.AverageDailyReduction > 0);
        Assert.Equal(15, result.Velocity.TotalResolved);
        Assert.NotNull(result.ProjectedZeroDate);
    }

    [Fact]
    public void Analyze_DegradingTrend_NegativeVelocity()
    {
        var runs = CreateMockRuns(
            (5, 1, 2, 2, 85, 20),
            (10, 2, 5, 3, 70, 10),
            (15, 3, 8, 4, 60, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        Assert.True(result.Velocity.AverageDailyReduction < 0);
        Assert.Null(result.ProjectedZeroDate);
    }

    [Fact]
    public void Analyze_SeverityTrends_Populated()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 10),
            (10, 2, 5, 3, 70, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        Assert.True(result.SeverityTrends.ContainsKey("Critical"));
        Assert.True(result.SeverityTrends.ContainsKey("Warning"));
        Assert.True(result.SeverityTrends.ContainsKey("Info"));
        Assert.Equal(2, result.SeverityTrends["Critical"].Count);
    }

    [Fact]
    public void Analyze_VelocityStats_TracksStreaks()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 40),
            (18, 4, 9, 5, 55, 30),
            (15, 3, 8, 4, 60, 20),
            (12, 2, 6, 4, 65, 10),
            (10, 2, 5, 3, 70, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        Assert.Equal(4, result.Velocity.ResolutionIntervals);
        Assert.Equal(0, result.Velocity.RegressionIntervals);
        Assert.True(result.Velocity.BestImprovementStreak >= 4);
    }

    [Fact]
    public void RenderText_ProducesOutput()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 20),
            (10, 2, 5, 3, 70, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());
        var text = FindingBurndownService.RenderText(result);

        Assert.Contains("Burndown", text);
        Assert.Contains("VELOCITY", text);
        Assert.Contains("PROJECTION", text);
    }

    [Fact]
    public void RenderJson_ValidJson()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 20),
            (10, 2, 5, 3, 70, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());
        var json = FindingBurndownService.RenderJson(result);

        Assert.Contains("HasData", json);
        Assert.Contains("Velocity", json);
    }

    [Fact]
    public void RenderCsv_HasHeaders()
    {
        var runs = CreateMockRuns(
            (20, 5, 10, 5, 50, 10),
            (10, 2, 5, 3, 70, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());
        var csv = FindingBurndownService.RenderCsv(result);

        Assert.StartsWith("timestamp,total_findings", csv);
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length); // header + 2 data rows
    }

    [Fact]
    public void Analyze_ZeroFindings_NoProjection()
    {
        var runs = CreateMockRuns(
            (5, 1, 2, 2, 85, 10),
            (0, 0, 0, 0, 100, 0)
        );

        var service = new FindingBurndownService();
        var result = service.Analyze(runs, new BurndownOptions());

        // Already at zero, no projection needed
        var text = FindingBurndownService.RenderText(result);
        Assert.Contains("Already at zero", text);
    }
}
