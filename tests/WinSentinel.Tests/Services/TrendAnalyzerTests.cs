using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class TrendAnalyzerTests
{
    private readonly TrendAnalyzer _analyzer = new();

    private static List<AuditRunRecord> CreateRuns(params (int score, string grade, int days)[] data)
    {
        var now = DateTimeOffset.UtcNow;
        return data.Select(d => new AuditRunRecord
        {
            Id = data.ToList().IndexOf(d) + 1,
            Timestamp = now.AddDays(-d.days),
            OverallScore = d.score,
            Grade = d.grade,
            TotalFindings = 10,
            CriticalCount = d.score < 50 ? 3 : 0,
            WarningCount = d.score < 80 ? 5 : 1,
            InfoCount = 2,
            PassCount = 3,
        }).ToList();
    }

    // ── Basic Analysis ──────────────────────────────────────────────

    [Fact]
    public void Analyze_EmptyRuns_ReturnsNoData()
    {
        var report = _analyzer.Analyze([]);
        Assert.False(report.HasData);
    }

    [Fact]
    public void Analyze_SingleRun_PopulatesBasicFields()
    {
        var runs = CreateRuns((85, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Equal(85, report.CurrentScore);
        Assert.Equal("A", report.CurrentGrade);
        Assert.Equal(1, report.TotalScans);
        Assert.Null(report.PreviousScore);
        Assert.Equal(0, report.ScoreChange);
    }

    [Fact]
    public void Analyze_MultipleRuns_CalculatesScoreChange()
    {
        var runs = CreateRuns((70, "C", 3), (80, "B", 1), (85, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(85, report.CurrentScore);
        Assert.Equal(80, report.PreviousScore);
        Assert.Equal(5, report.ScoreChange);
    }

    // ── Statistics ──────────────────────────────────────────────────

    [Fact]
    public void Analyze_CalculatesAverage()
    {
        var runs = CreateRuns((60, "C", 5), (80, "B", 3), (100, "A+", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(80, report.AverageScore);
    }

    [Fact]
    public void Analyze_CalculatesMedian_OddCount()
    {
        var runs = CreateRuns((50, "D", 5), (70, "C", 3), (90, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(70, report.MedianScore);
    }

    [Fact]
    public void Analyze_CalculatesMedian_EvenCount()
    {
        var runs = CreateRuns((50, "D", 5), (60, "C", 3), (70, "C", 1), (80, "B", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(65, report.MedianScore); // (60+70)/2
    }

    [Fact]
    public void Analyze_FindsBestAndWorst()
    {
        var runs = CreateRuns((70, "C", 5), (95, "A+", 3), (60, "C", 1), (80, "B", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(95, report.BestScore);
        Assert.Equal("A+", report.BestScoreGrade);
        Assert.Equal(60, report.WorstScore);
        Assert.Equal("C", report.WorstScoreGrade);
    }

    [Fact]
    public void Analyze_CalculatesStdDev()
    {
        var runs = CreateRuns((80, "B", 3), (80, "B", 1), (80, "B", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(0, report.ScoreStdDev); // All same = 0 deviation
    }

    // ── Trend Direction ─────────────────────────────────────────────

    [Fact]
    public void Analyze_DetectsImprovingTrend()
    {
        var runs = CreateRuns((50, "D", 10), (60, "C", 7), (70, "C", 4), (80, "B", 1), (90, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(TrendDirection.Improving, report.TrendDirection);
        Assert.True(report.TrendSlope > 0);
    }

    [Fact]
    public void Analyze_DetectsDecliningTrend()
    {
        var runs = CreateRuns((90, "A", 10), (80, "B", 7), (70, "C", 4), (60, "C", 1), (50, "D", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(TrendDirection.Declining, report.TrendDirection);
        Assert.True(report.TrendSlope < 0);
    }

    [Fact]
    public void Analyze_DetectsStableTrend()
    {
        var runs = CreateRuns((80, "B", 5), (80, "B", 3), (80, "B", 1), (80, "B", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(TrendDirection.Stable, report.TrendDirection);
    }

    // ── Streaks ─────────────────────────────────────────────────────

    [Fact]
    public void Analyze_TracksImprovementStreak()
    {
        var runs = CreateRuns((60, "C", 5), (50, "D", 4), (55, "D", 3), (65, "C", 2), (75, "C", 1), (85, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(4, report.CurrentImprovementStreak); // 50→55→65→75→85
        Assert.Equal(4, report.BestImprovementStreak);
    }

    [Fact]
    public void Analyze_TracksDeclineStreak()
    {
        var runs = CreateRuns((90, "A", 3), (85, "A", 2), (80, "B", 1), (70, "C", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(3, report.CurrentDeclineStreak);
    }

    [Fact]
    public void Analyze_StreakResets()
    {
        var runs = CreateRuns((70, "C", 4), (80, "B", 3), (90, "A", 2), (85, "A", 1), (88, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(1, report.CurrentImprovementStreak); // only 85→88
        Assert.Equal(2, report.BestImprovementStreak);   // 70→80→90
    }

    // ── Score Distribution ──────────────────────────────────────────

    [Fact]
    public void Analyze_CalculatesDistribution()
    {
        var runs = CreateRuns(
            (10, "F", 10), (30, "F", 8), (50, "D", 6),
            (70, "C", 4), (90, "A", 2), (95, "A+", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(1, report.Distribution["0-19"]);
        Assert.Equal(1, report.Distribution["20-39"]);
        Assert.Equal(1, report.Distribution["40-59"]);
        Assert.Equal(1, report.Distribution["60-79"]);
        Assert.Equal(2, report.Distribution["80-100"]);
    }

    // ── Alerts ──────────────────────────────────────────────────────

    [Fact]
    public void Analyze_AlertsBelowThreshold()
    {
        var runs = CreateRuns((60, "C", 0));
        var report = _analyzer.Analyze(runs, new TrendOptions { AlertThreshold = 80 });

        Assert.Single(report.Alerts);
        Assert.Equal(AlertLevel.Critical, report.Alerts[0].Level);
        Assert.Contains("below threshold", report.Alerts[0].Message);
    }

    [Fact]
    public void Analyze_NoAlertAboveThreshold()
    {
        var runs = CreateRuns((90, "A", 0));
        var report = _analyzer.Analyze(runs, new TrendOptions { AlertThreshold = 80 });

        Assert.Empty(report.Alerts);
    }

    [Fact]
    public void Analyze_AlertOnLargeScoreDrop()
    {
        var runs = CreateRuns((90, "A", 1), (70, "C", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Contains(report.Alerts, a => a.Message.Contains("dropped 20 points"));
    }

    [Fact]
    public void Analyze_AlertOnNewCriticalFindings()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            new() { Id = 1, Timestamp = now.AddDays(-1), OverallScore = 80, Grade = "B",
                    CriticalCount = 0, WarningCount = 2 },
            new() { Id = 2, Timestamp = now, OverallScore = 75, Grade = "C",
                    CriticalCount = 3, WarningCount = 4 },
        };
        var report = _analyzer.Analyze(runs);

        Assert.Contains(report.Alerts, a => a.Message.Contains("new critical"));
    }

    // ── Sparkline ───────────────────────────────────────────────────

    [Fact]
    public void GenerateSparkline_IncreasingScores()
    {
        var sparkline = TrendAnalyzer.GenerateSparkline([20, 40, 60, 80, 100]);

        Assert.Equal(5, sparkline.Length);
        // Should end with highest block
        Assert.Equal('█', sparkline[^1]);
    }

    [Fact]
    public void GenerateSparkline_AllSame()
    {
        var sparkline = TrendAnalyzer.GenerateSparkline([50, 50, 50]);
        // All should be the same character
        Assert.True(sparkline.Distinct().Count() == 1);
    }

    [Fact]
    public void GenerateSparkline_Empty()
    {
        var sparkline = TrendAnalyzer.GenerateSparkline([]);
        Assert.Equal("", sparkline);
    }

    // ── Bar Chart ───────────────────────────────────────────────────

    [Fact]
    public void GenerateBarChart_EmptyRuns()
    {
        var result = TrendAnalyzer.GenerateBarChart([]);
        Assert.Equal("No data", result);
    }

    [Fact]
    public void GenerateBarChart_ContainsScores()
    {
        var runs = CreateRuns((85, "A", 1), (90, "A", 0));
        var chart = TrendAnalyzer.GenerateBarChart(runs);

        Assert.Contains("85", chart);
        Assert.Contains("90", chart);
        Assert.Contains("█", chart);
    }

    // ── Module Trends ───────────────────────────────────────────────

    [Fact]
    public void Analyze_BuildsModuleTrends()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            new()
            {
                Id = 1, Timestamp = now.AddDays(-1), OverallScore = 80, Grade = "B",
                ModuleScores =
                [
                    new() { ModuleName = "Firewall", Category = "Network", Score = 90 },
                    new() { ModuleName = "Updates", Category = "System", Score = 70 },
                ]
            },
            new()
            {
                Id = 2, Timestamp = now, OverallScore = 85, Grade = "A",
                ModuleScores =
                [
                    new() { ModuleName = "Firewall", Category = "Network", Score = 95 },
                    new() { ModuleName = "Updates", Category = "System", Score = 75 },
                ]
            },
        };
        var report = _analyzer.Analyze(runs);

        Assert.Equal(2, report.ModuleTrends.Count);
        var firewall = report.ModuleTrends.First(m => m.ModuleName == "Firewall");
        Assert.Equal(95, firewall.CurrentScore);
        Assert.Equal(90, firewall.PreviousScore);
        Assert.Equal(5, firewall.ScoreChange);
    }

    // ── Sparkline Score Population ──────────────────────────────────

    [Fact]
    public void Analyze_PopulatesSparklineScores()
    {
        var runs = CreateRuns((60, "C", 5), (70, "C", 3), (80, "B", 1), (90, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.Equal(4, report.SparklineScores.Count);
        Assert.Equal(60, report.SparklineScores[0]);
        Assert.Equal(90, report.SparklineScores[^1]);
    }

    [Fact]
    public void Analyze_SparklineRespectsWidth()
    {
        var runs = CreateRuns(
            (50, "D", 10), (55, "D", 8), (60, "C", 6),
            (65, "C", 4), (70, "C", 2), (75, "C", 0));
        var report = _analyzer.Analyze(runs, new TrendOptions { SparklineWidth = 3 });

        Assert.Equal(3, report.SparklineScores.Count);
        Assert.Equal(75, report.SparklineScores[^1]); // Most recent
    }

    // ── Time Span ───────────────────────────────────────────────────

    [Fact]
    public void Analyze_CalculatesTimeSpan()
    {
        var runs = CreateRuns((80, "B", 7), (85, "A", 0));
        var report = _analyzer.Analyze(runs);

        Assert.True(report.TimeSpan.TotalDays >= 6.9);
        Assert.True(report.TimeSpan.TotalDays <= 7.1);
    }

    // ── Combined Alerts ─────────────────────────────────────────────

    [Fact]
    public void Analyze_MultipleAlerts()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            new() { Id = 1, Timestamp = now.AddDays(-1), OverallScore = 90, Grade = "A",
                    CriticalCount = 0, WarningCount = 1 },
            new() { Id = 2, Timestamp = now, OverallScore = 60, Grade = "C",
                    CriticalCount = 5, WarningCount = 8 },
        };
        var report = _analyzer.Analyze(runs, new TrendOptions { AlertThreshold = 80 });

        // Should have: below threshold + large drop + new critical findings
        Assert.True(report.Alerts.Count >= 3);
    }
}
