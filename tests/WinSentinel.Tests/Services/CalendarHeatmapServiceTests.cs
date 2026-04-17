using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class CalendarHeatmapServiceTests
{
    private readonly CalendarHeatmapService _service = new();

    private static AuditRunRecord MakeRun(DateTimeOffset timestamp, int score, int findings = 5, int critical = 0)
        => new()
        {
            Timestamp = timestamp,
            OverallScore = score,
            TotalFindings = findings,
            CriticalCount = critical,
            Grade = score >= 90 ? "A" : score >= 80 ? "B" : "C"
        };

    [Fact]
    public void Analyze_EmptyRuns_ReturnsZeroStats()
    {
        var result = _service.Analyze([], weeks: 4);

        Assert.Equal(4, result.Weeks);
        Assert.Equal(0, result.TotalAudits);
        Assert.Equal(0, result.ActiveDays);
        Assert.Equal(0, result.MaxAuditsInDay);
        Assert.Equal(0, result.BestScore);
        Assert.Equal(0, result.WorstScore);
        Assert.Equal(0, result.CurrentStreak);
        Assert.Equal(0, result.LongestStreak);
    }

    [Fact]
    public void Analyze_EmptyRuns_StillCreatesDayCells()
    {
        var result = _service.Analyze([], weeks: 4);

        // 4 weeks = 28 days of cells
        Assert.Equal(28, result.Days.Count);
    }

    [Fact]
    public void Analyze_SingleRun_CountsOneAuditOneActiveDay()
    {
        var today = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord> { MakeRun(today, 85) };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(1, result.TotalAudits);
        Assert.Equal(1, result.ActiveDays);
        Assert.Equal(1, result.MaxAuditsInDay);
        Assert.Equal(85, result.BestScore);
        Assert.Equal(85, result.WorstScore);
    }

    [Fact]
    public void Analyze_MultipleRunsSameDay_AggregatesCorrectly()
    {
        var today = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(today, 80, findings: 10, critical: 2),
            MakeRun(today.AddHours(-3), 90, findings: 5, critical: 0),
            MakeRun(today.AddHours(-6), 70, findings: 15, critical: 3),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(3, result.TotalAudits);
        Assert.Equal(1, result.ActiveDays);
        Assert.Equal(3, result.MaxAuditsInDay);
        Assert.Equal(90, result.BestScore);
        Assert.Equal(70, result.WorstScore);

        // Find today's cell
        var todayDate = DateOnly.FromDateTime(DateTime.Now);
        var todayCell = result.Days.FirstOrDefault(d => d.Date == todayDate);
        Assert.NotNull(todayCell);
        Assert.Equal(3, todayCell.AuditCount);
        Assert.Equal(80, todayCell.AvgScore); // avg(80,90,70) = 80
        Assert.Equal(30, todayCell.TotalFindings); // 10+5+15
        Assert.Equal(5, todayCell.CriticalCount); // 2+0+3
        Assert.Equal(90, todayCell.BestScore);
    }

    [Fact]
    public void Analyze_ConsecutiveDays_TracksCurrentStreak()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            MakeRun(now.AddDays(-1), 85),
            MakeRun(now.AddDays(-2), 80),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.True(result.CurrentStreak >= 3, $"CurrentStreak should be >= 3 but was {result.CurrentStreak}");
    }

    [Fact]
    public void Analyze_GapInDays_BreaksCurrentStreak()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            // gap: no run yesterday
            MakeRun(now.AddDays(-2), 85),
            MakeRun(now.AddDays(-3), 80),
        };

        var result = _service.Analyze(runs, weeks: 4);

        // Current streak should be 1 (today only) since yesterday is missing
        Assert.Equal(1, result.CurrentStreak);
    }

    [Fact]
    public void Analyze_LongestStreak_ComputedAcrossEntireRange()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            // Current streak: 1 day
            MakeRun(now, 90),
            // Gap
            // Old streak: 5 consecutive days
            MakeRun(now.AddDays(-10), 85),
            MakeRun(now.AddDays(-11), 80),
            MakeRun(now.AddDays(-12), 82),
            MakeRun(now.AddDays(-13), 88),
            MakeRun(now.AddDays(-14), 91),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(5, result.LongestStreak);
    }

    [Fact]
    public void Analyze_DaysCells_AreChronological()
    {
        var runs = new List<AuditRunRecord> { MakeRun(DateTimeOffset.Now, 90) };
        var result = _service.Analyze(runs, weeks: 4);

        for (int i = 1; i < result.Days.Count; i++)
        {
            Assert.True(result.Days[i].Date >= result.Days[i - 1].Date,
                $"Days should be chronological: {result.Days[i - 1].Date} should come before {result.Days[i].Date}");
        }
    }

    [Fact]
    public void Analyze_WeeksParameter_ControlsDayCount()
    {
        var result1 = _service.Analyze([], weeks: 1);
        var result52 = _service.Analyze([], weeks: 52);

        Assert.Equal(7, result1.Days.Count);
        Assert.Equal(364, result52.Days.Count);
    }

    [Fact]
    public void Analyze_RunsOutsideWindow_AreExcluded()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 90),
            MakeRun(now.AddDays(-200), 50), // way outside 4-week window
        };

        var result = _service.Analyze(runs, weeks: 4);

        // Only the recent run should be counted in active days
        // The old run may appear in TotalAudits from runsByDate grouping
        // but the cell won't be in the heatmap range
        Assert.Equal(1, result.ActiveDays);
    }

    [Fact]
    public void Analyze_DayCells_HaveCorrectDayOfWeek()
    {
        var result = _service.Analyze([], weeks: 2);

        foreach (var day in result.Days)
        {
            var expected = day.Date.DayOfWeek;
            Assert.Equal(expected, day.DayOfWeek);
        }
    }

    [Fact]
    public void Analyze_EmptyDayCells_HaveZeroValues()
    {
        var result = _service.Analyze([], weeks: 1);

        foreach (var day in result.Days)
        {
            Assert.Equal(0, day.AuditCount);
            Assert.Equal(0, day.AvgScore);
            Assert.Equal(0, day.TotalFindings);
            Assert.Equal(0, day.CriticalCount);
            Assert.Equal(0, day.BestScore);
        }
    }

    [Fact]
    public void Analyze_DefaultWeeks_Is26()
    {
        var result = _service.Analyze([]);

        Assert.Equal(26, result.Weeks);
        Assert.Equal(182, result.Days.Count);
    }

    [Fact]
    public void Analyze_MultipleRunsDifferentDays_TracksActiveDays()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 95),
            MakeRun(now.AddDays(-3), 85),
            MakeRun(now.AddDays(-7), 75),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(3, result.TotalAudits);
        Assert.Equal(3, result.ActiveDays);
        Assert.Equal(1, result.MaxAuditsInDay);
    }

    [Fact]
    public void Analyze_ScoreExtremes_TrackedCorrectly()
    {
        var now = DateTimeOffset.Now;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, 100),
            MakeRun(now.AddDays(-1), 0),
        };

        var result = _service.Analyze(runs, weeks: 4);

        Assert.Equal(100, result.BestScore);
        Assert.Equal(0, result.WorstScore);
    }
}
