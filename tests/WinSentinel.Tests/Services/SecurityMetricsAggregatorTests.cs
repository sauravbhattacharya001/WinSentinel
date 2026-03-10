using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityMetricsAggregatorTests
{
    private readonly SecurityMetricsAggregator _aggregator = new();

    private static AuditRunRecord MakeRun(
        long id, DateTimeOffset timestamp, int score,
        params (string module, string category, string title, string severity)[] findings)
    {
        var run = new AuditRunRecord
        {
            Id = id, Timestamp = timestamp, OverallScore = score,
            Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : "D",
            TotalFindings = findings.Length,
            CriticalCount = findings.Count(f => f.severity == "Critical"),
            WarningCount = findings.Count(f => f.severity == "Warning"),
            InfoCount = findings.Count(f => f.severity == "Info"),
            PassCount = 0, IsScheduled = false
        };

        foreach (var group in findings.GroupBy(f => f.module))
        {
            run.ModuleScores.Add(new ModuleScoreRecord
            {
                ModuleName = group.Key, Category = group.First().category,
                Score = score, FindingCount = group.Count(),
                CriticalCount = group.Count(f => f.severity == "Critical"),
                WarningCount = group.Count(f => f.severity == "Warning")
            });
        }

        foreach (var (module, _, title, severity) in findings)
            run.Findings.Add(new FindingRecord
            {
                ModuleName = module, Title = title,
                Severity = severity, Description = $"Test: {title}"
            });

        return run;
    }

    private static DateTimeOffset T(int dayOffset) =>
        new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero).AddDays(dayOffset);

    [Fact]
    public void Analyze_NullRuns_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _aggregator.Analyze(null!));
    }

    [Fact]
    public void Analyze_EmptyRuns_EmptyReport()
    {
        var r = _aggregator.Analyze([]);
        Assert.Equal(0, r.RunsAnalyzed);
        Assert.Equal("N/A", r.HealthGrade);
        Assert.Contains("No audit runs", r.Summary);
    }

    [Fact]
    public void Analyze_SingleRun_BasicMetrics()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 85,
                ("Firewall", "Network", "Open port 3389", "Warning"),
                ("Updates", "System", "Missing KB12345", "Critical"))
        });

        Assert.Equal(1, r.RunsAnalyzed);
        Assert.Equal(2, r.CurrentlyOpen);
        Assert.Equal(2, r.TotalUnique);
        Assert.Equal(0, r.TotalResolved);
        Assert.Equal(1, r.CurrentSeverity.Critical);
        Assert.Equal(1, r.CurrentSeverity.Warning);
    }

    [Fact]
    public void Analyze_FindingResolved_CalculatesMttr()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 90)
        });

        Assert.Equal(1, r.TotalResolved);
        Assert.Equal(48, r.MttrHours);
    }

    [Fact]
    public void Analyze_MultipleFindingsResolved_AveragesMttr()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 60, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical")),
            MakeRun(2, T(1), 70, ("B", "Cat", "F2", "Critical")),
            MakeRun(3, T(3), 95)
        });

        Assert.Equal(2, r.TotalResolved);
        Assert.True(r.MttrHours > 0);
    }

    [Fact]
    public void Analyze_Mttd_AverageGaps()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 85), MakeRun(2, T(1), 85), MakeRun(3, T(3), 85)
        });

        Assert.Equal(36, r.MttdHours);
    }

    [Fact]
    public void Analyze_FindingVelocity()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(5), 60, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical")),
            MakeRun(3, T(10), 50, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical"), ("C", "Cat", "F3", "Critical"))
        });

        Assert.Equal(0.3, r.FindingVelocityPerDay);
    }

    [Fact]
    public void Analyze_RecurringFinding_Tracked()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 90),
            MakeRun(3, T(4), 70, ("A", "Cat", "F1", "Warning"))
        });

        Assert.Equal(1, r.TotalRecurrent);
        Assert.True(r.RecurrenceRatePercent > 0);
        Assert.Single(r.TopRecurring);
        Assert.Equal("F1", r.TopRecurring[0].Title);
    }

    [Fact]
    public void Analyze_NoRecurrence_ZeroRate()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 90)
        });

        Assert.Equal(0, r.TotalRecurrent);
        Assert.Empty(r.TopRecurring);
    }

    [Fact]
    public void Analyze_AllResolved_EfficiencyOne()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 95)
        });

        Assert.Equal(1.0, r.ResolutionEfficiency);
    }

    [Fact]
    public void Analyze_NoneResolved_EfficiencyZero()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 60, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical"))
        });

        Assert.Equal(0, r.ResolutionEfficiency);
    }

    [Fact]
    public void Analyze_MixedSeverity_CorrectBreakdown()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 50,
                ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical"),
                ("C", "Cat", "F3", "Info"), ("D", "Cat", "F4", "Critical"))
        });

        Assert.Equal(2, r.CurrentSeverity.Critical);
        Assert.Equal(1, r.CurrentSeverity.Warning);
        Assert.Equal(1, r.CurrentSeverity.Info);
        Assert.Equal(4, r.CurrentSeverity.Total);
    }

    [Fact]
    public void Analyze_PassFindings_Excluded()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 85, ("A", "Cat", "Pass check", "Pass"), ("B", "Cat", "F1", "Warning"))
        });

        Assert.Equal(1, r.TotalUnique);
        Assert.Equal(1, r.CurrentlyOpen);
    }

    [Fact]
    public void Analyze_SeverityTrend_Windows()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(10), 60, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical")),
            MakeRun(3, T(20), 80, ("B", "Cat", "F2", "Critical")),
            MakeRun(4, T(30), 95)
        }, windowCount: 3);

        Assert.True(r.SeverityTrend.Count > 0);
        Assert.True(r.SeverityTrend.Count <= 3);
    }

    [Fact]
    public void Analyze_SingleRun_NoSeverityTrend()
    {
        var r = _aggregator.Analyze(new[] { MakeRun(1, T(0), 85, ("A", "Cat", "F1", "Warning")) });
        Assert.Empty(r.SeverityTrend);
    }

    [Fact]
    public void Analyze_ZeroWindowCount_EmptyTrend()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(5), 90)
        }, windowCount: 0);

        Assert.Empty(r.SeverityTrend);
    }

    [Fact]
    public void Analyze_ModuleHealth_Computed()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 60,
                ("Firewall", "Network", "Open port", "Warning"),
                ("Firewall", "Network", "No outbound", "Info"),
                ("Updates", "System", "Missing KB", "Critical")),
            MakeRun(2, T(3), 70,
                ("Firewall", "Network", "Open port", "Warning"),
                ("Updates", "System", "Missing KB", "Critical")),
            MakeRun(3, T(6), 85, ("Firewall", "Network", "Open port", "Warning"))
        });

        Assert.Equal(2, r.Modules.Count);
        var fw = r.Modules.First(m => m.ModuleName == "Firewall");
        Assert.Equal(1, fw.CurrentFindings);
        Assert.Equal(2, fw.PeakFindings);
        var upd = r.Modules.First(m => m.ModuleName == "Updates");
        Assert.Equal(0, upd.CurrentFindings);
        Assert.Equal(1, upd.TotalResolved);
    }

    [Fact]
    public void Analyze_ModuleCategory_Populated()
    {
        var r = _aggregator.Analyze(new[] { MakeRun(1, T(0), 70, ("Firewall", "Network", "F1", "Warning")) });
        Assert.Equal("Network", r.Modules[0].Category);
    }

    [Fact]
    public void Analyze_CleanState_GradeA()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 95, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(1), 100)
        });

        Assert.Equal("A", r.HealthGrade);
        Assert.True(r.HealthScore >= 90);
    }

    [Fact]
    public void Analyze_ManyCriticals_LowGrade()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 30,
                ("A", "Cat", "C1", "Critical"), ("B", "Cat", "C2", "Critical"),
                ("C", "Cat", "C3", "Critical"), ("D", "Cat", "C4", "Critical"),
                ("E", "Cat", "C5", "Critical"))
        });

        Assert.True(r.HealthScore < 70);
    }

    [Fact]
    public void Analyze_Summary_ContainsKPIs()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(5), 90)
        });

        Assert.Contains("MTTR", r.Summary);
        Assert.Contains("MTTD", r.Summary);
        Assert.Contains("Velocity", r.Summary);
        Assert.Contains("Recurrence", r.Summary);
    }

    [Fact]
    public void Analyze_LowEfficiency_Warning()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(5), 60,
                ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Warning"),
                ("C", "Cat", "F3", "Warning"), ("D", "Cat", "F4", "Critical"))
        });

        Assert.Contains("below 80%", r.Summary);
    }

    [Fact]
    public void Analyze_CriticalFinding_WarningInSummary()
    {
        var r = _aggregator.Analyze(new[] { MakeRun(1, T(0), 50, ("A", "Cat", "F1", "Critical")) });
        Assert.Contains("critical", r.Summary);
    }

    [Fact]
    public void Analyze_TopRecurringCount_Limits()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 50, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Warning"), ("C", "Cat", "F3", "Warning")),
            MakeRun(2, T(1), 90),
            MakeRun(3, T(2), 50, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Warning"), ("C", "Cat", "F3", "Warning"))
        }, topRecurringCount: 1);

        Assert.True(r.TopRecurring.Count <= 1);
    }

    [Fact]
    public void Analyze_UnorderedRuns_StillCorrect()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(3, T(4), 90),
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 85, ("A", "Cat", "F1", "Warning"))
        });

        Assert.Equal(3, r.RunsAnalyzed);
        Assert.Equal(0, r.CurrentlyOpen);
        Assert.Equal(1, r.TotalResolved);
    }

    [Fact]
    public void Analyze_CorrectPeriod()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 85), MakeRun(2, T(10), 85), MakeRun(3, T(30), 85)
        });

        Assert.Equal(30, r.AnalysisPeriod.TotalDays);
        Assert.Equal(T(0), r.FirstRun);
        Assert.Equal(T(30), r.LastRun);
    }

    [Fact]
    public void Analyze_ResolutionVelocity()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 60, ("A", "Cat", "F1", "Warning"), ("B", "Cat", "F2", "Critical")),
            MakeRun(2, T(10), 90)
        });

        Assert.Equal(0.2, r.ResolutionVelocityPerDay);
    }

    [Fact]
    public void Analyze_CaseInsensitiveMatching()
    {
        var run1 = MakeRun(1, T(0), 70);
        run1.Findings.Add(new FindingRecord { ModuleName = "Firewall", Title = "Open Port", Severity = "Warning", Description = "t" });
        var run2 = MakeRun(2, T(2), 70);
        run2.Findings.Add(new FindingRecord { ModuleName = "firewall", Title = "open port", Severity = "Warning", Description = "t" });

        var r = _aggregator.Analyze(new[] { run1, run2 });
        Assert.Equal(1, r.TotalUnique);
    }

    [Fact]
    public void Analyze_SameDayRuns_NoDivisionByZero()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(0).AddHours(1), 90)
        });

        Assert.False(double.IsNaN(r.FindingVelocityPerDay));
        Assert.True(r.FindingVelocityPerDay >= 0);
    }

    [Fact]
    public void Analyze_MultipleRecurrences_Counted()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(1), 90),
            MakeRun(3, T(2), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(4, T(3), 90),
            MakeRun(5, T(4), 70, ("A", "Cat", "F1", "Warning"))
        });

        var recurring = r.TopRecurring.First(x => x.Title == "F1");
        Assert.Equal(2, recurring.Recurrences);
        Assert.Equal(3, recurring.Occurrences);
    }

    [Fact]
    public void Analyze_HighRecurrence_WarningInSummary()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(1), 90),
            MakeRun(3, T(2), 70, ("A", "Cat", "F1", "Warning"))
        });

        Assert.True(r.RecurrenceRatePercent > 20);
        Assert.Contains("recurrence", r.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_NoFindings_HighHealthScore()
    {
        var r = _aggregator.Analyze(new[] { MakeRun(1, T(0), 100), MakeRun(2, T(5), 100) });

        Assert.Equal(0, r.CurrentlyOpen);
        Assert.True(r.HealthScore >= 90);
        Assert.Equal("A", r.HealthGrade);
    }

    [Fact]
    public void Analyze_ModuleHealth_OrderedByCurrentFindings()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 50,
                ("A", "Cat", "F1", "Warning"),
                ("B", "Cat", "F2", "Warning"), ("B", "Cat", "F3", "Warning"), ("B", "Cat", "F4", "Critical"))
        });

        Assert.Equal("B", r.Modules[0].ModuleName);
        Assert.Equal("A", r.Modules[1].ModuleName);
    }

    [Fact]
    public void Analyze_SeverityTrendPoint_HasOverallScore()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(10), 85, ("A", "Cat", "F1", "Warning"))
        }, windowCount: 2);

        Assert.True(r.SeverityTrend.Count > 0);
        Assert.True(r.SeverityTrend.All(p => p.OverallScore > 0));
    }

    [Fact]
    public void Analyze_RecurringFinding_AvgDaysBeforeRecurrence()
    {
        var r = _aggregator.Analyze(new[]
        {
            MakeRun(1, T(0), 70, ("A", "Cat", "F1", "Warning")),
            MakeRun(2, T(2), 90),
            MakeRun(3, T(6), 70, ("A", "Cat", "F1", "Warning"))
        });

        Assert.True(r.TopRecurring.First().AvgDaysBeforeRecurrence > 0);
    }
}
