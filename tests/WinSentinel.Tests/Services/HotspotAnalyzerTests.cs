using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class HotspotAnalyzerTests
{
    private readonly HotspotAnalyzer _sut = new();

    private static AuditRunRecord MakeRun(DateTimeOffset ts, params (string module, string category, int findings, int critical, int warning)[] modules)
    {
        var run = new AuditRunRecord { Timestamp = ts, ModuleScores = [], Findings = [] };
        foreach (var (mod, cat, fc, cc, wc) in modules)
        {
            run.ModuleScores.Add(new ModuleScoreRecord
            {
                ModuleName = mod,
                Category = cat,
                FindingCount = fc,
                CriticalCount = cc,
                WarningCount = wc
            });
            // Also add FindingRecords so noise tests can use the same helper
            for (int i = 0; i < cc; i++)
                run.Findings.Add(new FindingRecord { ModuleName = mod, Title = $"{mod}-Critical-{i}", Severity = "Critical" });
            for (int i = 0; i < wc; i++)
                run.Findings.Add(new FindingRecord { ModuleName = mod, Title = $"{mod}-Warning-{i}", Severity = "Warning" });
            for (int i = 0; i < Math.Max(0, fc - cc - wc); i++)
                run.Findings.Add(new FindingRecord { ModuleName = mod, Title = $"{mod}-Info-{i}", Severity = "Info" });
        }
        return run;
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnsNoneHeatLevel()
    {
        var result = _sut.Analyze([]);
        Assert.Equal("None", result.OverallHeatLevel);
        Assert.Empty(result.CategoryHotspots);
        Assert.Empty(result.ModuleHotspots);
        Assert.Equal(0, result.RunsAnalyzed);
    }

    [Fact]
    public void Analyze_SingleRun_ComputesHotspotsCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, ("Firewall", "Network", 5, 2, 2))
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.RunsAnalyzed);
        Assert.Single(result.CategoryHotspots);
        Assert.Single(result.ModuleHotspots);
        Assert.Equal("Network", result.HottestCategory);
        Assert.Equal("Firewall", result.HottestModule);

        // With 1 run, appearance rate = 100%, so heat = severity * (0.5 + 0.5*1) = severity
        var moduleHot = result.ModuleHotspots[0];
        Assert.Equal(2, moduleHot.CriticalFindings);
        Assert.Equal(2, moduleHot.WarningFindings);
        Assert.Equal(1, moduleHot.InfoFindings); // 5 - 2 - 2
        Assert.Equal(100.0, moduleHot.AppearanceRate);
        Assert.True(moduleHot.HeatScore > 0);
    }

    [Fact]
    public void Analyze_MaxRunsLimitsSubset()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("ModA", "CatA", 3, 1, 1)),
            MakeRun(now.AddHours(-1), ("ModA", "CatA", 2, 0, 1)),
            MakeRun(now.AddHours(-2), ("ModB", "CatB", 10, 5, 5)),
        };

        var result = _sut.Analyze(runs, maxRuns: 2);

        Assert.Equal(2, result.RunsAnalyzed);
        // Only first 2 runs should be analyzed - ModB shouldn't appear
        Assert.DoesNotContain(result.ModuleHotspots, h => h.Name == "ModB");
    }

    [Fact]
    public void Analyze_MultipleRuns_ComputesTrend()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("Firewall", "Network", 10, 3, 5)),          // recent: more findings
            MakeRun(now.AddHours(-1), ("Firewall", "Network", 3, 1, 1)), // previous: fewer
        };

        var result = _sut.Analyze(runs);

        var moduleHot = result.ModuleHotspots.First(h => h.Name == "Firewall");
        Assert.Equal("↑ Worsening", moduleHot.Trend);

        var catHot = result.CategoryHotspots.First(h => h.Name == "Network");
        Assert.Equal("↑ Worsening", catHot.Trend);
    }

    [Fact]
    public void Analyze_ImprovingTrend_Detected()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("Firewall", "Network", 1, 0, 1)),           // recent: fewer
            MakeRun(now.AddHours(-1), ("Firewall", "Network", 8, 3, 3)), // previous: more
        };

        var result = _sut.Analyze(runs);
        var moduleHot = result.ModuleHotspots.First(h => h.Name == "Firewall");
        Assert.Equal("↓ Improving", moduleHot.Trend);
    }

    [Fact]
    public void Analyze_StableTrend_Detected()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("Firewall", "Network", 5, 2, 2)),
            MakeRun(now.AddHours(-1), ("Firewall", "Network", 5, 2, 2)),
        };

        var result = _sut.Analyze(runs);
        var moduleHot = result.ModuleHotspots.First(h => h.Name == "Firewall");
        Assert.Equal("→ Stable", moduleHot.Trend);
    }

    [Fact]
    public void Analyze_HeatLevelClassification()
    {
        // Critical heat: score >= 50. Let's make a module with lots of critical findings
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, ("BigBad", "Danger", 20, 15, 5))
        };

        var result = _sut.Analyze(runs);
        var hot = result.ModuleHotspots[0];

        // 15*4 + 5*2 + 0*0.5 = 70, *1.0 = 70 -> Critical
        Assert.Equal("🔴 Critical", hot.HeatLevel);
    }

    [Fact]
    public void Analyze_ZeroFindingsModule_ExcludedFromHotspots()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow,
                ("Clean", "Good", 0, 0, 0),
                ("Dirty", "Bad", 5, 2, 2))
        };

        var result = _sut.Analyze(runs);
        Assert.DoesNotContain(result.ModuleHotspots, h => h.Name == "Clean");
        Assert.Single(result.ModuleHotspots);
    }

    [Fact]
    public void Analyze_MultipleCategoriesRankedByHeatScore()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow,
                ("ModA", "Low", 2, 0, 0),
                ("ModB", "High", 10, 5, 3))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal(2, result.CategoryHotspots.Count);
        Assert.Equal("High", result.CategoryHotspots[0].Name);
        Assert.Equal("Low", result.CategoryHotspots[1].Name);
    }

    [Fact]
    public void Analyze_DaysSpan_MinimumIsOne()
    {
        // Single run => daysSpan should be at least 1
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, ("M", "C", 1, 0, 1))
        };
        var result = _sut.Analyze(runs);
        Assert.True(result.DaysSpan >= 1);
    }

    [Fact]
    public void Analyze_AppearanceRate_CorrectAcrossMultipleRuns()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("ModA", "Cat", 3, 1, 1)),
            MakeRun(now.AddDays(-1), ("ModA", "Cat", 0, 0, 0)),  // no findings
            MakeRun(now.AddDays(-2), ("ModA", "Cat", 2, 0, 1)),
        };

        var result = _sut.Analyze(runs);
        var hot = result.ModuleHotspots.First(h => h.Name == "ModA");
        // Appeared in 2 of 3 runs = 66.7%
        Assert.Equal(66.7, hot.AppearanceRate);
        Assert.Equal(2, hot.Appearances);
    }

    [Fact]
    public void Analyze_UncategorizedModule_HandledGracefully()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, ("Orphan", "", 3, 1, 1))
        };

        var result = _sut.Analyze(runs);
        Assert.Contains(result.CategoryHotspots, h => h.Name == "Uncategorized");
    }
}
