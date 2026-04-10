using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class NoiseAnalyzerTests
{
    private readonly NoiseAnalyzer _sut = new();

    private static AuditRunRecord MakeRun(DateTimeOffset ts, params (string module, string category, string title, string severity)[] findings)
    {
        var run = new AuditRunRecord
        {
            Timestamp = ts,
            ModuleScores = [],
            Findings = findings.Select(f => new FindingRecord
            {
                ModuleName = f.module,
                Title = f.title,
                Severity = f.severity,
                Description = ""
            }).ToList()
        };

        // Build module scores from findings
        var groups = findings.GroupBy(f => f.module);
        foreach (var g in groups)
        {
            var cat = g.First().category;
            run.ModuleScores.Add(new ModuleScoreRecord
            {
                ModuleName = g.Key,
                Category = cat,
                FindingCount = g.Count(),
                CriticalCount = g.Count(f => f.severity == "Critical"),
                WarningCount = g.Count(f => f.severity == "Warning")
            });
        }

        return run;
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnsEmptyResult()
    {
        var result = _sut.Analyze([]);
        Assert.Equal(0, result.RunsAnalyzed);
        Assert.Empty(result.TopNoisyFindings);
        Assert.Empty(result.TopNoisyModules);
    }

    [Fact]
    public void Analyze_SingleRun_IdentifiesFindings()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow,
                ("Firewall", "Network", "Open Port 22", "Warning"),
                ("Firewall", "Network", "Open Port 80", "Info"))
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.RunsAnalyzed);
        Assert.Equal(2, result.TotalFindingOccurrences);
        Assert.Equal(2, result.UniqueFindingTitles);
        Assert.Equal(2, result.TopNoisyFindings.Count);
    }

    [Fact]
    public void Analyze_PerennialFinding_Detected()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("FW", "Net", "Always There", "Info")),
            MakeRun(now.AddHours(-1), ("FW", "Net", "Always There", "Info")),
            MakeRun(now.AddHours(-2), ("FW", "Net", "Always There", "Info")),
        };

        var result = _sut.Analyze(runs);

        var noisy = result.TopNoisyFindings.First(f => f.Title == "Always There");
        Assert.True(noisy.IsPerennial);
        Assert.Equal(100.0, noisy.OccurrenceRate);
        Assert.Equal(3, noisy.Occurrences);
    }

    [Fact]
    public void Analyze_SuggestedAction_PerennialInfo_SuggestsSuppression()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("FW", "Net", "Always Info", "Info")),
            MakeRun(now.AddHours(-1), ("FW", "Net", "Always Info", "Info")),
        };

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Always Info");
        Assert.Contains("Suppress", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_SuggestedAction_PerennialCritical_SuggestsInvestigation()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("FW", "Net", "Critical Bug", "Critical")),
            MakeRun(now.AddHours(-1), ("FW", "Net", "Critical Bug", "Critical")),
        };

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Critical Bug");
        Assert.Contains("root cause", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_SuggestedAction_SporadicFinding()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("FW", "Net", "Rare Issue", "Warning")),
            MakeRun(now.AddHours(-1)),
            MakeRun(now.AddHours(-2)),
            MakeRun(now.AddHours(-3)),
        };

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Rare Issue");
        Assert.Contains("Sporadic", finding.SuggestedAction);
    }

    private static AuditRunRecord MakeRun(DateTimeOffset ts)
    {
        return new AuditRunRecord { Timestamp = ts, ModuleScores = [], Findings = [] };
    }

    [Fact]
    public void Analyze_ModuleNoise_RankedByTotalFindings()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now,
                ("BigModule", "Cat", "F1", "Warning"),
                ("BigModule", "Cat", "F2", "Warning"),
                ("BigModule", "Cat", "F3", "Info"),
                ("SmallModule", "Cat2", "F4", "Info"))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal("BigModule", result.TopNoisyModules[0].ModuleName);
        Assert.Equal(3, result.TopNoisyModules[0].TotalFindings);
    }

    [Fact]
    public void Analyze_NoiseShare_SumsToHundred()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow,
                ("A", "C1", "F1", "Info"),
                ("B", "C2", "F2", "Info"))
        };

        var result = _sut.Analyze(runs);
        var totalShare = result.TopNoisyModules.Sum(m => m.NoiseShare);
        Assert.Equal(100.0, totalShare);
    }

    [Fact]
    public void Analyze_NoiseLevelRating_Low_WhenClean()
    {
        var now = DateTimeOffset.UtcNow;
        // One sporadic finding across several runs => Low noise
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("M", "C", "Rare", "Info")),
            MakeRun(now.AddHours(-1)),
            MakeRun(now.AddHours(-2)),
            MakeRun(now.AddHours(-3)),
            MakeRun(now.AddHours(-4)),
        };

        var result = _sut.Analyze(runs);
        Assert.Equal("Low", result.Stats.NoiseLevelRating);
    }

    [Fact]
    public void Analyze_NoiseLevelRating_Excessive_WhenManyPerennials()
    {
        var now = DateTimeOffset.UtcNow;
        // Many findings in every single run
        var findings = Enumerable.Range(0, 20)
            .Select(i => ("Mod", "Cat", $"Finding-{i}", "Warning"))
            .ToArray();

        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, findings),
            MakeRun(now.AddHours(-1), findings),
        };

        var result = _sut.Analyze(runs);
        // With 20 perennials, should be Excessive
        Assert.Equal("Excessive", result.Stats.NoiseLevelRating);
    }

    [Fact]
    public void Analyze_TopParam_LimitsResults()
    {
        var findings = Enumerable.Range(0, 30)
            .Select(i => ("Mod", "Cat", $"Finding-{i}", "Info"))
            .ToArray();

        var runs = new List<AuditRunRecord>
        {
            MakeRun(DateTimeOffset.UtcNow, findings)
        };

        var result = _sut.Analyze(runs, top: 5);
        Assert.Equal(5, result.TopNoisyFindings.Count);
    }

    [Fact]
    public void Analyze_DaysSpan_CalculatedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now, ("M", "C", "F", "Info")),
            MakeRun(now.AddDays(-7), ("M", "C", "F", "Info")),
        };

        var result = _sut.Analyze(runs);
        Assert.Equal(7, result.DaysSpan);
    }

    [Fact]
    public void Analyze_EstimatedSuppressible_CountsPerennialAndHighFreqInfo()
    {
        var now = DateTimeOffset.UtcNow;
        var runs = new List<AuditRunRecord>
        {
            MakeRun(now,
                ("M", "C", "Perennial-Info", "Info"),
                ("M", "C", "Perennial-Crit", "Critical")),
            MakeRun(now.AddHours(-1),
                ("M", "C", "Perennial-Info", "Info"),
                ("M", "C", "Perennial-Crit", "Critical")),
        };

        var result = _sut.Analyze(runs);
        // Both are perennial: perennial count = 2
        // Suppressible = perennial OR (high-freq + info)
        // Perennial-Info is perennial => yes
        // Perennial-Crit is perennial => yes
        Assert.Equal(2, result.Stats.EstimatedSuppressibleFindings);
    }
}
