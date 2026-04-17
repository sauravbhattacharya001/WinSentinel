namespace WinSentinel.Tests;

using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

public class NoiseAnalyzerTests
{
    private readonly NoiseAnalyzer _sut = new();

    #region Helper factories

    private static AuditRunRecord MakeRun(
        DateTimeOffset timestamp,
        params (string title, string module, string severity)[] findings)
    {
        var run = new AuditRunRecord
        {
            Timestamp = timestamp,
            Findings = findings.Select(f => new FindingRecord
            {
                Title = f.title,
                ModuleName = f.module,
                Severity = f.severity
            }).ToList(),
            ModuleScores = findings
                .Select(f => f.module)
                .Distinct()
                .Select(m => new ModuleScoreRecord { ModuleName = m, Category = $"Cat-{m}" })
                .ToList()
        };
        return run;
    }

    private static DateTimeOffset Day(int offset) =>
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddDays(offset);

    #endregion

    // ───── Empty input ─────

    [Fact]
    public void Analyze_EmptyRuns_ReturnsEmptyResult()
    {
        var result = _sut.Analyze([]);

        Assert.Equal(0, result.RunsAnalyzed);
        Assert.Equal(0, result.TotalFindingOccurrences);
        Assert.Empty(result.TopNoisyFindings);
        Assert.Empty(result.TopNoisyModules);
    }

    // ───── Single run ─────

    [Fact]
    public void Analyze_SingleRun_CalculatesBasicStats()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0),
                ("Weak password", "Auth", "Warning"),
                ("Open port 22", "Network", "Info"))
        };

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.RunsAnalyzed);
        Assert.Equal(0, result.DaysSpan); // single run = 0 days span
        Assert.Equal(2, result.TotalFindingOccurrences);
        Assert.Equal(2, result.UniqueFindingTitles);
    }

    [Fact]
    public void Analyze_SingleRun_NoPerennialFindings()
    {
        // Perennial requires totalRuns >= 2
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Always here", "Auth", "Info"))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal(0, result.Stats.PerennialFindings);
    }

    // ───── Perennial detection ─────

    [Fact]
    public void Analyze_FindingInEveryRun_MarkedPerennial()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Stale cert", "TLS", "Warning")),
            MakeRun(Day(1), ("Stale cert", "TLS", "Warning")),
            MakeRun(Day(2), ("Stale cert", "TLS", "Warning"))
        };

        var result = _sut.Analyze(runs);
        var finding = Assert.Single(result.TopNoisyFindings);
        Assert.True(finding.IsPerennial);
        Assert.Equal(100.0, finding.OccurrenceRate);
        Assert.Equal(3, finding.Occurrences);
    }

    [Fact]
    public void Analyze_FindingMissingFromOneRun_NotPerennial()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Intermittent", "Net", "Warning")),
            MakeRun(Day(1)), // no findings
            MakeRun(Day(2), ("Intermittent", "Net", "Warning"))
        };

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Intermittent");
        Assert.False(finding.IsPerennial);
        Assert.Equal(66.7, finding.OccurrenceRate);
    }

    // ───── Noise level ratings ─────

    [Fact]
    public void Analyze_NoPerennialLowFreq_NoiseLevelLow()
    {
        // 3 runs, finding appears in 1 run = 33% rate, no perennial
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Rare issue", "Misc", "Info")),
            MakeRun(Day(1)),
            MakeRun(Day(2))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal("Low", result.Stats.NoiseLevelRating);
    }

    [Fact]
    public void Analyze_ManyPerennials_NoiseLevelExcessive()
    {
        // 2 runs with 10+ perennial findings = excessive
        var findings = Enumerable.Range(1, 10)
            .Select(i => ($"Perennial-{i}", $"Mod{i}", "Warning"))
            .ToArray();

        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), findings),
            MakeRun(Day(1), findings)
        };

        var result = _sut.Analyze(runs);
        Assert.Equal("Excessive", result.Stats.NoiseLevelRating);
    }

    // ───── SuggestedAction logic ─────

    [Fact]
    public void Analyze_PerennialInfo_SuggestsSuppression()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Noise", "Mod", "Info")),
            MakeRun(Day(1), ("Noise", "Mod", "Info"))
        };

        var result = _sut.Analyze(runs);
        var finding = Assert.Single(result.TopNoisyFindings);
        Assert.Contains("Suppress", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_PerennialWarning_SuggestsInvestigation()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("Persistent issue", "Auth", "Warning")),
            MakeRun(Day(1), ("Persistent issue", "Auth", "Warning"))
        };

        var result = _sut.Analyze(runs);
        var finding = Assert.Single(result.TopNoisyFindings);
        Assert.Contains("root cause", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_HighRateInfo_SuggestsConsiderSuppressing()
    {
        // Appears in 9/10 runs (90%) but not all = not perennial, but high freq info
        var runs = Enumerable.Range(0, 10)
            .Select(i => i < 9
                ? MakeRun(Day(i), ("Frequent info", "Misc", "Info"))
                : MakeRun(Day(i)))
            .ToList();

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Frequent info");
        Assert.Contains("Consider suppressing", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_HighRateWarning_SuggestsPrioritizeFix()
    {
        var runs = Enumerable.Range(0, 10)
            .Select(i => i < 9
                ? MakeRun(Day(i), ("Frequent warn", "Auth", "Warning"))
                : MakeRun(Day(i)))
            .ToList();

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Frequent warn");
        Assert.Contains("Prioritize fix", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_MediumRate_SuggestsIntermittent()
    {
        // 60% rate
        var runs = Enumerable.Range(0, 10)
            .Select(i => i < 6
                ? MakeRun(Day(i), ("Mid issue", "Net", "Warning"))
                : MakeRun(Day(i)))
            .ToList();

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Mid issue");
        Assert.Contains("Intermittent", finding.SuggestedAction);
    }

    [Fact]
    public void Analyze_LowRate_SuggestsSporadic()
    {
        // 10% rate
        var runs = Enumerable.Range(0, 10)
            .Select(i => i == 0
                ? MakeRun(Day(i), ("Rare thing", "Misc", "Info"))
                : MakeRun(Day(i)))
            .ToList();

        var result = _sut.Analyze(runs);
        var finding = result.TopNoisyFindings.First(f => f.Title == "Rare thing");
        Assert.Contains("Sporadic", finding.SuggestedAction);
    }

    // ───── Module-level noise ─────

    [Fact]
    public void Analyze_ModuleNoiseShare_SumsTo100()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0),
                ("F1", "Auth", "Warning"),
                ("F2", "Auth", "Info"),
                ("F3", "Network", "Warning")),
            MakeRun(Day(1),
                ("F1", "Auth", "Warning"),
                ("F4", "Network", "Info"))
        };

        var result = _sut.Analyze(runs);
        var totalShare = result.TopNoisyModules.Sum(m => m.NoiseShare);
        Assert.Equal(100.0, totalShare);
    }

    [Fact]
    public void Analyze_ModuleWithMostFindings_RankedFirst()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0),
                ("A", "BigMod", "Warning"),
                ("B", "BigMod", "Info"),
                ("C", "BigMod", "Info"),
                ("D", "SmallMod", "Warning"))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal("BigMod", result.TopNoisyModules.First().ModuleName);
        Assert.Equal(3, result.TopNoisyModules.First().TotalFindings);
    }

    // ───── Top-N limiting ─────

    [Fact]
    public void Analyze_TopParameter_LimitsResults()
    {
        var findings = Enumerable.Range(1, 20)
            .Select(i => ($"Finding-{i}", "Mod", "Info"))
            .ToArray();

        var runs = new List<AuditRunRecord> { MakeRun(Day(0), findings) };

        var result = _sut.Analyze(runs, top: 5);
        Assert.Equal(5, result.TopNoisyFindings.Count);
    }

    // ───── DaysSpan ─────

    [Fact]
    public void Analyze_MultipleRuns_CalculatesDaysSpan()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("F", "M", "Info")),
            MakeRun(Day(10), ("F", "M", "Info"))
        };

        var result = _sut.Analyze(runs);
        Assert.Equal(10, result.DaysSpan);
    }

    // ───── Stats aggregation ─────

    [Fact]
    public void Analyze_MixedFrequencies_CorrectStatsBuckets()
    {
        // 5 runs: 
        // "Always" in all 5 (perennial, 100%)
        // "Often" in 5/5 (perennial, 100%) 
        // "Sometimes" in 3/5 (60%)
        // "Rare" in 1/5 (20% - but <20 is strict <, so 20% is NOT low freq)
        // Actually <20% means rate < 20, so 1/5 = 20% is not <20
        // Let's use 10 runs for cleaner math
        var runs = Enumerable.Range(0, 10).Select(i =>
        {
            var findings = new List<(string, string, string)>();
            findings.Add(("Always", "A", "Warning")); // 10/10 = perennial
            if (i < 9) findings.Add(("Often", "B", "Info")); // 9/10 = 90% high freq
            if (i < 5) findings.Add(("Sometimes", "C", "Warning")); // 5/10 = 50%
            if (i == 0) findings.Add(("Rare", "D", "Info")); // 1/10 = 10% low freq
            return MakeRun(Day(i), findings.ToArray());
        }).ToList();

        var result = _sut.Analyze(runs);

        Assert.Equal(1, result.Stats.PerennialFindings); // only "Always" (perennial = in ALL runs and >=2)
        // Wait: "Often" is in 9/10, not all, so not perennial. Only "Always" is perennial.
        Assert.Equal(10, result.RunsAnalyzed);
        Assert.True(result.Stats.HighFrequencyFindings >= 2); // "Always" (100%) and "Often" (90%)
        Assert.True(result.Stats.LowFrequencyFindings >= 1); // "Rare" (10%)
    }

    // ───── Average findings per scan ─────

    [Fact]
    public void Analyze_AvgFindingsPerScan_Correct()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("A", "M", "Info"), ("B", "M", "Info")), // 2 findings
            MakeRun(Day(1), ("A", "M", "Info")), // 1 finding
            MakeRun(Day(2)) // 0 findings
        };

        var result = _sut.Analyze(runs);
        Assert.Equal(1.0, result.Stats.AvgFindingsPerScan); // 3 total / 3 runs
    }

    // ───── Suppressible estimation ─────

    [Fact]
    public void Analyze_PerennialAndHighFreqInfo_CountedAsSuppressible()
    {
        var runs = Enumerable.Range(0, 5).Select(i =>
            MakeRun(Day(i),
                ("Perennial info", "M", "Info"),     // perennial → suppressible
                ("Perennial warn", "M", "Warning"))  // perennial but not info → still suppressible (perennial)
        ).ToList();

        var result = _sut.Analyze(runs);
        // Both are perennial, so both count as suppressible
        Assert.Equal(2, result.Stats.EstimatedSuppressibleFindings);
    }

    // ───── Duplicate finding titles across modules ─────

    [Fact]
    public void Analyze_SameTitleDifferentModules_GroupedByTitle()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0),
                ("Outdated config", "ModA", "Warning"),
                ("Outdated config", "ModB", "Warning"))
        };

        var result = _sut.Analyze(runs);
        // Grouped by title, so single entry with 2 occurrences
        var finding = Assert.Single(result.TopNoisyFindings);
        Assert.Equal("Outdated config", finding.Title);
        Assert.Equal(2, finding.Occurrences);
    }

    // ───── Module category propagation ─────

    [Fact]
    public void Analyze_ModuleCategory_PropagatedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0), ("F1", "AuthModule", "Warning"))
        };

        var result = _sut.Analyze(runs);
        var module = Assert.Single(result.TopNoisyModules);
        Assert.Equal("Cat-AuthModule", module.Category);
    }

    // ───── UniqueFindingTitles per module ─────

    [Fact]
    public void Analyze_ModuleUniqueTitles_CountsDistinct()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(Day(0),
                ("Issue A", "Mod", "Warning"),
                ("Issue A", "Mod", "Warning"), // duplicate title
                ("Issue B", "Mod", "Info"))
        };

        var result = _sut.Analyze(runs);
        var module = Assert.Single(result.TopNoisyModules);
        Assert.Equal(2, module.UniqueFindingTitles);
        Assert.Equal(3, module.TotalFindings);
    }
}
