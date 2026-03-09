using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class AuditScheduleOptimizerTests
{
    private readonly AuditScheduleOptimizer _optimizer = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static AuditRunRecord MakeRun(
        long id,
        DateTimeOffset timestamp,
        params (string module, string category, int score, string[] findings)[] modules)
    {
        var run = new AuditRunRecord
        {
            Id = id,
            Timestamp = timestamp,
            OverallScore = modules.Length > 0 ? (int)modules.Average(m => m.score) : 100,
            Grade = "B",
            TotalFindings = modules.Sum(m => m.findings.Length),
            CriticalCount = 0,
            WarningCount = 0,
            InfoCount = 0,
            PassCount = 0,
            IsScheduled = false
        };

        foreach (var (module, category, score, findings) in modules)
        {
            run.ModuleScores.Add(new ModuleScoreRecord
            {
                ModuleName = module,
                Category = category,
                Score = score,
                FindingCount = findings.Length,
                CriticalCount = 0,
                WarningCount = 0
            });

            foreach (var title in findings)
            {
                run.Findings.Add(new FindingRecord
                {
                    ModuleName = module,
                    Title = title,
                    Severity = "Warning",
                    Description = $"Finding: {title}"
                });
            }
        }

        return run;
    }

    private static DateTimeOffset Day(int offset) =>
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddDays(offset);

    // ── Empty / insufficient data tests ──────────────────────────────

    [Fact]
    public void AnalyzeFromRuns_EmptyList_ReturnsZeroRuns()
    {
        var result = _optimizer.AnalyzeFromRuns([]);
        Assert.Equal(0, result.RunsAnalyzed);
        Assert.Contains("No audit history", result.Summary);
    }

    [Fact]
    public void AnalyzeFromRuns_SingleRun_ReturnsInsufficientData()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Firewall", "Network", 80, ["Open port 22"]))
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(1, result.RunsAnalyzed);
        Assert.Contains("Only 1", result.Summary);
    }

    // ── Stable module tests ─────────────────────────────────────────

    [Fact]
    public void StableModule_GetsMonthlyOrWeeklyCadence()
    {
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 10; i++)
        {
            runs.Add(MakeRun(i + 1, Day(i),
                ("Firewall", "Network", 80, ["Open port 22"])));
        }

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(10, result.RunsAnalyzed);
        Assert.Single(result.Modules);

        var fw = result.Modules[0];
        Assert.Equal("Firewall", fw.ModuleName);
        Assert.Equal(0, fw.ScoreChanges);
        Assert.Equal(0, fw.FindingChurns);
        Assert.True(fw.RecommendedCadence >= AuditScheduleOptimizer.ScanCadence.Weekly);
    }

    [Fact]
    public void StableModule_HasZeroVolatility()
    {
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 5; i++)
        {
            runs.Add(MakeRun(i + 1, Day(i),
                ("Encryption", "System", 100, Array.Empty<string>())));
        }

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.Equal(0, mod.VolatilityScore);
        Assert.Equal(AuditScheduleOptimizer.ScanCadence.Monthly, mod.RecommendedCadence);
    }

    // ── Volatile module tests ────────────────────────────────────────

    [Fact]
    public void VolatileModule_GetsEveryRunOrHourlyCadence()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Network", "Network", 80, ["Issue A"])),
            MakeRun(2, Day(1), ("Network", "Network", 60, ["Issue B", "Issue C"])),
            MakeRun(3, Day(2), ("Network", "Network", 40, ["Issue D"])),
            MakeRun(4, Day(3), ("Network", "Network", 70, ["Issue E", "Issue F"])),
            MakeRun(5, Day(4), ("Network", "Network", 50, ["Issue G"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.Equal("Network", mod.ModuleName);
        Assert.True(mod.ScoreChanges >= 4);
        Assert.True(mod.RecommendedCadence <= AuditScheduleOptimizer.ScanCadence.Hourly);
    }

    [Fact]
    public void HighFindingChurn_IncreasesVolatility()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Process", "System", 80, ["A", "B"])),
            MakeRun(2, Day(1), ("Process", "System", 80, ["C", "D"])),
            MakeRun(3, Day(2), ("Process", "System", 80, ["E", "F"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        // Score didn't change but findings churned completely
        Assert.Equal(0, mod.ScoreChanges);
        Assert.True(mod.FindingChurns >= 4);
        Assert.True(mod.VolatilityScore > 0);
    }

    // ── Multiple modules ─────────────────────────────────────────────

    [Fact]
    public void MultipleModules_SortedByVolatilityDescending()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Volatile", "Network", 80, ["A"])),
            MakeRun(2, Day(1),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Volatile", "Network", 50, ["B", "C"])),
            MakeRun(3, Day(2),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Volatile", "Network", 70, ["D"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(2, result.Modules.Count);
        Assert.Equal("Volatile", result.Modules[0].ModuleName);
        Assert.Equal("Stable", result.Modules[1].ModuleName);
        Assert.True(result.Modules[0].VolatilityScore > result.Modules[1].VolatilityScore);
    }

    [Fact]
    public void HighPriority_ContainsVolatileModules()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Hot", "Network", 80, ["A"])),
            MakeRun(2, Day(1),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Hot", "Network", 30, ["B", "C", "D", "E"])),
            MakeRun(3, Day(2),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Hot", "Network", 70, ["F"])),
            MakeRun(4, Day(3),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Hot", "Network", 20, ["G", "H", "I"])),
            MakeRun(5, Day(4),
                ("Stable", "System", 100, Array.Empty<string>()),
                ("Hot", "Network", 60, ["J"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.True(result.HighPriority.Any(m => m.ModuleName == "Hot"));
        Assert.True(result.LowPriority.Any(m => m.ModuleName == "Stable"));
    }

    // ── Score statistics ─────────────────────────────────────────────

    [Fact]
    public void ScoreRange_CalculatedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Test", "Cat", 40, ["A"])),
            MakeRun(2, Day(1), ("Test", "Cat", 90, Array.Empty<string>())),
            MakeRun(3, Day(2), ("Test", "Cat", 60, ["B"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.Equal(40, mod.MinScore);
        Assert.Equal(90, mod.MaxScore);
        Assert.Equal(50, mod.ScoreRange);
    }

    [Fact]
    public void AverageScore_CalculatedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Test", "Cat", 60, ["A"])),
            MakeRun(2, Day(1), ("Test", "Cat", 80, Array.Empty<string>())),
            MakeRun(3, Day(2), ("Test", "Cat", 100, Array.Empty<string>())),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.Equal(80, mod.AverageScore);
    }

    [Fact]
    public void ScoreStdDev_ZeroForConstantScores()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Test", "Cat", 75, ["A"])),
            MakeRun(2, Day(1), ("Test", "Cat", 75, ["A"])),
            MakeRun(3, Day(2), ("Test", "Cat", 75, ["A"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(0, result.Modules.Single().ScoreStdDev);
    }

    // ── Savings estimation ───────────────────────────────────────────

    [Fact]
    public void EstimatedSavings_PositiveWhenModulesCanBeSkipped()
    {
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 30; i++)
        {
            runs.Add(MakeRun(i + 1, Day(i),
                ("AlwaysStable", "System", 100, Array.Empty<string>())));
        }

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.True(result.EstimatedSavingsPercent > 0);
    }

    [Fact]
    public void EstimatedSavings_ZeroWhenAllModulesEveryRun()
    {
        // All modules change every run
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("X", "Cat", 90, ["A"])),
            MakeRun(2, Day(1), ("X", "Cat", 30, ["B", "C", "D"])),
            MakeRun(3, Day(2), ("X", "Cat", 80, ["E"])),
            MakeRun(4, Day(3), ("X", "Cat", 20, ["F", "G", "H"])),
            MakeRun(5, Day(4), ("X", "Cat", 70, ["I"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        // If cadence is EveryRun, savings should be 0
        if (result.Modules.All(m => m.RecommendedCadence == AuditScheduleOptimizer.ScanCadence.EveryRun))
            Assert.Equal(0, result.EstimatedSavingsPercent);
    }

    // ── Cadence classification ───────────────────────────────────────

    [Fact]
    public void MediumVolatility_GetsDailyCadence()
    {
        // 30% score change rate should map to Daily
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 10; i++)
        {
            int score = i % 3 == 0 ? 70 : 80; // changes ~33% of the time
            runs.Add(MakeRun(i + 1, Day(i),
                ("Medium", "Cat", score, score == 70 ? ["A"] : Array.Empty<string>())));
        }

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.True(mod.RecommendedCadence <= AuditScheduleOptimizer.ScanCadence.Daily);
    }

    // ── Summary and result properties ────────────────────────────────

    [Fact]
    public void Summary_ContainsModuleCount()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0),
                ("A", "Cat1", 80, ["X"]),
                ("B", "Cat2", 90, Array.Empty<string>())),
            MakeRun(2, Day(1),
                ("A", "Cat1", 60, ["Y"]),
                ("B", "Cat2", 90, Array.Empty<string>())),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Contains("2 modules", result.Summary);
    }

    [Fact]
    public void Summary_ContainsEstimatedSavings()
    {
        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 5; i++)
        {
            runs.Add(MakeRun(i + 1, Day(i),
                ("Stable", "System", 100, Array.Empty<string>())));
        }

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Contains("savings", result.Summary);
    }

    [Fact]
    public void AnalysisPeriod_CorrectlyComputed()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("A", "C", 80, ["X"])),
            MakeRun(2, Day(10), ("A", "C", 70, ["Y"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(10, result.AnalysisPeriod.TotalDays);
    }

    [Fact]
    public void AverageVolatility_CorrectlyComputed()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0),
                ("A", "C1", 100, Array.Empty<string>()),
                ("B", "C2", 80, ["X"])),
            MakeRun(2, Day(1),
                ("A", "C1", 100, Array.Empty<string>()),
                ("B", "C2", 50, ["Y", "Z"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        // A has 0 volatility, B has >0 volatility
        Assert.True(result.AverageVolatility >= 0);
        Assert.True(result.Modules[0].VolatilityScore >= result.Modules[1].VolatilityScore);
    }

    // ── Module appearances ───────────────────────────────────────────

    [Fact]
    public void ModuleAppearingInSubsetOfRuns_StillAnalyzed()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0),
                ("Always", "C", 80, ["A"]),
                ("Sometimes", "C", 90, ["B"])),
            MakeRun(2, Day(1),
                ("Always", "C", 80, ["A"])),
            MakeRun(3, Day(2),
                ("Always", "C", 80, ["A"]),
                ("Sometimes", "C", 70, ["C"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(2, result.Modules.Count);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void TwoRunsOnly_ProducesValidResult()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Test", "Cat", 80, ["A"])),
            MakeRun(2, Day(1), ("Test", "Cat", 60, ["B"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(2, result.RunsAnalyzed);
        Assert.Single(result.Modules);
        Assert.Equal(1, result.Modules[0].ScoreChanges);
    }

    [Fact]
    public void ManyModules_AllAnalyzed()
    {
        var modules = Enumerable.Range(1, 20)
            .Select(i => ($"Module{i}", "Cat", 80 + (i % 5), new[] { $"Finding{i}" }))
            .ToArray();

        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), modules),
            MakeRun(2, Day(1), modules),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        Assert.Equal(20, result.Modules.Count);
    }

    [Fact]
    public void FindingChurnRate_CorrectForCompleteTurnover()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Mod", "Cat", 80, ["A", "B"])),
            MakeRun(2, Day(1), ("Mod", "Cat", 80, ["C", "D"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        // 2 removed + 2 added = 4 churns in 1 transition
        Assert.Equal(4, mod.FindingChurns);
        Assert.Equal(4.0, mod.FindingChurnRate);
    }

    [Fact]
    public void ScoreChangeRate_CorrectForAlternating()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, Day(0), ("Mod", "Cat", 80, ["A"])),
            MakeRun(2, Day(1), ("Mod", "Cat", 60, ["B"])),
            MakeRun(3, Day(2), ("Mod", "Cat", 80, ["A"])),
            MakeRun(4, Day(3), ("Mod", "Cat", 60, ["B"])),
            MakeRun(5, Day(4), ("Mod", "Cat", 80, ["A"])),
        };

        var result = _optimizer.AnalyzeFromRuns(runs);
        var mod = result.Modules.Single();
        Assert.Equal(4, mod.ScoreChanges);
        Assert.Equal(1.0, mod.ScoreChangeRate);
    }

    // ── CLI parser tests ─────────────────────────────────────────────

    [Fact]
    public void CliParser_ParsesScheduleOptimize()
    {
        var options = WinSentinel.Cli.CliParser.Parse(["--schedule-optimize"]);
        Assert.Equal(WinSentinel.Cli.CliCommand.ScheduleOptimize, options.Command);
        Assert.Equal(90, options.ScheduleOptimizeDays); // default
    }

    [Fact]
    public void CliParser_ParsesOptDays()
    {
        var options = WinSentinel.Cli.CliParser.Parse(["--schedule-optimize", "--opt-days", "30"]);
        Assert.Equal(WinSentinel.Cli.CliCommand.ScheduleOptimize, options.Command);
        Assert.Equal(30, options.ScheduleOptimizeDays);
    }

    [Fact]
    public void CliParser_InvalidOptDays_ReturnsError()
    {
        var options = WinSentinel.Cli.CliParser.Parse(["--schedule-optimize", "--opt-days", "999"]);
        Assert.NotNull(options.Error);
        Assert.Contains("opt-days", options.Error);
    }

    [Fact]
    public void CliParser_MissingOptDaysValue_ReturnsError()
    {
        var options = WinSentinel.Cli.CliParser.Parse(["--schedule-optimize", "--opt-days"]);
        Assert.NotNull(options.Error);
    }

    [Fact]
    public void CliParser_ScheduleOptimizeWithJson()
    {
        var options = WinSentinel.Cli.CliParser.Parse(["--schedule-optimize", "--json"]);
        Assert.Equal(WinSentinel.Cli.CliCommand.ScheduleOptimize, options.Command);
        Assert.True(options.Json);
    }
}
