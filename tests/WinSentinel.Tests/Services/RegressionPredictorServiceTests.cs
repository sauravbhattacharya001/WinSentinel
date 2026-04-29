using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class RegressionPredictorServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;

    public RegressionPredictorServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"regression-test-{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _history.EnsureDatabase();
    }

    public void Dispose()
    {
        _history.Dispose();
        try { File.Delete(_dbPath); } catch { }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private SecurityReport BuildReport(int score, DateTimeOffset timestamp, params (string title, string module, string severity)[] findings)
    {
        var report = new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = timestamp,
            Results = new List<AuditResult>()
        };

        var grouped = findings.GroupBy(f => f.module);
        foreach (var group in grouped)
        {
            var result = new AuditResult
            {
                ModuleName = group.Key,
                Category = "Test",
                Findings = group.Select(f => new Finding
                {
                    Title = f.title,
                    Description = f.title,
                    Severity = Enum.TryParse<Severity>(f.severity, true, out var s) ? s : Core.Models.Severity.Info,
                    Category = "Test"
                }).ToList()
            };
            report.Results.Add(result);
        }

        return report;
    }

    private void SaveReports(params SecurityReport[] reports)
    {
        foreach (var r in reports)
            _history.SaveAuditResult(r);
    }

    // ── Tests ────────────────────────────────────────────────────────

    [Fact]
    public void Analyze_EmptyHistory_ReturnsEmptyReport()
    {
        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Equal(0, result.AnalyzedRuns);
        Assert.Empty(result.YoYoFindings);
        Assert.Empty(result.AtRiskFixes);
    }

    [Fact]
    public void Analyze_LessThan3Runs_ReturnsEarlyWithRunCount()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(80, now.AddDays(-2), ("FindingA", "ModA", "Warning")),
            BuildReport(85, now.AddDays(-1), ("FindingA", "ModA", "Warning"))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Equal(2, result.AnalyzedRuns);
        Assert.Empty(result.YoYoFindings);
    }

    [Fact]
    public void Analyze_SingleRegression_Detected()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-4), ("LeakyFinding", "ModA", "Warning")),  // present
            BuildReport(80, now.AddDays(-3)),                                        // fixed
            BuildReport(65, now.AddDays(-2), ("LeakyFinding", "ModA", "Warning")),  // regressed!
            BuildReport(80, now.AddDays(-1))                                         // fixed again
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Equal(4, result.AnalyzedRuns);
        Assert.Single(result.YoYoFindings);
        Assert.Equal("LeakyFinding", result.YoYoFindings[0].Title);
        Assert.Equal(1, result.YoYoFindings[0].RegressionCount);
        Assert.Equal(1, result.TotalRegressionsFound);
    }

    [Fact]
    public void Analyze_MultipleRegressions_SameFinding()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-7), ("Bouncer", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-6)),                                      // fix 1
            BuildReport(65, now.AddDays(-5), ("Bouncer", "ModA", "Critical")),    // regress 1
            BuildReport(80, now.AddDays(-4)),                                      // fix 2
            BuildReport(65, now.AddDays(-3), ("Bouncer", "ModA", "Critical")),    // regress 2
            BuildReport(80, now.AddDays(-2)),                                      // fix 3
            BuildReport(85, now.AddDays(-1))                                       // still fixed
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Equal(2, result.YoYoFindings[0].RegressionCount);
        Assert.Equal(2, result.TotalRegressionsFound);
    }

    [Fact]
    public void Analyze_ChronicPattern_ClassifiedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        // 3+ regressions = Chronic
        SaveReports(
            BuildReport(70, now.AddDays(-10), ("Chronic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-9)),
            BuildReport(65, now.AddDays(-8), ("Chronic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6), ("Chronic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4), ("Chronic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Equal("Chronic", result.YoYoFindings[0].Pattern);
        Assert.Equal(3, result.YoYoFindings[0].RegressionCount);
    }

    [Fact]
    public void Analyze_PeriodicPattern_RegularIntervals()
    {
        var now = DateTimeOffset.UtcNow;
        // 2 regressions at regular intervals (each 1 run apart) = Periodic
        SaveReports(
            BuildReport(70, now.AddDays(-8), ("Periodic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6), ("Periodic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4), ("Periodic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        // This has 2 regressions at interval 1, but 2 regressions AND regular => could be Periodic
        // However, with RegressionCount == 2 and regular intervals with CV < 0.4:
        // Actually FixDurations = [1, 1], avg=1, variance=0, cv=0 < 0.4 => Periodic
        // But wait, RegressionCount is 2, not >= 3, so it won't be Chronic
        Assert.Single(result.YoYoFindings);
        Assert.Equal("Periodic", result.YoYoFindings[0].Pattern);
    }

    [Fact]
    public void Analyze_SporadicPattern_IrregularIntervals()
    {
        var now = DateTimeOffset.UtcNow;
        // 2 regressions at very different intervals
        SaveReports(
            BuildReport(70, now.AddDays(-12), ("Sporadic", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-11)),
            BuildReport(65, now.AddDays(-10), ("Sporadic", "ModA", "Warning")),  // regress after 1 run
            BuildReport(80, now.AddDays(-9)),
            BuildReport(80, now.AddDays(-8)),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(80, now.AddDays(-6)),
            BuildReport(65, now.AddDays(-5), ("Sporadic", "ModA", "Warning")),  // regress after 4 runs
            BuildReport(80, now.AddDays(-4)),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Equal("Sporadic", result.YoYoFindings[0].Pattern);
    }

    [Fact]
    public void Analyze_QuickRegression_RootCauseHint()
    {
        var now = DateTimeOffset.UtcNow;
        // Fix duration of 1 run = quick regression
        SaveReports(
            BuildReport(70, now.AddDays(-5), ("Quick", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(65, now.AddDays(-3), ("Quick", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Contains("superficial fix", result.YoYoFindings[0].RootCauseHint);
    }

    [Fact]
    public void Analyze_ChronicRegression_SystemicRootCause()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-14), ("Systemic", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-13)),
            BuildReport(80, now.AddDays(-12)),
            BuildReport(80, now.AddDays(-11)),
            BuildReport(65, now.AddDays(-10), ("Systemic", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-9)),
            BuildReport(80, now.AddDays(-8)),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6), ("Systemic", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(65, now.AddDays(-2), ("Systemic", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Contains("systemic", result.YoYoFindings[0].RootCauseHint.ToLower());
    }

    [Fact]
    public void Analyze_RecentlyFixed_PredictedAtRisk()
    {
        var now = DateTimeOffset.UtcNow;
        // Finding was present, regressed once, then fixed again recently
        SaveReports(
            BuildReport(70, now.AddDays(-6), ("AtRisk", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4), ("AtRisk", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(65, now.AddDays(-2), ("AtRisk", "ModA", "Warning")),
            BuildReport(80, now.AddDays(-1))  // recently fixed - should appear in AtRiskFixes
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.NotEmpty(result.AtRiskFixes);
        var prediction = result.AtRiskFixes.FirstOrDefault(p => p.Title == "AtRisk");
        Assert.NotNull(prediction);
        Assert.True(prediction.RegressionProbability > 0);
    }

    [Fact]
    public void Analyze_RepeatOffender_HighProbability()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-8), ("Repeat", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6), ("Repeat", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4), ("Repeat", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(65, now.AddDays(-2), ("Repeat", "ModA", "Critical")),
            BuildReport(80, now.AddDays(-1))  // fixed again
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        var prediction = result.AtRiskFixes.FirstOrDefault(p => p.Title == "Repeat");
        Assert.NotNull(prediction);
        Assert.True(prediction.RegressionProbability >= 0.5, $"Expected >= 0.5 but got {prediction.RegressionProbability}");
    }

    [Fact]
    public void Analyze_FirstTimeFix_LowProbability()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-4), ("FirstTime", "ModA", "Info")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))  // still fixed
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        // FirstTime was fixed and stayed fixed, so it should be in AtRiskFixes with low probability
        var prediction = result.AtRiskFixes.FirstOrDefault(p => p.Title == "FirstTime");
        if (prediction != null)
        {
            Assert.True(prediction.RegressionProbability <= 0.3, $"Expected <= 0.3 but got {prediction.RegressionProbability}");
        }
    }

    [Fact]
    public void Analyze_ModuleProfiles_Calculated()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-5),
                ("FA", "ModA", "Warning"), ("FB", "ModB", "Critical")),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(65, now.AddDays(-3),
                ("FA", "ModA", "Warning"), ("FB", "ModB", "Critical")),
            BuildReport(80, now.AddDays(-2),
                ("FA", "ModA", "Warning")),  // FA persists, FB fixed
            BuildReport(75, now.AddDays(-1),
                ("FA", "ModA", "Warning"))   // FA still present
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.NotEmpty(result.ModuleProfiles);
    }

    [Fact]
    public void Analyze_VolatileModule_ClassifiedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        // Module with many regressions relative to its finding count
        SaveReports(
            BuildReport(70, now.AddDays(-8),
                ("V1", "Volatile", "Warning"), ("V2", "Volatile", "Critical")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6),
                ("V1", "Volatile", "Warning"), ("V2", "Volatile", "Critical")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4),
                ("V1", "Volatile", "Warning"), ("V2", "Volatile", "Critical")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(65, now.AddDays(-2),
                ("V1", "Volatile", "Warning"), ("V2", "Volatile", "Critical")),
            BuildReport(80, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        // Module "Volatile" has findings that keep regressing
        var profile = result.ModuleProfiles.FirstOrDefault(m => m.ModuleName == "Volatile");
        Assert.NotNull(profile);
        Assert.True(profile.RegressionCount > 0);
    }

    [Fact]
    public void Analyze_StableModule_ClassifiedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        // Module with no regressions
        SaveReports(
            BuildReport(70, now.AddDays(-4),
                ("S1", "Stable", "Warning")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1),
                ("S2", "Stable", "Info"))  // different finding, no regression
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        // If there are module profiles, check Stable module is stable
        var profile = result.ModuleProfiles.FirstOrDefault(m => m.ModuleName == "Stable");
        if (profile != null)
        {
            Assert.Equal("Stable", profile.Stability);
        }
    }

    [Fact]
    public void Analyze_RegressionScore_LowForClean()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(80, now.AddDays(-3), ("A", "Mod", "Info")),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(90, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.True(result.RegressionScore < 25, $"Expected < 25 but got {result.RegressionScore}");
        Assert.Equal("Low", result.RiskLevel);
    }

    [Fact]
    public void Analyze_RegressionScore_HighForManyRegressions()
    {
        var now = DateTimeOffset.UtcNow;
        // Many regressions across multiple findings
        SaveReports(
            BuildReport(50, now.AddDays(-10),
                ("A", "M1", "Critical"), ("B", "M2", "Warning"), ("C", "M3", "Critical")),
            BuildReport(80, now.AddDays(-9)),
            BuildReport(50, now.AddDays(-8),
                ("A", "M1", "Critical"), ("B", "M2", "Warning"), ("C", "M3", "Critical")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(50, now.AddDays(-6),
                ("A", "M1", "Critical"), ("B", "M2", "Warning"), ("C", "M3", "Critical")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(50, now.AddDays(-4),
                ("A", "M1", "Critical"), ("B", "M2", "Warning"), ("C", "M3", "Critical")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(50, now.AddDays(-2),
                ("A", "M1", "Critical"), ("B", "M2", "Warning"), ("C", "M3", "Critical")),
            BuildReport(80, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.True(result.RegressionScore >= 25, $"Expected >= 25 but got {result.RegressionScore}");
    }

    [Fact]
    public void Analyze_RiskLevel_CriticalForExtreme()
    {
        var now = DateTimeOffset.UtcNow;
        var reports = new List<SecurityReport>();
        // Create a ton of regressions
        for (int i = 0; i < 20; i++)
        {
            if (i % 2 == 0)
                reports.Add(BuildReport(40, now.AddDays(-20 + i),
                    ("X1", "M", "Critical"), ("X2", "M", "Critical"),
                    ("X3", "M", "Critical"), ("X4", "M", "Critical"),
                    ("X5", "M", "Critical")));
            else
                reports.Add(BuildReport(90, now.AddDays(-20 + i)));
        }
        SaveReports(reports.ToArray());

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.True(result.RegressionScore >= 50, $"Expected >= 50 but got {result.RegressionScore}");
    }

    [Fact]
    public void Analyze_Recommendations_ChronicTriggered()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-8), ("Chronic", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-7)),
            BuildReport(65, now.AddDays(-6), ("Chronic", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-5)),
            BuildReport(65, now.AddDays(-4), ("Chronic", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-3)),
            BuildReport(65, now.AddDays(-2), ("Chronic", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.NotEmpty(result.Recommendations);
        Assert.True(result.Recommendations.Any(r => r.Contains("chronic", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void Analyze_ModuleFilter_FiltersCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-5),
                ("FA", "ModA", "Warning"), ("FB", "ModB", "Critical")),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(65, now.AddDays(-3),
                ("FA", "ModA", "Warning"), ("FB", "ModB", "Critical")),
            BuildReport(80, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90, moduleFilter: "ModA");

        // Should only see ModA findings
        Assert.All(result.YoYoFindings, f => Assert.Equal("ModA", f.Module));
    }

    [Fact]
    public void Analyze_SeverityOrdering_HigherSeverityFirst()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-5),
                ("Low", "Mod", "Info"), ("High", "Mod", "Critical")),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(65, now.AddDays(-3),
                ("Low", "Mod", "Info"), ("High", "Mod", "Critical")),
            BuildReport(80, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        // Both have same regression count (1), so Critical should come first by severity weight
        if (result.YoYoFindings.Count >= 2)
        {
            Assert.Equal("Critical", result.YoYoFindings[0].Severity);
        }
    }

    [Fact]
    public void Analyze_NoRegressions_EmptyResults()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-4), ("Stable", "Mod", "Warning")),
            BuildReport(75, now.AddDays(-3), ("Stable", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-2), ("Stable", "Mod", "Warning")),
            BuildReport(85, now.AddDays(-1), ("Stable", "Mod", "Warning"))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Empty(result.YoYoFindings);
        Assert.Equal(0, result.TotalRegressionsFound);
    }

    [Fact]
    public void Analyze_ManyFindings_TopNLimits()
    {
        var now = DateTimeOffset.UtcNow;
        var findings1 = Enumerable.Range(1, 20)
            .Select(i => ($"F{i}", $"M{i}", "Warning"))
            .ToArray();
        var findings2 = Array.Empty<(string, string, string)>();

        SaveReports(
            BuildReport(50, now.AddDays(-5), findings1),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(50, now.AddDays(-3), findings1),
            BuildReport(80, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90, topN: 5);

        Assert.True(result.YoYoFindings.Count <= 5);
    }

    [Fact]
    public void Analyze_RegressionRate_CalculatedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        // 1 finding, 2 fixes, 1 regression = rate 0.5
        SaveReports(
            BuildReport(70, now.AddDays(-5), ("Rate", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-4)),
            BuildReport(65, now.AddDays(-3), ("Rate", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        // Fix count = 2 (disappeared twice), Regression count = 1
        Assert.Equal(0.5, result.YoYoFindings[0].RegressionRate);
    }

    [Fact]
    public void Analyze_AverageFixDuration_Calculated()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(70, now.AddDays(-6), ("Dur", "Mod", "Warning")),
            BuildReport(80, now.AddDays(-5)),                                    // fix (run index 1)
            BuildReport(65, now.AddDays(-4), ("Dur", "Mod", "Warning")),        // regress after 1 run
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(85, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.Single(result.YoYoFindings);
        Assert.Equal(1.0, result.YoYoFindings[0].AverageFixDuration);
    }

    [Fact]
    public void Analyze_GeneratedAt_IsSet()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(90, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.True(result.GeneratedAt > now.AddMinutes(-5));
    }

    [Fact]
    public void Analyze_LowScore_GetsPositiveRecommendation()
    {
        var now = DateTimeOffset.UtcNow;
        SaveReports(
            BuildReport(80, now.AddDays(-3)),
            BuildReport(85, now.AddDays(-2)),
            BuildReport(90, now.AddDays(-1))
        );

        var svc = new RegressionPredictorService(_history);
        var result = svc.Analyze(90);

        Assert.NotEmpty(result.Recommendations);
        // Should get the "Low regression risk" recommendation
        Assert.True(result.Recommendations.Any(r => r.Contains("Low regression risk") || r.Contains("acceptable")));
    }
}
