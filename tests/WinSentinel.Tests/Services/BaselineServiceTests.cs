using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class BaselineServiceTests : IDisposable
{
    private readonly string _testDir;
    private readonly BaselineService _service;

    public BaselineServiceTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "WinSentinel_BaselineTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_testDir);
        _service = new BaselineService(_testDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private static SecurityReport CreateTestReport(int score = 75, int criticals = 1, int warnings = 2)
    {
        var findings = new List<Finding>();

        for (int i = 0; i < criticals; i++)
            findings.Add(Finding.Critical($"Critical Issue {i + 1}", $"Critical description {i + 1}", "TestCategory"));
        for (int i = 0; i < warnings; i++)
            findings.Add(Finding.Warning($"Warning Issue {i + 1}", $"Warning description {i + 1}", "TestCategory"));
        findings.Add(Finding.Pass("Pass Check 1", "All good", "TestCategory"));
        findings.Add(Finding.Info("Info Note 1", "FYI", "TestCategory"));

        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test Category",
            Findings = findings,
            StartTime = DateTimeOffset.UtcNow.AddSeconds(-5),
            EndTime = DateTimeOffset.UtcNow,
            Success = true
        };

        return new SecurityReport
        {
            Results = [result],
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow
        };
    }

    // ── Save Tests ──

    [Fact]
    public void SaveBaseline_CreatesJsonFile()
    {
        var report = CreateTestReport();
        var baseline = _service.SaveBaseline("test-baseline", report, "Test description");

        Assert.Equal("test-baseline", baseline.Name);
        Assert.Equal("Test description", baseline.Description);
        Assert.Equal(75, baseline.OverallScore);
        Assert.True(File.Exists(Path.Combine(_testDir, "test-baseline.json")));
    }

    [Fact]
    public void SaveBaseline_CapturesModuleScores()
    {
        var report = CreateTestReport();
        var baseline = _service.SaveBaseline("modules-test", report);

        Assert.Single(baseline.ModuleScores);
        Assert.Equal("TestModule", baseline.ModuleScores[0].ModuleName);
        Assert.Equal("Test Category", baseline.ModuleScores[0].Category);
    }

    [Fact]
    public void SaveBaseline_CapturesFindings()
    {
        var report = CreateTestReport(criticals: 1, warnings: 2);
        var baseline = _service.SaveBaseline("findings-test", report);

        Assert.Equal(5, baseline.Findings.Count); // 1 critical + 2 warnings + 1 pass + 1 info
        Assert.Contains(baseline.Findings, f => f.Severity == "Critical");
        Assert.Contains(baseline.Findings, f => f.Severity == "Warning");
        Assert.Contains(baseline.Findings, f => f.Severity == "Pass");
        Assert.Contains(baseline.Findings, f => f.Severity == "Info");
    }

    [Fact]
    public void SaveBaseline_CapturesFindingCounts()
    {
        var report = CreateTestReport(criticals: 2, warnings: 3);
        var baseline = _service.SaveBaseline("counts-test", report);

        Assert.Equal(2, baseline.CriticalCount);
        Assert.Equal(3, baseline.WarningCount);
        Assert.Equal(1, baseline.InfoCount);
        Assert.Equal(1, baseline.PassCount);
        Assert.Equal(7, baseline.TotalFindings);
    }

    [Fact]
    public void SaveBaseline_ThrowsOnDuplicate()
    {
        var report = CreateTestReport();
        _service.SaveBaseline("dupe", report);

        Assert.Throws<InvalidOperationException>(() =>
            _service.SaveBaseline("dupe", report));
    }

    [Fact]
    public void SaveBaseline_OverwriteWithForce()
    {
        var report1 = CreateTestReport(score: 70);
        _service.SaveBaseline("overwrite", report1);

        var report2 = CreateTestReport(score: 90);
        var baseline = _service.SaveBaseline("overwrite", report2, overwrite: true);

        Assert.Equal(90, baseline.OverallScore);
    }

    [Fact]
    public void SaveBaseline_SetsGrade()
    {
        var report = CreateTestReport(score: 85);
        var baseline = _service.SaveBaseline("grade-test", report);

        Assert.NotEmpty(baseline.Grade);
    }

    [Fact]
    public void SaveBaseline_SetsMachineName()
    {
        var report = CreateTestReport();
        var baseline = _service.SaveBaseline("machine-test", report);

        Assert.Equal(Environment.MachineName, baseline.MachineName);
    }

    // ── Name Validation Tests ──

    [Fact]
    public void SaveBaseline_ThrowsOnEmptyName()
    {
        var report = CreateTestReport();
        Assert.Throws<ArgumentException>(() => _service.SaveBaseline("", report));
    }

    [Fact]
    public void SaveBaseline_ThrowsOnInvalidChars()
    {
        var report = CreateTestReport();
        Assert.Throws<ArgumentException>(() => _service.SaveBaseline("bad name!", report));
    }

    [Fact]
    public void SaveBaseline_ThrowsOnTooLongName()
    {
        var report = CreateTestReport();
        var longName = new string('a', 51);
        Assert.Throws<ArgumentException>(() => _service.SaveBaseline(longName, report));
    }

    [Fact]
    public void SaveBaseline_AcceptsValidNames()
    {
        var report = CreateTestReport();
        var baseline1 = _service.SaveBaseline("my-baseline_v2", report);
        Assert.Equal("my-baseline_v2", baseline1.Name);

        var baseline2 = _service.SaveBaseline("CamelCase123", report);
        Assert.Equal("CamelCase123", baseline2.Name);
    }

    // ── Load Tests ──

    [Fact]
    public void LoadBaseline_RoundTrips()
    {
        var report = CreateTestReport(score: 82);
        _service.SaveBaseline("roundtrip", report, "A round trip test");

        var loaded = _service.LoadBaseline("roundtrip");
        Assert.NotNull(loaded);
        Assert.Equal("roundtrip", loaded.Name);
        Assert.Equal("A round trip test", loaded.Description);
        Assert.Equal(82, loaded.OverallScore);
        Assert.NotEmpty(loaded.ModuleScores);
        Assert.NotEmpty(loaded.Findings);
    }

    [Fact]
    public void LoadBaseline_ReturnsNullForMissing()
    {
        var loaded = _service.LoadBaseline("nonexistent");
        Assert.Null(loaded);
    }

    // ── List Tests ──

    [Fact]
    public void ListBaselines_ReturnsAll()
    {
        var report = CreateTestReport();
        _service.SaveBaseline("alpha", report, "First");
        _service.SaveBaseline("beta", report, "Second");

        var list = _service.ListBaselines();
        Assert.Equal(2, list.Count);
        Assert.Contains(list, b => b.Name == "alpha");
        Assert.Contains(list, b => b.Name == "beta");
    }

    [Fact]
    public void ListBaselines_EmptyWhenNone()
    {
        var list = _service.ListBaselines();
        Assert.Empty(list);
    }

    [Fact]
    public void ListBaselines_IncludesDescriptions()
    {
        var report = CreateTestReport();
        _service.SaveBaseline("described", report, "My description");

        var list = _service.ListBaselines();
        Assert.Single(list);
        Assert.Equal("My description", list[0].Description);
    }

    // ── Delete Tests ──

    [Fact]
    public void DeleteBaseline_RemovesFile()
    {
        var report = CreateTestReport();
        _service.SaveBaseline("to-delete", report);
        Assert.True(_service.BaselineExists("to-delete"));

        var deleted = _service.DeleteBaseline("to-delete");
        Assert.True(deleted);
        Assert.False(_service.BaselineExists("to-delete"));
    }

    [Fact]
    public void DeleteBaseline_ReturnsFalseForMissing()
    {
        var deleted = _service.DeleteBaseline("nonexistent");
        Assert.False(deleted);
    }

    // ── Check Tests ──

    [Fact]
    public void CheckBaseline_DetectsRegressions()
    {
        // Baseline: 1 critical, 2 warnings
        var baselineReport = CreateTestReport(criticals: 1, warnings: 2);
        _service.SaveBaseline("check-regress", baselineReport);

        // Current: original issues plus a new critical
        var currentFindings = new List<Finding>
        {
            Finding.Critical("Critical Issue 1", "Same as baseline", "TestCategory"),
            Finding.Warning("Warning Issue 1", "Same as baseline", "TestCategory"),
            Finding.Warning("Warning Issue 2", "Same as baseline", "TestCategory"),
            Finding.Pass("Pass Check 1", "All good", "TestCategory"),
            Finding.Info("Info Note 1", "FYI", "TestCategory"),
            Finding.Critical("NEW Critical Problem", "This is a regression", "TestCategory"),
        };

        var currentReport = new SecurityReport
        {
            Results = [new AuditResult
            {
                ModuleName = "TestModule",
                Category = "Test Category",
                Findings = currentFindings,
                Success = true,
                StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                EndTime = DateTimeOffset.UtcNow
            }],
            SecurityScore = 55,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var result = _service.CheckBaseline("check-regress", currentReport);

        Assert.Single(result.Regressions);
        Assert.Equal("NEW Critical Problem", result.Regressions[0].Title);
        Assert.Equal("Critical", result.Regressions[0].Severity);
        Assert.False(result.Passed);
    }

    [Fact]
    public void CheckBaseline_DetectsResolved()
    {
        // Baseline: 1 critical, 2 warnings
        var baselineReport = CreateTestReport(criticals: 1, warnings: 2);
        _service.SaveBaseline("check-resolved", baselineReport);

        // Current: the critical is resolved, warnings remain
        var currentFindings = new List<Finding>
        {
            Finding.Warning("Warning Issue 1", "Same as baseline", "TestCategory"),
            Finding.Warning("Warning Issue 2", "Same as baseline", "TestCategory"),
            Finding.Pass("Pass Check 1", "All good", "TestCategory"),
            Finding.Info("Info Note 1", "FYI", "TestCategory"),
        };

        var currentReport = new SecurityReport
        {
            Results = [new AuditResult
            {
                ModuleName = "TestModule",
                Category = "Test Category",
                Findings = currentFindings,
                Success = true,
                StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                EndTime = DateTimeOffset.UtcNow
            }],
            SecurityScore = 90,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var result = _service.CheckBaseline("check-resolved", currentReport);

        Assert.Single(result.Resolved);
        Assert.Equal("Critical Issue 1", result.Resolved[0].Title);
        Assert.Empty(result.Regressions);
        Assert.True(result.Passed);
    }

    [Fact]
    public void CheckBaseline_DetectsUnchanged()
    {
        var baselineReport = CreateTestReport(criticals: 1, warnings: 1);
        _service.SaveBaseline("check-unchanged", baselineReport);

        // Current: exact same findings
        var currentFindings = new List<Finding>
        {
            Finding.Critical("Critical Issue 1", "Same", "TestCategory"),
            Finding.Warning("Warning Issue 1", "Same", "TestCategory"),
            Finding.Pass("Pass Check 1", "All good", "TestCategory"),
            Finding.Info("Info Note 1", "FYI", "TestCategory"),
        };

        var currentReport = new SecurityReport
        {
            Results = [new AuditResult
            {
                ModuleName = "TestModule",
                Category = "Test Category",
                Findings = currentFindings,
                Success = true,
                StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                EndTime = DateTimeOffset.UtcNow
            }],
            SecurityScore = 75,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var result = _service.CheckBaseline("check-unchanged", currentReport);

        Assert.Empty(result.Regressions);
        Assert.Empty(result.Resolved);
        Assert.Equal(4, result.Unchanged.Count);
        Assert.True(result.Passed);
    }

    [Fact]
    public void CheckBaseline_ScoreComparison()
    {
        var baselineReport = CreateTestReport(score: 80);
        _service.SaveBaseline("check-score", baselineReport);

        var currentReport = CreateTestReport(score: 60);
        var result = _service.CheckBaseline("check-score", currentReport);

        Assert.Equal(80, result.Baseline.OverallScore);
        Assert.Equal(60, result.CurrentScore);
        Assert.Equal(-20, result.ScoreChange);
        Assert.False(result.ScorePassed);
    }

    [Fact]
    public void CheckBaseline_ScoreImproved()
    {
        var baselineReport = CreateTestReport(score: 60);
        _service.SaveBaseline("check-improved", baselineReport);

        var currentReport = CreateTestReport(score: 85);
        var result = _service.CheckBaseline("check-improved", currentReport);

        Assert.Equal(25, result.ScoreChange);
        Assert.True(result.ScorePassed);
    }

    [Fact]
    public void CheckBaseline_ModuleDeviations()
    {
        var baselineReport = CreateTestReport(score: 75);
        _service.SaveBaseline("check-modules", baselineReport);

        // Create a report with a different module score
        var currentFindings = new List<Finding>
        {
            Finding.Critical("Critical Issue 1", "Same", "TestCategory"),
            Finding.Critical("Critical Issue Extra", "Extra critical", "TestCategory"),
            Finding.Warning("Warning Issue 1", "Same", "TestCategory"),
            Finding.Warning("Warning Issue 2", "Same", "TestCategory"),
            Finding.Pass("Pass Check 1", "All good", "TestCategory"),
            Finding.Info("Info Note 1", "FYI", "TestCategory"),
        };

        var currentReport = new SecurityReport
        {
            Results = [new AuditResult
            {
                ModuleName = "TestModule",
                Category = "Test Category",
                Findings = currentFindings,
                Success = true,
                StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                EndTime = DateTimeOffset.UtcNow
            }],
            SecurityScore = 55,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var result = _service.CheckBaseline("check-modules", currentReport);

        Assert.NotEmpty(result.ModuleDeviations);
        var deviation = result.ModuleDeviations.First(d => d.ModuleName == "TestModule");
        Assert.Equal("Test Category", deviation.Category);
    }

    [Fact]
    public void CheckBaseline_ThrowsForMissing()
    {
        var report = CreateTestReport();
        Assert.Throws<InvalidOperationException>(() =>
            _service.CheckBaseline("nonexistent", report));
    }

    [Fact]
    public void CheckBaseline_CriticalRegressionCount()
    {
        var baselineReport = CreateTestReport(criticals: 0, warnings: 0);
        _service.SaveBaseline("crit-count", baselineReport);

        var currentFindings = new List<Finding>
        {
            Finding.Critical("New Crit 1", "Bad", "TestCategory"),
            Finding.Critical("New Crit 2", "Bad", "TestCategory"),
            Finding.Warning("New Warn 1", "Bad", "TestCategory"),
            Finding.Pass("Pass Check 1", "All good", "TestCategory"),
            Finding.Info("Info Note 1", "FYI", "TestCategory"),
        };

        var currentReport = new SecurityReport
        {
            Results = [new AuditResult
            {
                ModuleName = "TestModule",
                Category = "Test Category",
                Findings = currentFindings,
                Success = true,
                StartTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                EndTime = DateTimeOffset.UtcNow
            }],
            SecurityScore = 50,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var result = _service.CheckBaseline("crit-count", currentReport);
        Assert.Equal(2, result.CriticalRegressions);
        Assert.Equal(1, result.WarningRegressions);
        Assert.False(result.Passed);
    }

    // ── Exists Tests ──

    [Fact]
    public void BaselineExists_TrueWhenSaved()
    {
        var report = CreateTestReport();
        _service.SaveBaseline("exists-test", report);
        Assert.True(_service.BaselineExists("exists-test"));
    }

    [Fact]
    public void BaselineExists_FalseWhenMissing()
    {
        Assert.False(_service.BaselineExists("missing"));
    }

    // ── Multi-Module Tests ──

    [Fact]
    public void SaveAndCheck_MultipleModules()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "FirewallAudit", Category = "Firewall",
                Findings = [Finding.Pass("Firewall Enabled", "Good", "Firewall")],
                Success = true, StartTime = DateTimeOffset.UtcNow.AddSeconds(-2), EndTime = DateTimeOffset.UtcNow
            },
            new()
            {
                ModuleName = "NetworkAudit", Category = "Network",
                Findings = [Finding.Warning("Open Port 80", "Port 80 exposed", "Network")],
                Success = true, StartTime = DateTimeOffset.UtcNow.AddSeconds(-1), EndTime = DateTimeOffset.UtcNow
            }
        };

        var report = new SecurityReport
        {
            Results = results,
            SecurityScore = 85,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        _service.SaveBaseline("multi-mod", report);
        var baseline = _service.LoadBaseline("multi-mod");

        Assert.NotNull(baseline);
        Assert.Equal(2, baseline.ModuleScores.Count);
        Assert.Contains(baseline.ModuleScores, m => m.ModuleName == "FirewallAudit");
        Assert.Contains(baseline.ModuleScores, m => m.ModuleName == "NetworkAudit");
        Assert.Equal(2, baseline.Findings.Count);
    }

    // ── BaselineCheckResult Model Tests ──

    [Fact]
    public void BaselineCheckResult_PassedWhenNoRegressions()
    {
        var result = new BaselineCheckResult
        {
            Baseline = new SecurityBaseline { OverallScore = 70 },
            CurrentScore = 80,
            Regressions = [],
            Resolved = [new BaselineFinding { Title = "Fixed", Severity = "Warning" }],
            Unchanged = []
        };

        Assert.True(result.Passed);
        Assert.True(result.ScorePassed);
        Assert.Equal(10, result.ScoreChange);
    }

    [Fact]
    public void BaselineCheckResult_FailedOnScoreDrop()
    {
        var result = new BaselineCheckResult
        {
            Baseline = new SecurityBaseline { OverallScore = 90 },
            CurrentScore = 70,
            Regressions = [],
            Resolved = [],
            Unchanged = []
        };

        Assert.False(result.Passed); // Score dropped
        Assert.False(result.ScorePassed);
    }

    [Fact]
    public void BaselineModuleDeviation_Status()
    {
        var improved = new BaselineModuleDeviation { BaselineScore = 60, CurrentScore = 80 };
        Assert.Equal("Improved", improved.Status);
        Assert.Equal(20, improved.ScoreChange);

        var regressed = new BaselineModuleDeviation { BaselineScore = 80, CurrentScore = 60 };
        Assert.Equal("Regressed", regressed.Status);
        Assert.Equal(-20, regressed.ScoreChange);

        var unchanged = new BaselineModuleDeviation { BaselineScore = 75, CurrentScore = 75 };
        Assert.Equal("Unchanged", unchanged.Status);
        Assert.Equal(0, unchanged.ScoreChange);
    }
}
