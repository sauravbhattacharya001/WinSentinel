using WinSentinel.Cli;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityChangelogServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly SecurityChangelogService _service;

    public SecurityChangelogServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"changelog-test-{Guid.NewGuid()}.db");
        _history = new AuditHistoryService(_dbPath);
        _service = new SecurityChangelogService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        // SQLite connection pooling on Windows may hold the file open briefly
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch (IOException) { /* best effort */ }
    }

    private SecurityReport MakeReport(int score, int criticals = 0, int warnings = 0, DateTimeOffset? timestamp = null,
        List<(string module, string title, Severity severity)>? findings = null)
    {
        var report = new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = timestamp ?? DateTimeOffset.UtcNow
        };

        var result = new AuditResult { ModuleName = "TestModule", Category = "Test" };
        if (findings != null)
        {
            foreach (var (mod, title, sev) in findings)
            {
                result.Findings.Add(new Finding
                {
                    Title = title,
                    Description = $"Description for {title}",
                    Severity = sev,
                    Category = "Test"
                });
            }
        }
        else
        {
            for (int i = 0; i < criticals; i++)
                result.Findings.Add(Finding.Critical($"Critical-{i}", $"Critical finding {i}", "Test"));
            for (int i = 0; i < warnings; i++)
                result.Findings.Add(Finding.Warning($"Warning-{i}", $"Warning finding {i}", "Test"));
        }

        report.Results.Add(result);
        return report;
    }

    [Fact]
    public void EmptyHistory_ReturnsEmptyReport()
    {
        var report = _service.Generate();
        Assert.Equal(0, report.TotalScans);
        Assert.Empty(report.Entries);
        Assert.Empty(report.Milestones);
    }

    [Fact]
    public void SingleScan_NoEntries()
    {
        _history.SaveAuditResult(MakeReport(75, timestamp: DateTimeOffset.UtcNow));
        var report = _service.Generate();
        Assert.Equal(1, report.TotalScans);
        Assert.Empty(report.Entries); // need 2 scans for a diff
    }

    [Fact]
    public void TwoScans_ScoreImprovement_GeneratesEntry()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(60, timestamp: t1));
        _history.SaveAuditResult(MakeReport(80, timestamp: t2));

        var report = _service.Generate();
        Assert.Equal(2, report.TotalScans);
        Assert.Equal(60, report.StartScore);
        Assert.Equal(80, report.EndScore);
        Assert.Equal(20, report.NetScoreChange);
        Assert.Single(report.Entries);
        Assert.Contains(report.Entries[0].Events, e => e.Type == ChangelogEventType.Improvement);
    }

    [Fact]
    public void TwoScans_ScoreRegression_DetectedAsRegression()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(90, timestamp: t1));
        _history.SaveAuditResult(MakeReport(70, timestamp: t2));

        var report = _service.Generate();
        Assert.Equal(-20, report.NetScoreChange);
        Assert.Contains(report.Entries[0].Events, e => e.Type == ChangelogEventType.Regression);
    }

    [Fact]
    public void GradeChange_Detected()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(65, timestamp: t1)); // C
        _history.SaveAuditResult(MakeReport(85, timestamp: t2)); // B

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.GradeUp || e.Type == ChangelogEventType.GradeDown);
    }

    [Fact]
    public void CriticalFindings_ResolutionDetected()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(50, criticals: 3, timestamp: t1));
        _history.SaveAuditResult(MakeReport(80, criticals: 0, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.FindingsResolved && e.Summary.Contains("critical"));
    }

    [Fact]
    public void NewCriticalFindings_Detected()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(80, criticals: 0, timestamp: t1));
        _history.SaveAuditResult(MakeReport(50, criticals: 2, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.FindingsIntroduced && e.Summary.Contains("critical"));
    }

    [Fact]
    public void WarningChanges_Detected()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(70, warnings: 5, timestamp: t1));
        _history.SaveAuditResult(MakeReport(80, warnings: 2, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.FindingsResolved && e.Summary.Contains("warning"));
    }

    [Fact]
    public void ZeroCritical_MilestoneEvent()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(50, criticals: 3, timestamp: t1));
        _history.SaveAuditResult(MakeReport(80, criticals: 0, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.Milestone && e.Summary.Contains("critical"));
    }

    [Fact]
    public void ImprovementStreak_Milestone()
    {
        for (int i = 0; i < 5; i++)
        {
            _history.SaveAuditResult(MakeReport(50 + i * 10, timestamp: DateTimeOffset.UtcNow.AddHours(-10 + i)));
        }

        var report = _service.Generate();
        Assert.Contains(report.Milestones, m => m.Type == MilestoneType.ImprovementStreak);
    }

    [Fact]
    public void PerfectScore_Milestone()
    {
        _history.SaveAuditResult(MakeReport(90, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(100, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Contains(report.Milestones, m => m.Type == MilestoneType.PerfectScore);
    }

    [Fact]
    public void BiggestImprovement_Milestone()
    {
        _history.SaveAuditResult(MakeReport(40, timestamp: DateTimeOffset.UtcNow.AddHours(-3)));
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(72, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Contains(report.Milestones, m => m.Type == MilestoneType.BiggestImprovement);
    }

    [Fact]
    public void NoScoreChange_NoEntries()
    {
        _history.SaveAuditResult(MakeReport(75, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(75, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Empty(report.Entries);
    }

    [Fact]
    public void DayFilter_RespectsRange()
    {
        _history.SaveAuditResult(MakeReport(50, timestamp: DateTimeOffset.UtcNow.AddDays(-60)));
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddDays(-5)));
        _history.SaveAuditResult(MakeReport(80, timestamp: DateTimeOffset.UtcNow.AddDays(-1)));

        var report = _service.Generate(days: 10);
        Assert.Equal(2, report.TotalScans);
    }

    [Fact]
    public void FindingDiff_Resolved()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(60, findings: new()
        {
            ("Firewall", "Firewall disabled", Severity.Critical),
            ("Updates", "Updates pending", Severity.Warning)
        }, timestamp: t1));
        _history.SaveAuditResult(MakeReport(80, findings: new()
        {
            ("Updates", "Updates pending", Severity.Warning)
        }, timestamp: t2));

        var report = _service.Generate();
        Assert.Single(report.Entries);
        Assert.Contains(report.Entries[0].FindingChanges,
            fc => fc.Type == FindingChangeType.Resolved && fc.Title == "Firewall disabled");
    }

    [Fact]
    public void FindingDiff_Introduced()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(80, findings: new()
        {
            ("Updates", "Updates pending", Severity.Warning)
        }, timestamp: t1));
        _history.SaveAuditResult(MakeReport(60, findings: new()
        {
            ("Updates", "Updates pending", Severity.Warning),
            ("Firewall", "Firewall disabled", Severity.Critical)
        }, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].FindingChanges,
            fc => fc.Type == FindingChangeType.Introduced && fc.Title == "Firewall disabled");
    }

    [Fact]
    public void BestWorstScore_Calculated()
    {
        _history.SaveAuditResult(MakeReport(50, timestamp: DateTimeOffset.UtcNow.AddHours(-3)));
        _history.SaveAuditResult(MakeReport(90, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Equal(90, report.BestScore);
        Assert.Equal(50, report.WorstScore);
    }

    [Fact]
    public void ImprovementRegressionCounts()
    {
        _history.SaveAuditResult(MakeReport(50, timestamp: DateTimeOffset.UtcNow.AddHours(-5)));
        _history.SaveAuditResult(MakeReport(60, timestamp: DateTimeOffset.UtcNow.AddHours(-4)));
        _history.SaveAuditResult(MakeReport(55, timestamp: DateTimeOffset.UtcNow.AddHours(-3)));
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(75, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Equal(3, report.ImprovementCount);
        Assert.Equal(1, report.RegressionCount);
    }

    [Fact]
    public void MultipleEntries_ChronologicalOrder()
    {
        for (int i = 0; i < 4; i++)
        {
            _history.SaveAuditResult(MakeReport(50 + i * 10,
                timestamp: DateTimeOffset.UtcNow.AddHours(-10 + i)));
        }

        var report = _service.Generate();
        for (int i = 1; i < report.Entries.Count; i++)
        {
            Assert.True(report.Entries[i].Timestamp > report.Entries[i - 1].Timestamp);
        }
    }

    [Fact]
    public void ZeroCritical_Milestone_DetectedInMilestones()
    {
        _history.SaveAuditResult(MakeReport(50, criticals: 2, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(80, criticals: 0, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Contains(report.Milestones, m => m.Type == MilestoneType.ZeroCritical);
    }

    [Fact]
    public void IsGradeBetter_ComparisonWorks()
    {
        Assert.True(SecurityChangelogService.IsGradeBetter("A+", "B"));
        Assert.True(SecurityChangelogService.IsGradeBetter("B", "C"));
        Assert.False(SecurityChangelogService.IsGradeBetter("C", "A"));
        Assert.False(SecurityChangelogService.IsGradeBetter("F", "A+"));
    }

    [Fact]
    public void CliParser_Changelog_Parsed()
    {
        var opts = CliParser.Parse(new[] { "--changelog" });
        Assert.Equal(CliCommand.Changelog, opts.Command);
        Assert.Equal(30, opts.ChangelogDays);
        Assert.Null(opts.ChangelogModuleFilter);
    }

    [Fact]
    public void CliParser_Changelog_WithDays()
    {
        var opts = CliParser.Parse(new[] { "--changelog", "--changelog-days", "60" });
        Assert.Equal(CliCommand.Changelog, opts.Command);
        Assert.Equal(60, opts.ChangelogDays);
    }

    [Fact]
    public void CliParser_Changelog_WithModule()
    {
        var opts = CliParser.Parse(new[] { "--changelog", "--changelog-module", "Firewall" });
        Assert.Equal(CliCommand.Changelog, opts.Command);
        Assert.Equal("Firewall", opts.ChangelogModuleFilter);
    }

    [Fact]
    public void CliParser_ChangelogDays_InvalidValue_Error()
    {
        var opts = CliParser.Parse(new[] { "--changelog", "--changelog-days", "0" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_ChangelogDays_MissingValue_Error()
    {
        var opts = CliParser.Parse(new[] { "--changelog", "--changelog-days" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_ChangelogModule_MissingValue_Error()
    {
        var opts = CliParser.Parse(new[] { "--changelog", "--changelog-module" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void GradeAchievement_Milestone()
    {
        _history.SaveAuditResult(MakeReport(80, timestamp: DateTimeOffset.UtcNow.AddHours(-3)));
        _history.SaveAuditResult(MakeReport(95, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));

        var report = _service.Generate();
        Assert.Contains(report.Milestones, m => m.Type == MilestoneType.GradeAchievement);
    }

    [Fact]
    public void FindingChangesOmitted_WhenMoreThanFive()
    {
        var findings1 = new List<(string, string, Severity)>();
        for (int i = 0; i < 8; i++)
            findings1.Add(("Mod", $"Finding-{i}", Severity.Warning));

        _history.SaveAuditResult(MakeReport(50, findings: findings1,
            timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(90, findings: new(),
            timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        var entry = report.Entries[0];
        Assert.True(entry.FindingChanges.Count <= 5);
        Assert.True(entry.FindingChangesOmitted > 0);
    }

    [Fact]
    public void Report_Period_Set()
    {
        var report = _service.Generate(days: 14);
        Assert.Equal(14, report.Period);
    }

    [Fact]
    public void ShortStreak_NoMilestone()
    {
        _history.SaveAuditResult(MakeReport(50, timestamp: DateTimeOffset.UtcNow.AddHours(-4)));
        _history.SaveAuditResult(MakeReport(60, timestamp: DateTimeOffset.UtcNow.AddHours(-3)));
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(65, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.DoesNotContain(report.Milestones, m => m.Type == MilestoneType.ImprovementStreak);
    }

    [Fact]
    public void SmallImprovement_NoBiggestMilestone()
    {
        _history.SaveAuditResult(MakeReport(70, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(73, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.DoesNotContain(report.Milestones, m => m.Type == MilestoneType.BiggestImprovement);
    }

    [Fact]
    public void WarningIntroduced_Detected()
    {
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddHours(-1);
        _history.SaveAuditResult(MakeReport(80, warnings: 1, timestamp: t1));
        _history.SaveAuditResult(MakeReport(70, warnings: 4, timestamp: t2));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events,
            e => e.Type == ChangelogEventType.FindingsIntroduced && e.Summary.Contains("warning"));
    }

    [Fact]
    public void GradeDown_Detected()
    {
        _history.SaveAuditResult(MakeReport(90, timestamp: DateTimeOffset.UtcNow.AddHours(-2)));
        _history.SaveAuditResult(MakeReport(60, timestamp: DateTimeOffset.UtcNow.AddHours(-1)));

        var report = _service.Generate();
        Assert.Contains(report.Entries[0].Events, e => e.Type == ChangelogEventType.GradeDown);
    }
}
