using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class SecurityTimelineTests
{
    private readonly SecurityTimeline _timeline = new();
    private static readonly DateTimeOffset BaseTime = new(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);

    private static AuditRunRecord MakeRun(long id, DateTimeOffset ts, int score,
        List<FindingRecord>? findings = null, List<ModuleScoreRecord>? modules = null)
    {
        var f = findings ?? [];
        return new AuditRunRecord
        {
            Id = id,
            Timestamp = ts,
            OverallScore = score,
            Grade = SecurityScorer.GetGrade(score),
            TotalFindings = f.Count,
            CriticalCount = f.Count(x => x.Severity == "Critical"),
            WarningCount = f.Count(x => x.Severity == "Warning"),
            InfoCount = f.Count(x => x.Severity == "Info"),
            PassCount = f.Count(x => x.Severity == "Pass"),
            Findings = f,
            ModuleScores = modules ?? [],
        };
    }

    private static FindingRecord MakeFinding(long runId, string title, string severity,
        string module = "Network", string desc = "Test finding")
    {
        return new FindingRecord
        {
            RunId = runId,
            Title = title,
            Severity = severity,
            ModuleName = module,
            Description = desc,
        };
    }

    private static ModuleScoreRecord MakeModule(long runId, string name, int score)
    {
        return new ModuleScoreRecord
        {
            RunId = runId,
            ModuleName = name,
            Category = name,
            Score = score,
        };
    }

    // ── Empty/single run (5) ──────────────────────────────────────────

    [Fact]
    public void Build_EmptyRuns_ReturnsEmptyReport()
    {
        var report = _timeline.Build([]);
        Assert.Empty(report.Events);
        Assert.Equal(0, report.RunsAnalyzed);
        Assert.Null(report.StartDate);
        Assert.Null(report.EndDate);
    }

    [Fact]
    public void Build_SingleRun_HasInitialScanEvent()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, BaseTime, 85) };
        var report = _timeline.Build(runs);
        Assert.Single(report.Events);
        Assert.Equal(TimelineEventType.InitialScan, report.Events[0].EventType);
        Assert.Equal("Initial Security Scan", report.Events[0].Title);
    }

    [Fact]
    public void Build_SingleRun_RecordsScore()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, BaseTime, 75) };
        var report = _timeline.Build(runs);
        Assert.Equal(75, report.Events[0].Score);
    }

    [Fact]
    public void Build_SingleRun_CountsFindings()
    {
        var findings = new List<FindingRecord>
        {
            MakeFinding(1, "F1", "Critical"),
            MakeFinding(1, "F2", "Warning"),
        };
        var runs = new List<AuditRunRecord> { MakeRun(1, BaseTime, 75, findings) };
        var report = _timeline.Build(runs);
        Assert.Contains("1 critical", report.Events[0].Description);
        Assert.Contains("1 warnings", report.Events[0].Description);
    }

    [Fact]
    public void Build_SingleRun_SetsDateRange()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, BaseTime, 90) };
        var report = _timeline.Build(runs);
        Assert.Equal(BaseTime, report.StartDate);
        Assert.Equal(BaseTime, report.EndDate);
        Assert.Equal(1, report.RunsAnalyzed);
    }

    // ── Score changes (8) ─────────────────────────────────────────────

    [Fact]
    public void Build_ScoreImproved_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 75),
        };
        var report = _timeline.Build(runs);
        var improved = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.ScoreImproved);
        Assert.NotNull(improved);
        Assert.Equal(75, improved.Score);
        Assert.Equal(70, improved.PreviousScore);
        Assert.Equal(5, improved.ScoreDelta);
    }

    [Fact]
    public void Build_ScoreRegressed_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80),
            MakeRun(2, BaseTime.AddHours(1), 75),
        };
        var report = _timeline.Build(runs);
        var regressed = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.ScoreRegressed);
        Assert.NotNull(regressed);
        Assert.Equal(75, regressed.Score);
        Assert.Equal(80, regressed.PreviousScore);
        Assert.Equal(-5, regressed.ScoreDelta);
    }

    [Fact]
    public void Build_LargeImprovement_IsNoticeSeverity()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 60),
            MakeRun(2, BaseTime.AddHours(1), 75),
        };
        var report = _timeline.Build(runs);
        var improved = report.Events.First(e => e.EventType == TimelineEventType.ScoreImproved);
        Assert.Equal(TimelineSeverity.Notice, improved.Severity);
    }

    [Fact]
    public void Build_LargeRegression_IsWarningSeverity()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80),
            MakeRun(2, BaseTime.AddHours(1), 65),
        };
        var report = _timeline.Build(runs);
        var regressed = report.Events.First(e => e.EventType == TimelineEventType.ScoreRegressed);
        Assert.Equal(TimelineSeverity.Warning, regressed.Severity);
    }

    [Fact]
    public void Build_ScoreUnchanged_NoScoreEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.ScoreImproved);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.ScoreRegressed);
    }

    [Fact]
    public void Build_NewHighScore_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 85),
        };
        var report = _timeline.Build(runs);
        var highScore = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.NewHighScore);
        Assert.NotNull(highScore);
        Assert.Equal(85, highScore.Score);
    }

    [Fact]
    public void Build_NewLowScore_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 50),
        };
        var report = _timeline.Build(runs);
        var lowScore = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.NewLowScore);
        Assert.NotNull(lowScore);
        Assert.Equal(50, lowScore.Score);
    }

    [Fact]
    public void Build_HighScore_OnlyTriggersOnce()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 90),
            MakeRun(3, BaseTime.AddHours(2), 85),
            MakeRun(4, BaseTime.AddHours(3), 90), // same as previous high, NOT a new high
        };
        var report = _timeline.Build(runs);
        var highScores = report.Events.Where(e => e.EventType == TimelineEventType.NewHighScore).ToList();
        Assert.Single(highScores);
        Assert.Equal(90, highScores[0].Score);
    }

    // ── Finding changes (10) ──────────────────────────────────────────

    [Fact]
    public void Build_NewFinding_CreatesFindingAppearedEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 85,
                [MakeFinding(2, "Open Port 22", "Warning")]),
        };
        var report = _timeline.Build(runs);
        var appeared = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.FindingAppeared);
        Assert.NotNull(appeared);
        Assert.Equal("Open Port 22", appeared.FindingTitle);
        Assert.Equal("Network", appeared.Module);
    }

    [Fact]
    public void Build_FindingResolved_CreatesFindingResolvedEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 85,
                [MakeFinding(1, "Open Port 22", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        var resolved = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.FindingResolved);
        Assert.NotNull(resolved);
        Assert.Contains("Open Port 22", resolved.FindingTitle);
    }

    [Fact]
    public void Build_PersistentFinding_NoEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 85,
                [MakeFinding(1, "Open Port 22", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 85,
                [MakeFinding(2, "Open Port 22", "Warning")]),
        };
        var report = _timeline.Build(runs);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.FindingAppeared);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.FindingResolved);
    }

    [Fact]
    public void Build_MultipleFindingsAppear_CreatesMultipleEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 70,
            [
                MakeFinding(2, "Finding A", "Warning"),
                MakeFinding(2, "Finding B", "Info"),
                MakeFinding(2, "Finding C", "Warning"),
            ]),
        };
        var report = _timeline.Build(runs);
        var appeared = report.Events.Where(e => e.EventType == TimelineEventType.FindingAppeared).ToList();
        Assert.Equal(3, appeared.Count);
    }

    [Fact]
    public void Build_MultipleFindingsResolve_CreatesMultipleEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70,
            [
                MakeFinding(1, "Finding A", "Warning"),
                MakeFinding(1, "Finding B", "Warning"),
            ]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        var resolved = report.Events.Where(e => e.EventType == TimelineEventType.FindingResolved).ToList();
        Assert.Equal(2, resolved.Count);
    }

    [Fact]
    public void Build_NewCriticalFinding_CreatesCriticalAlertEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 60,
                [MakeFinding(2, "Remote Code Execution", "Critical")]),
        };
        var report = _timeline.Build(runs);
        var critical = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.CriticalAlert);
        Assert.NotNull(critical);
        Assert.Equal(TimelineSeverity.Critical, critical.Severity);
        Assert.Equal("Remote Code Execution", critical.FindingTitle);
    }

    [Fact]
    public void Build_FindingAppearedThenResolved_TracksResolutionTime()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddDays(1), 80,
                [MakeFinding(2, "Issue X", "Warning")]),
            MakeRun(3, BaseTime.AddDays(3), 90), // resolved 2 days later
        };
        var report = _timeline.Build(runs);
        Assert.NotNull(report.Summary.AverageTimeToResolve);
        Assert.Equal(TimeSpan.FromDays(2), report.Summary.AverageTimeToResolve.Value);
    }

    [Fact]
    public void Build_SeverityChanged_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 85,
                [MakeFinding(1, "Weak Password", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 80,
                [MakeFinding(2, "Weak Password", "Critical")]),
        };
        var report = _timeline.Build(runs);
        var sevChanged = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.SeverityChanged);
        Assert.NotNull(sevChanged);
        Assert.Contains("Warning", sevChanged.Description);
        Assert.Contains("Critical", sevChanged.Description);
    }

    [Fact]
    public void Build_SeverityUpgrade_HasWarningSeverity()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 85,
                [MakeFinding(1, "Weak Password", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 80,
                [MakeFinding(2, "Weak Password", "Critical")]),
        };
        var report = _timeline.Build(runs);
        var sevChanged = report.Events.First(e => e.EventType == TimelineEventType.SeverityChanged);
        Assert.Equal(TimelineSeverity.Warning, sevChanged.Severity);
    }

    [Fact]
    public void Build_SeverityDowngrade_HasInfoSeverity()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Weak Password", "Critical")]),
            MakeRun(2, BaseTime.AddHours(1), 85,
                [MakeFinding(2, "Weak Password", "Warning")]),
        };
        var report = _timeline.Build(runs);
        var sevChanged = report.Events.First(e => e.EventType == TimelineEventType.SeverityChanged);
        Assert.Equal(TimelineSeverity.Info, sevChanged.Severity);
    }

    // ── Critical alerts (4) ───────────────────────────────────────────

    [Fact]
    public void Build_CriticalAppears_CreatesCriticalAlert()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 60,
                [MakeFinding(2, "RCE Vuln", "Critical")]),
        };
        var report = _timeline.Build(runs);
        Assert.Contains(report.Events, e => e.EventType == TimelineEventType.CriticalAlert);
    }

    [Fact]
    public void Build_AllCriticalsResolved_CreatesCriticalsClear()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 60,
                [MakeFinding(1, "RCE Vuln", "Critical")]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        Assert.Contains(report.Events, e => e.EventType == TimelineEventType.CriticalsClear);
    }

    [Fact]
    public void Build_CriticalsStillPresent_NoClearEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 60,
                [MakeFinding(1, "RCE Vuln", "Critical")]),
            MakeRun(2, BaseTime.AddHours(1), 60,
                [MakeFinding(2, "RCE Vuln", "Critical")]),
        };
        var report = _timeline.Build(runs);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.CriticalsClear);
    }

    [Fact]
    public void Build_NoCriticalsEver_NoClearEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 85,
                [MakeFinding(1, "Minor Issue", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.CriticalsClear);
    }

    // ── Module score changes (4) ──────────────────────────────────────

    [Fact]
    public void Build_ModuleScoreIncrease10_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70, modules: [MakeModule(1, "Network", 60)]),
            MakeRun(2, BaseTime.AddHours(1), 80, modules: [MakeModule(2, "Network", 70)]),
        };
        var report = _timeline.Build(runs);
        var modEvent = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.ModuleScoreChanged);
        Assert.NotNull(modEvent);
        Assert.Equal("Network", modEvent.Module);
        Assert.Equal(10, modEvent.ScoreDelta);
    }

    [Fact]
    public void Build_ModuleScoreDecrease10_CreatesEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80, modules: [MakeModule(1, "Network", 80)]),
            MakeRun(2, BaseTime.AddHours(1), 70, modules: [MakeModule(2, "Network", 70)]),
        };
        var report = _timeline.Build(runs);
        var modEvent = report.Events.FirstOrDefault(e => e.EventType == TimelineEventType.ModuleScoreChanged);
        Assert.NotNull(modEvent);
        Assert.Equal(-10, modEvent.ScoreDelta);
    }

    [Fact]
    public void Build_ModuleScoreSmallChange_NoEvent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80, modules: [MakeModule(1, "Network", 80)]),
            MakeRun(2, BaseTime.AddHours(1), 78, modules: [MakeModule(2, "Network", 75)]),
        };
        var report = _timeline.Build(runs);
        Assert.DoesNotContain(report.Events, e => e.EventType == TimelineEventType.ModuleScoreChanged);
    }

    [Fact]
    public void Build_ModuleScoreLargeRegression_HasWarningSeverity()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80, modules: [MakeModule(1, "Network", 90)]),
            MakeRun(2, BaseTime.AddHours(1), 60, modules: [MakeModule(2, "Network", 70)]),
        };
        var report = _timeline.Build(runs);
        var modEvent = report.Events.First(e => e.EventType == TimelineEventType.ModuleScoreChanged);
        Assert.Equal(TimelineSeverity.Warning, modEvent.Severity); // -20 is < -15
    }

    // ── Filtering (8) ─────────────────────────────────────────────────

    [Fact]
    public void Build_MinSeverityFilter_FiltersLowEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 75), // small improvement = Info severity
        };
        var options = new TimelineOptions { MinSeverity = TimelineSeverity.Warning };
        var report = _timeline.Build(runs, options);
        // InitialScan is Info, small improvement is Info — both filtered
        Assert.All(report.Events, e => Assert.True(e.Severity >= TimelineSeverity.Warning));
    }

    [Fact]
    public void Build_ModuleFilter_FiltersOtherModules()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 80,
            [
                MakeFinding(2, "Net Issue", "Warning", "Network"),
                MakeFinding(2, "FW Issue", "Warning", "Firewall"),
            ]),
        };
        var options = new TimelineOptions { ModuleFilter = "Network" };
        var report = _timeline.Build(runs, options);
        // Should include events with Module=null (global) and Module=Network, but not Firewall
        Assert.DoesNotContain(report.Events, e => e.Module == "Firewall");
    }

    [Fact]
    public void Build_ModuleFilter_KeepsGlobalEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 80,
                [MakeFinding(2, "Net Issue", "Warning", "Network")]),
        };
        var options = new TimelineOptions { ModuleFilter = "Network" };
        var report = _timeline.Build(runs, options);
        // Global events (InitialScan, score changes) have null Module — should be kept
        Assert.Contains(report.Events, e => e.Module == null);
    }

    [Fact]
    public void Build_EventTypeFilter_FiltersOtherTypes()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var options = new TimelineOptions
        {
            EventTypes = [TimelineEventType.ScoreImproved]
        };
        var report = _timeline.Build(runs, options);
        Assert.All(report.Events, e => Assert.Equal(TimelineEventType.ScoreImproved, e.EventType));
        Assert.NotEmpty(report.Events);
    }

    [Fact]
    public void Build_MaxEvents_LimitsMostRecent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 50),
            MakeRun(2, BaseTime.AddHours(1), 60),
            MakeRun(3, BaseTime.AddHours(2), 70),
            MakeRun(4, BaseTime.AddHours(3), 80),
            MakeRun(5, BaseTime.AddHours(4), 90),
        };
        var options = new TimelineOptions { MaxEvents = 3 };
        var report = _timeline.Build(runs, options);
        Assert.Equal(3, report.Events.Count);
    }

    [Fact]
    public void Build_CombinedFilters_WorkTogether()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 60,
            [
                MakeFinding(2, "Critical Net", "Critical", "Network"),
                MakeFinding(2, "Minor FW", "Info", "Firewall"),
            ]),
        };
        var options = new TimelineOptions
        {
            MinSeverity = TimelineSeverity.Warning,
            ModuleFilter = "Network",
        };
        var report = _timeline.Build(runs, options);
        Assert.All(report.Events, e =>
        {
            Assert.True(e.Severity >= TimelineSeverity.Warning);
            Assert.True(e.Module == null || e.Module.Contains("Network"));
        });
    }

    [Fact]
    public void Build_NoFilter_ReturnsAllEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        // Should have at least InitialScan + ScoreImproved + NewHighScore
        Assert.True(report.Events.Count >= 2);
    }

    [Fact]
    public void Build_EmptyEventTypeFilter_ReturnsAllEvents()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var options = new TimelineOptions { EventTypes = [] };
        var report = _timeline.Build(runs, options);
        // Empty list treated as no filter
        Assert.True(report.Events.Count >= 2);
        Assert.Null(report.EventTypeFilter);
    }

    // ── Summary statistics (8) ────────────────────────────────────────

    [Fact]
    public void Summary_CountsResolvedFindings()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Issue A", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        Assert.Equal(1, report.Summary.FindingsResolved);
    }

    [Fact]
    public void Summary_CountsStillOpenFindings()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Issue A", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 80,
                [MakeFinding(2, "Issue A", "Warning")]),
        };
        var report = _timeline.Build(runs);
        Assert.Equal(1, report.Summary.FindingsStillOpen);
    }

    [Fact]
    public void Summary_CountsImprovementsAndRegressions()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
            MakeRun(3, BaseTime.AddHours(2), 60),
        };
        var report = _timeline.Build(runs);
        Assert.Equal(1, report.Summary.ScoreImprovements);
        Assert.Equal(1, report.Summary.ScoreRegressions);
    }

    [Fact]
    public void Summary_CalculatesNetScoreChange()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 60),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        Assert.Equal(20, report.Summary.NetScoreChange);
    }

    [Fact]
    public void Summary_CalculatesAverageResolutionTime()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
            [
                MakeFinding(1, "A", "Warning"),
                MakeFinding(1, "B", "Warning"),
            ]),
            MakeRun(2, BaseTime.AddDays(2), 90), // both resolved after 2 days
        };
        var report = _timeline.Build(runs);
        Assert.NotNull(report.Summary.AverageTimeToResolve);
        Assert.Equal(TimeSpan.FromDays(2), report.Summary.AverageTimeToResolve.Value);
    }

    [Fact]
    public void Summary_CalculatesFastestResolution()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Fast", "Warning")]),
            MakeRun(2, BaseTime.AddHours(2), 85,
                [MakeFinding(2, "Slow", "Warning")]),
            MakeRun(3, BaseTime.AddHours(3), 90), // Fast resolved at run2 (2h), Slow resolved at run3 (1h)
        };
        var report = _timeline.Build(runs);
        Assert.NotNull(report.Summary.FastestResolution);
        Assert.Equal(TimeSpan.FromHours(1), report.Summary.FastestResolution.Value);
    }

    [Fact]
    public void Summary_CalculatesSlowestResolution()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Fast", "Warning")]),
            MakeRun(2, BaseTime.AddHours(2), 85,
                [MakeFinding(2, "Slow", "Warning")]),
            MakeRun(3, BaseTime.AddHours(3), 90), // Fast resolved at run2 (2h), Slow resolved at run3 (1h)
        };
        var report = _timeline.Build(runs);
        Assert.NotNull(report.Summary.SlowestResolution);
        Assert.Equal(TimeSpan.FromHours(2), report.Summary.SlowestResolution.Value);
    }

    [Fact]
    public void Summary_CountsEventsByType()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        Assert.True(report.Summary.EventsByType.ContainsKey(TimelineEventType.InitialScan));
        Assert.Equal(1, report.Summary.EventsByType[TimelineEventType.InitialScan]);
    }

    // ── Multi-run scenarios (6) ───────────────────────────────────────

    [Fact]
    public void Build_ThreeRuns_CorrectChronologicalOrder()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 60),
            MakeRun(2, BaseTime.AddHours(1), 70),
            MakeRun(3, BaseTime.AddHours(2), 80),
        };
        var report = _timeline.Build(runs);
        for (int i = 1; i < report.Events.Count; i++)
        {
            Assert.True(report.Events[i].Timestamp >= report.Events[i - 1].Timestamp);
        }
    }

    [Fact]
    public void Build_RunsOutOfOrder_SortsChronologically()
    {
        // Pass runs in reverse order (newest first, like GetHistory returns)
        var runs = new List<AuditRunRecord>
        {
            MakeRun(3, BaseTime.AddHours(2), 80),
            MakeRun(1, BaseTime, 60),
            MakeRun(2, BaseTime.AddHours(1), 70),
        };
        var report = _timeline.Build(runs);
        Assert.Equal(TimelineEventType.InitialScan, report.Events[0].EventType);
        Assert.Equal(60, report.Events[0].Score); // first chronologically
    }

    [Fact]
    public void Build_FiveRuns_FindingLifecycle()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddDays(1), 80,
                [MakeFinding(2, "Lifecycle", "Warning")]), // appeared
            MakeRun(3, BaseTime.AddDays(2), 80,
                [MakeFinding(3, "Lifecycle", "Warning")]), // persists
            MakeRun(4, BaseTime.AddDays(3), 80,
                [MakeFinding(4, "Lifecycle", "Warning")]), // persists
            MakeRun(5, BaseTime.AddDays(4), 90), // resolved
        };
        var report = _timeline.Build(runs);
        Assert.Contains(report.Events, e => e.EventType == TimelineEventType.FindingAppeared && e.FindingTitle == "Lifecycle");
        Assert.Contains(report.Events, e => e.EventType == TimelineEventType.FindingResolved && e.FindingTitle == "Lifecycle");
        // Resolution time should be 3 days (appeared day 1, resolved day 4)
        Assert.NotNull(report.Summary.AverageTimeToResolve);
        Assert.Equal(TimeSpan.FromDays(3), report.Summary.AverageTimeToResolve.Value);
    }

    [Fact]
    public void Build_TenRuns_GradualImprovement()
    {
        var runs = Enumerable.Range(1, 10)
            .Select(i => MakeRun(i, BaseTime.AddHours(i), 50 + i * 5))
            .ToList();
        var report = _timeline.Build(runs);
        Assert.Equal(10, report.RunsAnalyzed);
        // Net change: 55 to 100 = +45
        Assert.Equal(45, report.Summary.NetScoreChange);
        // All improvements (9 of them, since first is InitialScan)
        Assert.Equal(9, report.Summary.ScoreImprovements);
        Assert.Equal(0, report.Summary.ScoreRegressions);
    }

    [Fact]
    public void Build_FindingFlapping_TrackedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddDays(1), 80,
                [MakeFinding(2, "Flapper", "Warning")]),       // appears
            MakeRun(3, BaseTime.AddDays(2), 90),                // resolved
            MakeRun(4, BaseTime.AddDays(3), 80,
                [MakeFinding(4, "Flapper", "Warning")]),       // reappears
            MakeRun(5, BaseTime.AddDays(4), 90),                // resolved again
        };
        var report = _timeline.Build(runs);
        var appeared = report.Events.Where(e => e.EventType == TimelineEventType.FindingAppeared && e.FindingTitle == "Flapper").ToList();
        var resolved = report.Events.Where(e => e.EventType == TimelineEventType.FindingResolved && e.FindingTitle == "Flapper").ToList();
        Assert.Equal(2, appeared.Count);
        Assert.Equal(2, resolved.Count);
    }

    [Fact]
    public void Build_MixedEvents_AllTypesPresent()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70,
                [MakeFinding(1, "Crit1", "Critical")],
                [MakeModule(1, "Net", 60)]),
            MakeRun(2, BaseTime.AddHours(1), 85,
                [MakeFinding(2, "NewWarn", "Warning")],
                [MakeModule(2, "Net", 80)]), // +20 module change, criticals cleared
        };
        var report = _timeline.Build(runs);
        var types = report.Events.Select(e => e.EventType).Distinct().ToList();
        Assert.Contains(TimelineEventType.InitialScan, types);
        Assert.Contains(TimelineEventType.ScoreImproved, types);
        Assert.Contains(TimelineEventType.NewHighScore, types);
        Assert.Contains(TimelineEventType.FindingResolved, types);
        Assert.Contains(TimelineEventType.ModuleScoreChanged, types);
        Assert.Contains(TimelineEventType.CriticalsClear, types);
    }

    // ── FormatText (4) ────────────────────────────────────────────────

    [Fact]
    public void FormatText_EmptyReport_ShowsNoEvents()
    {
        var report = new TimelineReport();
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("No events found", text);
    }

    [Fact]
    public void FormatText_WithEvents_ContainsIcons()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("🏁", text); // InitialScan
        Assert.Contains("📈", text); // ScoreImproved
    }

    [Fact]
    public void FormatText_GroupsByDate()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddDays(1), 80),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        // Should contain date separator lines
        Assert.Contains("───", text);
    }

    [Fact]
    public void FormatText_IncludesSummary()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 70),
            MakeRun(2, BaseTime.AddHours(1), 80),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("Summary", text);
        Assert.Contains("Findings:", text);
        Assert.Contains("Score:", text);
    }

    // ── FormatDuration and GetEventIcon (4) ───────────────────────────

    [Fact]
    public void FormatText_LongResolutionTime_ShowsDays()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "LongFix", "Warning")]),
            MakeRun(2, BaseTime.AddDays(5), 90),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("5.0d", text);
    }

    [Fact]
    public void FormatText_ShortResolutionTime_ShowsMinutes()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "QuickFix", "Warning")]),
            MakeRun(2, BaseTime.AddMinutes(30), 90),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("30m", text);
    }

    [Fact]
    public void FormatText_ContainsCriticalIcon()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 90),
            MakeRun(2, BaseTime.AddHours(1), 60,
                [MakeFinding(2, "RCE", "Critical")]),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("🚨", text);
    }

    [Fact]
    public void FormatText_ContainsResolvedIcon()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, BaseTime, 80,
                [MakeFinding(1, "Fix Me", "Warning")]),
            MakeRun(2, BaseTime.AddHours(1), 90),
        };
        var report = _timeline.Build(runs);
        var text = SecurityTimeline.FormatText(report);
        Assert.Contains("✅", text);
    }

    // ── TimelineOptions (4) ───────────────────────────────────────────

    [Fact]
    public void Options_DefaultValues()
    {
        var options = new TimelineOptions();
        Assert.Null(options.MinSeverity);
        Assert.Null(options.ModuleFilter);
        Assert.Null(options.EventTypes);
        Assert.Null(options.MaxEvents);
    }

    [Fact]
    public void Options_CustomMinSeverity()
    {
        var options = new TimelineOptions { MinSeverity = TimelineSeverity.Critical };
        Assert.Equal(TimelineSeverity.Critical, options.MinSeverity);
    }

    [Fact]
    public void Options_CustomModuleFilter()
    {
        var options = new TimelineOptions { ModuleFilter = "Firewall" };
        Assert.Equal("Firewall", options.ModuleFilter);
    }

    [Fact]
    public void Options_CustomMaxEvents()
    {
        var options = new TimelineOptions { MaxEvents = 50 };
        Assert.Equal(50, options.MaxEvents);
    }
}
