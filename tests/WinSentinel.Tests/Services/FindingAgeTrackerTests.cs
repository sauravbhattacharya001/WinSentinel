using WinSentinel.Cli;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class FindingAgeTrackerTests
{
    private readonly FindingAgeTracker _tracker = new();
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static AuditRunRecord MakeRun(long id, DateTimeOffset ts, int score,
        List<FindingRecord>? findings = null)
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
        };
    }

    private static FindingRecord MakeFinding(long runId, string title,
        string severity = "Warning", string module = "Network")
    {
        return new FindingRecord
        {
            RunId = runId,
            Title = title,
            Severity = severity,
            ModuleName = module,
            Description = $"Description for {title}",
        };
    }

    // ── Null/Empty ────────────────────────────────────────────────────

    [Fact]
    public void Analyze_NullRuns_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => _tracker.Analyze(null!));
    }

    [Fact]
    public void Analyze_EmptyRuns_ReturnsEmptyReport()
    {
        var report = _tracker.Analyze([]);
        Assert.Empty(report.Findings);
        Assert.Equal(0, report.Summary.RunsAnalyzed);
        Assert.Equal(0, report.Summary.TotalFindings);
    }

    [Fact]
    public void Analyze_EmptyRuns_HealthGradeIsA()
    {
        var report = _tracker.Analyze([]);
        Assert.Equal("A", report.Summary.HealthGrade);
    }

    // ── Single run ────────────────────────────────────────────────────

    [Fact]
    public void Analyze_SingleRun_NoFindings_ReturnsEmpty()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, T0, 95) };
        var report = _tracker.Analyze(runs);
        Assert.Empty(report.Findings);
        Assert.Equal(1, report.Summary.RunsAnalyzed);
    }

    [Fact]
    public void Analyze_SingleRun_WithFindings_AllClassifiedAsNew()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 75, [
                MakeFinding(1, "SMB Open"),
                MakeFinding(1, "Firewall Off", "Critical", "Firewall"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(2, report.Findings.Count);
        Assert.All(report.Findings, f => Assert.Equal("New", f.Classification));
    }

    [Fact]
    public void Analyze_SingleRun_FindingsAreActive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Open Port")])
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        Assert.True(report.Findings[0].IsActive);
        Assert.Null(report.Findings[0].ResolvedAt);
    }

    [Fact]
    public void Analyze_SingleRun_ConsecutiveRunsIsOne()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Test")])
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Findings[0].ConsecutiveRuns);
        Assert.Equal(1, report.Findings[0].TotalOccurrences);
    }

    [Fact]
    public void Analyze_SingleRun_FirstSeenEqualsLastSeen()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Test")])
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(T0, report.Findings[0].FirstSeen);
        Assert.Equal(T0, report.Findings[0].LastSeen);
    }

    // ── Persistence across runs ────────────────────────────────────

    [Fact]
    public void Analyze_PersistentFinding_TracksAcrossRuns()
    {
        var t1 = T0.AddHours(1);
        var t2 = T0.AddHours(2);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "SMB Open")]),
            MakeRun(2, t1, 80, [MakeFinding(2, "SMB Open")]),
            MakeRun(3, t2, 80, [MakeFinding(3, "SMB Open")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        var f = report.Findings[0];
        Assert.Equal(T0, f.FirstSeen);
        Assert.Equal(t2, f.LastSeen);
        Assert.Equal(3, f.TotalOccurrences);
        Assert.Equal(3, f.ConsecutiveRuns);
        Assert.True(f.IsActive);
    }

    [Fact]
    public void Analyze_PersistentFinding_FrequencyIsOne()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A")]),
            MakeRun(2, T0.AddHours(1), 80, [MakeFinding(2, "A")]),
            MakeRun(3, T0.AddHours(2), 80, [MakeFinding(3, "A")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1.0, report.Findings[0].Frequency);
    }

    [Fact]
    public void Analyze_PersistentFinding_ClassifiedAsChronic()
    {
        // Need >= 90% frequency for Chronic
        var runs = Enumerable.Range(0, 10)
            .Select(i => MakeRun(i + 1, T0.AddHours(i), 80, [MakeFinding(i + 1, "Persistent")]))
            .ToList();
        var report = _tracker.Analyze(runs);
        Assert.Equal("Chronic", report.Findings[0].Classification);
    }

    // ── Resolution ────────────────────────────────────────────────────

    [Fact]
    public void Analyze_ResolvedFinding_MarkedInactive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Gone")]),
            MakeRun(2, T0.AddHours(1), 90), // Finding disappeared
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        Assert.False(report.Findings[0].IsActive);
        Assert.Equal("Resolved", report.Findings[0].Classification);
    }

    [Fact]
    public void Analyze_ResolvedFinding_HasResolvedTimestamp()
    {
        var t1 = T0.AddHours(1);
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Gone")]),
            MakeRun(2, t1, 90),
        };
        var report = _tracker.Analyze(runs);
        Assert.NotNull(report.Findings[0].ResolvedAt);
        Assert.Equal(t1, report.Findings[0].ResolvedAt);
    }

    [Fact]
    public void Analyze_ResolvedFinding_ConsecutiveRunsReset()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Gone")]),
            MakeRun(2, T0.AddHours(1), 90),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(0, report.Findings[0].ConsecutiveRuns);
    }

    // ── Intermittent findings ──────────────────────────────────────

    [Fact]
    public void Analyze_IntermittentFinding_ReappearsMakesActive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Flaky")]),
            MakeRun(2, T0.AddHours(1), 90), // Gone
            MakeRun(3, T0.AddHours(2), 80, [MakeFinding(3, "Flaky")]), // Back
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        Assert.True(report.Findings[0].IsActive);
        Assert.Equal(2, report.Findings[0].TotalOccurrences);
    }

    [Fact]
    public void Analyze_IntermittentFinding_FrequencyCorrect()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Flaky")]),
            MakeRun(2, T0.AddHours(1), 90),
            MakeRun(3, T0.AddHours(2), 80, [MakeFinding(3, "Flaky")]),
            MakeRun(4, T0.AddHours(3), 90),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(0.5, report.Findings[0].Frequency); // 2 out of 4
    }

    [Fact]
    public void Analyze_IntermittentFinding_ClassifiedCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Flaky")]),
            MakeRun(2, T0.AddHours(1), 90),
            MakeRun(3, T0.AddHours(2), 80, [MakeFinding(3, "Flaky")]),
            MakeRun(4, T0.AddHours(3), 90),
            MakeRun(5, T0.AddHours(4), 80, [MakeFinding(5, "Flaky")]),
        };
        var report = _tracker.Analyze(runs);
        // 3/5 = 60% → Recurring
        Assert.Equal("Recurring", report.Findings[0].Classification);
    }

    // ── Pass severity skipping ──────────────────────────────────────

    [Fact]
    public void Analyze_PassFindings_AreSkipped()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 95, [
                MakeFinding(1, "Good Thing", "Pass"),
                MakeFinding(1, "Bad Thing", "Warning"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        Assert.Equal("Bad Thing", report.Findings[0].Title);
    }

    // ── Module + title composite key ────────────────────────────────

    [Fact]
    public void Analyze_SameTitleDifferentModule_TrackedSeparately()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [
                MakeFinding(1, "Open Port", "Warning", "Network"),
                MakeFinding(1, "Open Port", "Warning", "Firewall"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(2, report.Findings.Count);
    }

    [Fact]
    public void Analyze_CaseInsensitiveKey()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "SMB Open", "Warning", "Network")]),
            MakeRun(2, T0.AddHours(1), 80, [
                new FindingRecord { RunId = 2, Title = "smb open", Severity = "Warning", ModuleName = "network", Description = "test" }
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.Findings);
        Assert.Equal(2, report.Findings[0].TotalOccurrences);
    }

    // ── Severity updates ────────────────────────────────────────────

    [Fact]
    public void Analyze_SeverityUpgrade_UsesLatest()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Issue", "Warning")]),
            MakeRun(2, T0.AddHours(1), 70, [MakeFinding(2, "Issue", "Critical")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal("Critical", report.Findings[0].Severity);
    }

    // ── Summary statistics ──────────────────────────────────────────

    [Fact]
    public void Summary_CountsActive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A"), MakeFinding(1, "B")]),
            MakeRun(2, T0.AddHours(1), 85, [MakeFinding(2, "A")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Summary.ActiveFindings);
        Assert.Equal(1, report.Summary.ResolvedFindings);
    }

    [Fact]
    public void Summary_CountsChronic()
    {
        var runs = Enumerable.Range(0, 10)
            .Select(i => MakeRun(i + 1, T0.AddHours(i), 80, [MakeFinding(i + 1, "Always")]))
            .ToList();
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Summary.ChronicFindings);
    }

    [Fact]
    public void Summary_CountsNew()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Fresh")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Summary.NewFindings);
    }

    [Fact]
    public void Summary_MeanTimeToResolve_Calculated()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A"), MakeFinding(1, "B")]),
            MakeRun(2, T0.AddHours(2), 85, [MakeFinding(2, "A")]), // B resolved in 2h
            MakeRun(3, T0.AddHours(6), 90), // A resolved in 6h
        };
        var report = _tracker.Analyze(runs);
        Assert.NotNull(report.Summary.MeanTimeToResolveHours);
        Assert.Equal(4.0, report.Summary.MeanTimeToResolveHours!.Value, 0.01); // (2+6)/2
    }

    [Fact]
    public void Summary_MedianTimeToResolve_Calculated()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A"), MakeFinding(1, "B"), MakeFinding(1, "C")]),
            MakeRun(2, T0.AddHours(1), 82, [MakeFinding(2, "A"), MakeFinding(2, "C")]), // B resolved 1h
            MakeRun(3, T0.AddHours(3), 85, [MakeFinding(3, "A")]), // C resolved 3h
            MakeRun(4, T0.AddHours(10), 90), // A resolved 10h
        };
        var report = _tracker.Analyze(runs);
        Assert.NotNull(report.Summary.MedianTimeToResolveHours);
        Assert.Equal(3.0, report.Summary.MedianTimeToResolveHours!.Value, 0.01); // median of {1,3,10}
    }

    [Fact]
    public void Summary_NoResolutions_MTTRIsNull()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Persistent")]),
            MakeRun(2, T0.AddHours(1), 80, [MakeFinding(2, "Persistent")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Null(report.Summary.MeanTimeToResolveHours);
        Assert.Null(report.Summary.MedianTimeToResolveHours);
    }

    [Fact]
    public void Summary_OldestActiveFinding_Tracked()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Old")]),
            MakeRun(2, T0.AddHours(24), 80, [
                MakeFinding(2, "Old"),
                MakeFinding(2, "New"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal("Old", report.Summary.OldestActiveFindingTitle);
    }

    [Fact]
    public void Summary_ActiveBySeverity_Breakdown()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "A", "Critical"),
                MakeFinding(1, "B", "Warning"),
                MakeFinding(1, "C", "Warning"),
                MakeFinding(1, "D", "Info"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Summary.ActiveBySeverity["Critical"]);
        Assert.Equal(2, report.Summary.ActiveBySeverity["Warning"]);
        Assert.Equal(1, report.Summary.ActiveBySeverity["Info"]);
    }

    [Fact]
    public void Summary_ActiveByModule_Breakdown()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "A", "Warning", "Network"),
                MakeFinding(1, "B", "Warning", "Network"),
                MakeFinding(1, "C", "Warning", "Firewall"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(2, report.Summary.ActiveByModule["Network"]);
        Assert.Equal(1, report.Summary.ActiveByModule["Firewall"]);
    }

    [Fact]
    public void Summary_ActiveByClassification_Breakdown()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Fresh")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(1, report.Summary.ActiveByClassification["New"]);
    }

    // ── Priority score ──────────────────────────────────────────────

    [Fact]
    public void PriorityScore_CriticalHigherThanWarning()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "Crit", "Critical"),
                MakeFinding(1, "Warn", "Warning"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        var crit = report.Findings.First(f => f.Title == "Crit");
        var warn = report.Findings.First(f => f.Title == "Warn");
        Assert.True(crit.PriorityScore > warn.PriorityScore);
    }

    [Fact]
    public void PriorityScore_OlderFindingHigherPriority()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Old")]),
            MakeRun(2, T0.AddDays(7), 80, [
                MakeFinding(2, "Old"),
                MakeFinding(2, "New"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        var old = report.Findings.First(f => f.Title == "Old");
        var newF = report.Findings.First(f => f.Title == "New");
        Assert.True(old.PriorityScore > newF.PriorityScore);
    }

    [Fact]
    public void PriorityScore_IsNonNegative()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Test")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.True(report.Findings[0].PriorityScore >= 0);
    }

    // ── Report views ──────────────────────────────────────────────────

    [Fact]
    public void PriorityQueue_OnlyActive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Active"), MakeFinding(1, "Gone")]),
            MakeRun(2, T0.AddHours(1), 85, [MakeFinding(2, "Active")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.PriorityQueue);
        Assert.Equal("Active", report.PriorityQueue[0].Title);
    }

    [Fact]
    public void PriorityQueue_SortedDescending()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "Warn", "Warning"),
                MakeFinding(1, "Crit", "Critical"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal("Crit", report.PriorityQueue[0].Title);
    }

    [Fact]
    public void ChronicFindings_OnlyHighFrequency()
    {
        var runs = Enumerable.Range(0, 10)
            .Select(i => MakeRun(i + 1, T0.AddHours(i), 80, [MakeFinding(i + 1, "Always")]))
            .ToList();
        // Add one finding that only appears once
        runs[0].Findings.Add(MakeFinding(1, "Once"));
        runs[0].TotalFindings++;
        var report = _tracker.Analyze(runs);
        Assert.Single(report.ChronicFindings);
        Assert.Equal("Always", report.ChronicFindings[0].Title);
    }

    [Fact]
    public void NewFindings_OnlyNewClassification()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.NewFindings);
    }

    [Fact]
    public void ResolvedFindings_SortedByResolvedDate()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [MakeFinding(1, "A"), MakeFinding(1, "B")]),
            MakeRun(2, T0.AddHours(1), 80, [MakeFinding(2, "B")]), // A resolved
            MakeRun(3, T0.AddHours(2), 90), // B resolved
        };
        var report = _tracker.Analyze(runs);
        var resolved = report.ResolvedFindings;
        Assert.Equal(2, resolved.Count);
        // Most recently resolved first
        Assert.Equal("B", resolved[0].Title);
        Assert.Equal("A", resolved[1].Title);
    }

    [Fact]
    public void GetByModule_FiltersCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "Net1", "Warning", "Network"),
                MakeFinding(1, "FW1", "Warning", "Firewall"),
                MakeFinding(1, "Net2", "Warning", "Network"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        var netFindings = report.GetByModule("Network");
        Assert.Equal(2, netFindings.Count);
    }

    [Fact]
    public void GetByModule_CaseInsensitive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "X", "Warning", "Network")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Single(report.GetByModule("network"));
    }

    [Fact]
    public void GetBySeverity_FiltersCorrectly()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [
                MakeFinding(1, "A", "Critical"),
                MakeFinding(1, "B", "Warning"),
                MakeFinding(1, "C", "Critical"),
            ]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(2, report.GetBySeverity("Critical").Count);
    }

    // ── Ordering ────────────────────────────────────────────────────

    [Fact]
    public void Analyze_RunsOrderedChronologically()
    {
        // Provide runs in reverse order — should still work
        var runs = new List<AuditRunRecord>
        {
            MakeRun(3, T0.AddHours(2), 80, [MakeFinding(3, "A")]),
            MakeRun(1, T0, 80, [MakeFinding(1, "A")]),
            MakeRun(2, T0.AddHours(1), 80, [MakeFinding(2, "A")]),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(T0, report.Findings[0].FirstSeen);
        Assert.Equal(3, report.Findings[0].TotalOccurrences);
    }

    // ── Health grade ──────────────────────────────────────────────────

    [Fact]
    public void HealthGrade_AllResolved_GoodGrade()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Fixed")]),
            MakeRun(2, T0.AddHours(1), 95),
        };
        var report = _tracker.Analyze(runs);
        Assert.Contains(report.Summary.HealthGrade, new[] { "A", "B" });
    }

    [Fact]
    public void HealthGrade_ManyChronic_WorsensGrade()
    {
        var findings = Enumerable.Range(0, 5)
            .Select(i => MakeFinding(0, $"Chronic{i}", "Critical"))
            .ToList();
        var runs = Enumerable.Range(0, 10)
            .Select(i =>
            {
                var f = findings.Select(f => new FindingRecord
                {
                    RunId = i + 1, Title = f.Title, Severity = f.Severity,
                    ModuleName = f.ModuleName, Description = f.Description
                }).ToList();
                return MakeRun(i + 1, T0.AddHours(i), 50, f);
            })
            .ToList();
        var report = _tracker.Analyze(runs);
        Assert.Contains(report.Summary.HealthGrade, new[] { "D", "F" });
    }

    // ── AgeText ────────────────────────────────────────────────────

    [Fact]
    public void FindingLifecycle_AgeText_Minutes()
    {
        var lc = new FindingLifecycle
        {
            FirstSeen = DateTimeOffset.UtcNow.AddMinutes(-30),
            LastSeen = DateTimeOffset.UtcNow,
            IsActive = true,
        };
        Assert.Contains("m", lc.AgeText);
    }

    [Fact]
    public void FindingLifecycle_AgeText_Hours()
    {
        var lc = new FindingLifecycle
        {
            FirstSeen = DateTimeOffset.UtcNow.AddHours(-5),
            LastSeen = DateTimeOffset.UtcNow,
            IsActive = true,
        };
        Assert.Contains("h", lc.AgeText);
    }

    [Fact]
    public void FindingLifecycle_AgeText_Days()
    {
        var lc = new FindingLifecycle
        {
            FirstSeen = DateTimeOffset.UtcNow.AddDays(-3),
            LastSeen = DateTimeOffset.UtcNow,
            IsActive = true,
        };
        Assert.Contains("d", lc.AgeText);
    }

    // ── FormatReport ────────────────────────────────────────────────

    [Fact]
    public void FormatReport_NullReport_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => _tracker.FormatReport(null!));
    }

    [Fact]
    public void FormatReport_EmptyReport_ContainsHeader()
    {
        var report = _tracker.Analyze([]);
        var text = _tracker.FormatReport(report);
        Assert.Contains("Finding Age Tracker", text);
    }

    [Fact]
    public void FormatReport_WithFindings_ContainsPriorityQueue()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Test Issue")]),
        };
        var report = _tracker.Analyze(runs);
        var text = _tracker.FormatReport(report);
        Assert.Contains("Priority Queue", text);
        Assert.Contains("Test Issue", text);
    }

    [Fact]
    public void FormatReport_WithChronic_ShowsChronicSection()
    {
        var runs = Enumerable.Range(0, 10)
            .Select(i => MakeRun(i + 1, T0.AddHours(i), 80, [MakeFinding(i + 1, "Persistent")]))
            .ToList();
        var report = _tracker.Analyze(runs);
        var text = _tracker.FormatReport(report);
        Assert.Contains("Chronic Findings", text);
    }

    [Fact]
    public void FormatReport_WithResolved_ShowsResolvedSection()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "Fixed")]),
            MakeRun(2, T0.AddHours(1), 95),
        };
        var report = _tracker.Analyze(runs);
        var text = _tracker.FormatReport(report);
        Assert.Contains("Recently Resolved", text);
        Assert.Contains("Fixed", text);
    }

    [Fact]
    public void FormatReport_SeverityBreakdown_ShowsIcons()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [MakeFinding(1, "Crit", "Critical")]),
        };
        var report = _tracker.Analyze(runs);
        var text = _tracker.FormatReport(report);
        Assert.Contains("🔴", text);
    }

    [Fact]
    public void FormatReport_ModuleBreakdown_Listed()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [MakeFinding(1, "X", "Warning", "Network")]),
        };
        var report = _tracker.Analyze(runs);
        var text = _tracker.FormatReport(report);
        Assert.Contains("Active by Module", text);
        Assert.Contains("Network", text);
    }

    // ── ToDict ──────────────────────────────────────────────────────

    [Fact]
    public void ToDict_NullReport_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => _tracker.ToDict(null!));
    }

    [Fact]
    public void ToDict_HasExpectedKeys()
    {
        var report = _tracker.Analyze([]);
        var dict = _tracker.ToDict(report);
        Assert.Contains("summary", dict.Keys);
        Assert.Contains("priorityQueue", dict.Keys);
        Assert.Contains("chronicFindings", dict.Keys);
        Assert.Contains("newFindings", dict.Keys);
        Assert.Contains("resolvedFindings", dict.Keys);
        Assert.Contains("allFindings", dict.Keys);
    }

    [Fact]
    public void ToDict_SummaryContainsRunsAnalyzed()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, T0, 80, [MakeFinding(1, "X")]) };
        var report = _tracker.Analyze(runs);
        var dict = _tracker.ToDict(report);
        var summary = (Dictionary<string, object?>)dict["summary"]!;
        Assert.Equal(1, summary["runsAnalyzed"]);
    }

    [Fact]
    public void ToDict_FindingContainsExpectedFields()
    {
        var runs = new List<AuditRunRecord> { MakeRun(1, T0, 80, [MakeFinding(1, "TestF")]) };
        var report = _tracker.Analyze(runs);
        var dict = _tracker.ToDict(report);
        var allFindings = (List<Dictionary<string, object?>>)dict["allFindings"]!;
        Assert.Single(allFindings);
        var f = allFindings[0];
        Assert.Contains("title", f.Keys);
        Assert.Contains("moduleName", f.Keys);
        Assert.Contains("severity", f.Keys);
        Assert.Contains("classification", f.Keys);
        Assert.Contains("priorityScore", f.Keys);
        Assert.Contains("ageText", f.Keys);
        Assert.Contains("frequency", f.Keys);
        Assert.Equal("TestF", f["title"]);
    }

    // ── CLI parser ──────────────────────────────────────────────────

    [Fact]
    public void CliParser_Age_DefaultsToReport()
    {
        var opts = CliParser.Parse(["--age"]);
        Assert.Equal(CliCommand.FindingAge, opts.Command);
        Assert.Equal(FindingAgeAction.Report, opts.AgeAction);
    }

    [Fact]
    public void CliParser_Age_Priority()
    {
        var opts = CliParser.Parse(["--age", "priority"]);
        Assert.Equal(FindingAgeAction.Priority, opts.AgeAction);
    }

    [Fact]
    public void CliParser_Age_Chronic()
    {
        var opts = CliParser.Parse(["--age", "chronic"]);
        Assert.Equal(FindingAgeAction.Chronic, opts.AgeAction);
    }

    [Fact]
    public void CliParser_Age_New()
    {
        var opts = CliParser.Parse(["--age", "new"]);
        Assert.Equal(FindingAgeAction.New, opts.AgeAction);
    }

    [Fact]
    public void CliParser_Age_Resolved()
    {
        var opts = CliParser.Parse(["--age", "resolved"]);
        Assert.Equal(FindingAgeAction.Resolved, opts.AgeAction);
    }

    [Fact]
    public void CliParser_Age_InvalidAction_SetsError()
    {
        var opts = CliParser.Parse(["--age", "invalid"]);
        Assert.NotNull(opts.Error);
        Assert.Contains("invalid", opts.Error);
    }

    [Fact]
    public void CliParser_AgeDays_Parsed()
    {
        var opts = CliParser.Parse(["--age", "--age-days", "7"]);
        Assert.Equal(7, opts.AgeDays);
    }

    [Fact]
    public void CliParser_AgeDays_InvalidValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-days", "0"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeDays_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-days"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeSeverity_Parsed()
    {
        var opts = CliParser.Parse(["--age", "--age-severity", "critical"]);
        Assert.Equal("critical", opts.AgeSeverityFilter);
    }

    [Fact]
    public void CliParser_AgeSeverity_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-severity"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeModule_Parsed()
    {
        var opts = CliParser.Parse(["--age", "--age-module", "Firewall"]);
        Assert.Equal("Firewall", opts.AgeModuleFilter);
    }

    [Fact]
    public void CliParser_AgeModule_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-module"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeClass_Parsed()
    {
        var opts = CliParser.Parse(["--age", "--age-class", "chronic"]);
        Assert.Equal("chronic", opts.AgeClassification);
    }

    [Fact]
    public void CliParser_AgeClass_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-class"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeTop_Parsed()
    {
        var opts = CliParser.Parse(["--age", "--age-top", "25"]);
        Assert.Equal(25, opts.AgeTop);
    }

    [Fact]
    public void CliParser_AgeTop_InvalidValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-top", "0"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeTop_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(["--age", "--age-top"]);
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_AgeDefaults()
    {
        var opts = CliParser.Parse(["--age"]);
        Assert.Equal(90, opts.AgeDays);
        Assert.Equal(10, opts.AgeTop);
        Assert.Null(opts.AgeSeverityFilter);
        Assert.Null(opts.AgeModuleFilter);
        Assert.Null(opts.AgeClassification);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    [Fact]
    public void Analyze_ManyRuns_NoStackOverflow()
    {
        var runs = Enumerable.Range(0, 100)
            .Select(i => MakeRun(i + 1, T0.AddMinutes(i * 30), 80, [MakeFinding(i + 1, "Persistent")]))
            .ToList();
        var report = _tracker.Analyze(runs);
        Assert.Equal(100, report.Summary.RunsAnalyzed);
        Assert.Equal(1, report.Summary.TotalFindings);
        Assert.Equal(100, report.Findings[0].TotalOccurrences);
    }

    [Fact]
    public void Analyze_AllFindingsResolved_ZeroActive()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 70, [MakeFinding(1, "A"), MakeFinding(1, "B")]),
            MakeRun(2, T0.AddHours(1), 95),
        };
        var report = _tracker.Analyze(runs);
        Assert.Equal(0, report.Summary.ActiveFindings);
        Assert.Equal(2, report.Summary.ResolvedFindings);
        Assert.Empty(report.PriorityQueue);
    }

    [Fact]
    public void Analyze_SummaryText_AllResolvedMessage()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 80, [MakeFinding(1, "A")]),
            MakeRun(2, T0.AddHours(1), 95),
        };
        var report = _tracker.Analyze(runs);
        Assert.Contains("resolved", report.Summary.SummaryText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_SummaryText_NoFindings()
    {
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, T0, 95),
            MakeRun(2, T0.AddHours(1), 95),
        };
        var report = _tracker.Analyze(runs);
        Assert.Contains("No findings", report.Summary.SummaryText);
    }

    [Fact]
    public void Analyze_TotalRunsAnalyzed_SetOnAll()
    {
        var runs = Enumerable.Range(0, 5)
            .Select(i => MakeRun(i + 1, T0.AddHours(i), 80, [MakeFinding(i + 1, "X")]))
            .ToList();
        var report = _tracker.Analyze(runs);
        Assert.All(report.Findings, f => Assert.Equal(5, f.TotalRunsAnalyzed));
    }

    [Fact]
    public void FindingLifecycle_Age_ResolvedUsesResolvedAt()
    {
        var lc = new FindingLifecycle
        {
            FirstSeen = T0,
            LastSeen = T0.AddHours(2),
            ResolvedAt = T0.AddHours(3),
            IsActive = false,
        };
        Assert.Equal(3, lc.Age.TotalHours, 0.01);
    }

    [Fact]
    public void FindingLifecycle_Frequency_ZeroRuns_ReturnsZero()
    {
        var lc = new FindingLifecycle { TotalRunsAnalyzed = 0, TotalOccurrences = 0 };
        Assert.Equal(0, lc.Frequency);
    }

    [Fact]
    public void FindingAgeSummary_DefaultValues()
    {
        var s = new FindingAgeSummary();
        Assert.Equal(0, s.TotalFindings);
        Assert.Equal(0, s.ActiveFindings);
        Assert.Equal("N/A", s.HealthGrade);
        Assert.Empty(s.SummaryText);
    }
}
