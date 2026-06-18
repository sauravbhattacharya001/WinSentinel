using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="ComplianceTrendTracker"/> — multi-snapshot compliance
/// trend analysis (direction, control transitions, persistent gaps).
/// </summary>
public class ComplianceTrendTrackerTests
{
    private readonly ComplianceTrendTracker _tracker = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport ReportAt(DateTimeOffset when, params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "AccountAudit",
            Category = findings.FirstOrDefault()?.Category ?? "Accounts",
            Findings = findings.ToList()
        };
        return new SecurityReport
        {
            SecurityScore = 50,
            GeneratedAt = when,
            Results = new List<AuditResult> { result }
        };
    }

    private static SecurityReport EmptyReportAt(DateTimeOffset when) => new()
    {
        SecurityScore = 100,
        GeneratedAt = when,
        Results = new List<AuditResult>()
    };

    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Empty / insufficient input ───────────────────────────────────

    [Fact]
    public void Analyze_NullSnapshots_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _tracker.Analyze(null!));
    }

    [Fact]
    public void Analyze_EmptySnapshots_Insufficient()
    {
        var report = _tracker.Analyze(new List<SecurityReport>());
        Assert.Equal(0, report.SnapshotCount);
        Assert.Equal(ComplianceTrendTracker.TrendDirection.Insufficient, report.OverallDirection);
    }

    [Fact]
    public void Analyze_SingleSnapshot_DirectionInsufficient()
    {
        var report = _tracker.Analyze(new[] { EmptyReportAt(T0) });
        Assert.Equal(1, report.SnapshotCount);
        Assert.Equal(ComplianceTrendTracker.TrendDirection.Insufficient, report.OverallDirection);
        // No pair of runs => no transitions.
        Assert.Empty(report.RecentTransitions);
    }

    // ── Regression bug: Partial -> NotAssessed is NOT an improvement ──

    [Fact]
    public void Analyze_PartialToNotAssessed_IsNotCountedAsImprovement()
    {
        // Older snapshot: a Warning finding makes the password control Partial.
        var older = ReportAt(T0,
            Finding.Warning("Weak password length", "Minimum password length is only 6", "Accounts"));
        // Newer snapshot: the finding is gone entirely -> control becomes NotAssessed
        // (no matching finding). This is a LOSS of assessment signal, not progress.
        var newer = EmptyReportAt(T0.AddDays(1));

        var report = _tracker.Analyze(new[] { older, newer });

        var transition = Assert.Single(
            report.RecentTransitions.Where(t =>
                t.ControlId == "CIS-1.1" && t.PreviousStatus == "Partial" && t.NewStatus == "NotAssessed"));

        Assert.False(transition.IsImprovement,
            "Partial -> NotAssessed loses assessment coverage and must not be flagged as an improvement.");

        // No transition INTO NotAssessed may ever be an improvement, in any framework.
        Assert.All(report.RecentTransitions.Where(t => t.NewStatus == "NotAssessed"),
            t => Assert.False(t.IsImprovement));

        // And it must be tallied as a regression in the summary, not an improvement.
        Assert.Contains("regression", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_FailToNotAssessed_IsNotImprovement()
    {
        // Critical finding -> Fail, then finding disappears -> NotAssessed.
        var older = ReportAt(T0,
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));
        var newer = EmptyReportAt(T0.AddDays(1));

        var report = _tracker.Analyze(new[] { older, newer });

        var transition = Assert.Single(
            report.RecentTransitions.Where(t =>
                t.ControlId == "CIS-1.1" && t.PreviousStatus == "Fail" && t.NewStatus == "NotAssessed"));

        Assert.False(transition.IsImprovement,
            "Fail -> NotAssessed is a loss of signal, not a fix.");
    }

    // ── Genuine improvement still detected ───────────────────────────

    [Fact]
    public void Analyze_FailToPass_IsImprovement()
    {
        var older = ReportAt(T0,
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));
        var newer = ReportAt(T0.AddDays(1),
            Finding.Pass("Password policy enforced", "Strong password complexity enabled", "Accounts"));

        var report = _tracker.Analyze(new[] { older, newer });

        var transition = Assert.Single(
            report.RecentTransitions.Where(t => t.ControlId == "CIS-1.1" && t.PreviousStatus == "Fail" && t.NewStatus == "Pass"));
        Assert.True(transition.IsImprovement, "Fail -> Pass must be an improvement.");
    }

    [Fact]
    public void Analyze_NotAssessedToPartial_IsImprovement()
    {
        // Regaining assessment with a partial pass is forward progress.
        var older = EmptyReportAt(T0);
        var newer = ReportAt(T0.AddDays(1),
            Finding.Warning("Weak password length", "Minimum password length is only 6", "Accounts"));

        var report = _tracker.Analyze(new[] { older, newer });

        var transition = Assert.Single(
            report.RecentTransitions.Where(t =>
                t.ControlId == "CIS-1.1" && t.PreviousStatus == "NotAssessed" && t.NewStatus == "Partial"));
        Assert.True(transition.IsImprovement, "NotAssessed -> Partial regains coverage and is an improvement.");
    }

    // ── Snapshots are sorted chronologically regardless of input order ─

    [Fact]
    public void Analyze_OutOfOrderSnapshots_SortedByTimestamp()
    {
        var early = ReportAt(T0,
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));
        var late = ReportAt(T0.AddDays(2),
            Finding.Pass("Password policy enforced", "Strong password complexity enabled", "Accounts"));

        // Feed newest-first; tracker must sort so the transition reads Fail -> Pass.
        var report = _tracker.Analyze(new[] { late, early });

        Assert.Equal(2, report.SnapshotCount);
        Assert.True(report.TimeSpan >= TimeSpan.FromDays(2) - TimeSpan.FromSeconds(1));
        var transition = Assert.Single(
            report.RecentTransitions.Where(t => t.ControlId == "CIS-1.1"));
        Assert.Equal("Fail", transition.PreviousStatus);
        Assert.Equal("Pass", transition.NewStatus);
        Assert.True(transition.IsImprovement);
    }

    // ── Persistent gaps: failing across all runs ─────────────────────

    [Fact]
    public void Analyze_PersistentFailure_ListedAsGap()
    {
        var s1 = ReportAt(T0,
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));
        var s2 = ReportAt(T0.AddDays(1),
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));
        var s3 = ReportAt(T0.AddDays(2),
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));

        var report = _tracker.Analyze(new[] { s1, s2, s3 });

        Assert.Contains(report.PersistentGaps,
            g => g.ControlId == "CIS-1.1" && g.FailingRunCount == 3);
    }
}
