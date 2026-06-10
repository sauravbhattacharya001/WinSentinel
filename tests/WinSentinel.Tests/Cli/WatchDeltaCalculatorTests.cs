// SPDX-License-Identifier: Apache-2.0
using WinSentinel.Cli.Watch;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for <see cref="WatchDeltaCalculator"/>, the pure data layer behind
/// <c>winsentinel watch</c>'s status line. Lifted out of <c>Program.HandleWatch</c>
/// in Day 18 so the change-detection logic can be unit-tested without an
/// audit run, a console session, or a SQLite history db.
///
/// Covers:
/// <list type="bullet">
///   <item>Baseline (first run) emits no New/Resolved.</item>
///   <item>New / resolved sets are diffed correctly.</item>
///   <item>Severity gating ignores Info / Pass.</item>
///   <item>Title de-duplication when two modules raise the same title.</item>
///   <item>Score change sign is current - previous.</item>
///   <item>Stable, deterministic ordering (Ordinal sort) of New/Resolved.</item>
///   <item>Null-tolerance on bad input (null finding, null AuditResult).</item>
///   <item>Whitespace titles are dropped, not counted as findings.</item>
///   <item>Convenience flags (HasNew/HasResolved/ScoreImproved/ScoreRegressed).</item>
/// </list>
/// </summary>
public class WatchDeltaCalculatorTests
{
    // ── Helpers ──────────────────────────────────────────────────────────

    private static Finding F(string title, Severity sev = Severity.Critical) =>
        new() { Title = title, Description = title, Severity = sev };

    private static AuditResult R(string module, params Finding[] findings) =>
        new()
        {
            ModuleName = module,
            Category = module,
            Findings = findings.ToList(),
        };

    private static SecurityReport Report(int score, params AuditResult[] results) =>
        new() { SecurityScore = score, Results = results.ToList() };

    // ── Baseline behavior ────────────────────────────────────────────────

    [Fact]
    public void Compute_WithNullPrevious_FlagsAsBaselineAndZeroDeltas()
    {
        var current = Report(80,
            R("Firewall", F("RDP exposed"), F("Inbound 445 open")),
            R("Defender", F("Tamper protection off", Severity.Warning)));

        var delta = WatchDeltaCalculator.Compute(previous: null, current);

        Assert.True(delta.IsBaseline);
        Assert.Empty(delta.NewFindings);
        Assert.Empty(delta.ResolvedFindings);
        Assert.Equal(0, delta.ScoreChange);
        Assert.Equal(80, delta.CurrentScore);
        Assert.False(delta.HasNew);
        Assert.False(delta.HasResolved);
    }

    [Fact]
    public void Compute_WithNullCurrent_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            WatchDeltaCalculator.Compute(previous: null, current: null!));
    }

    // ── Diff math ────────────────────────────────────────────────────────

    [Fact]
    public void Compute_NewFinding_AppearsOnlyInNew()
    {
        var prev = Report(85, R("Firewall", F("RDP exposed")));
        var curr = Report(70, R("Firewall", F("RDP exposed"), F("SMBv1 enabled")));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.False(delta.IsBaseline);
        Assert.Equal(new[] { "SMBv1 enabled" }, delta.NewFindings);
        Assert.Empty(delta.ResolvedFindings);
        Assert.Equal(-15, delta.ScoreChange);
        Assert.True(delta.HasNew);
        Assert.True(delta.ScoreRegressed);
        Assert.False(delta.ScoreImproved);
    }

    [Fact]
    public void Compute_ResolvedFinding_AppearsOnlyInResolved()
    {
        var prev = Report(70, R("Firewall", F("RDP exposed"), F("SMBv1 enabled")));
        var curr = Report(85, R("Firewall", F("RDP exposed")));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Empty(delta.NewFindings);
        Assert.Equal(new[] { "SMBv1 enabled" }, delta.ResolvedFindings);
        Assert.Equal(15, delta.ScoreChange);
        Assert.True(delta.HasResolved);
        Assert.True(delta.ScoreImproved);
        Assert.False(delta.ScoreRegressed);
    }

    [Fact]
    public void Compute_OverlappingChanges_ReportsBothSides()
    {
        var prev = Report(75, R("Firewall", F("RDP exposed"), F("SMBv1 enabled")));
        var curr = Report(72, R("Firewall", F("RDP exposed"), F("LLMNR on")));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(new[] { "LLMNR on" }, delta.NewFindings);
        Assert.Equal(new[] { "SMBv1 enabled" }, delta.ResolvedFindings);
        Assert.Equal(-3, delta.ScoreChange);
    }

    [Fact]
    public void Compute_NoChange_EmptyDiffs()
    {
        var snapshot = Report(80, R("Firewall", F("RDP exposed")));
        var delta = WatchDeltaCalculator.Compute(snapshot, snapshot);

        Assert.False(delta.IsBaseline);
        Assert.Empty(delta.NewFindings);
        Assert.Empty(delta.ResolvedFindings);
        Assert.Equal(0, delta.ScoreChange);
        Assert.False(delta.ScoreImproved);
        Assert.False(delta.ScoreRegressed);
    }

    // ── Severity gating ──────────────────────────────────────────────────

    [Fact]
    public void Compute_InfoAndPassFindings_AreIgnored()
    {
        // Adding an Info finding should NOT show up as a "new" alert.
        var prev = Report(80, R("Firewall", F("RDP exposed")));
        var curr = Report(80,
            R("Firewall",
                F("RDP exposed"),
                F("Firewall service running", Severity.Pass),
                F("Audit policy collected", Severity.Info)));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Empty(delta.NewFindings);
        Assert.Empty(delta.ResolvedFindings);
    }

    [Fact]
    public void Compute_OnlyCriticalAndWarning_AreActionable()
    {
        var prev = Report(80);
        var curr = Report(80,
            R("Firewall", F("Critical issue", Severity.Critical)),
            R("Defender", F("Warning issue", Severity.Warning)),
            R("Network", F("Info bit", Severity.Info)),
            R("System", F("Pass thing", Severity.Pass)));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(2, delta.NewFindings.Count);
        Assert.Contains("Critical issue", delta.NewFindings);
        Assert.Contains("Warning issue", delta.NewFindings);
        Assert.DoesNotContain("Info bit", delta.NewFindings);
        Assert.DoesNotContain("Pass thing", delta.NewFindings);
    }

    [Fact]
    public void ActionableSeverities_ContainsExactlyCriticalAndWarning()
    {
        Assert.Equal(2, WatchDeltaCalculator.ActionableSeverities.Count);
        Assert.Contains(Severity.Critical, WatchDeltaCalculator.ActionableSeverities);
        Assert.Contains(Severity.Warning, WatchDeltaCalculator.ActionableSeverities);
        Assert.DoesNotContain(Severity.Info, WatchDeltaCalculator.ActionableSeverities);
        Assert.DoesNotContain(Severity.Pass, WatchDeltaCalculator.ActionableSeverities);
    }

    // ── De-duplication ───────────────────────────────────────────────────

    [Fact]
    public void Compute_DuplicateTitlesAcrossModules_AreDeduplicated()
    {
        // Two modules raising the "Tamper protection off" finding shouldn't
        // double-count in the diff.
        var prev = Report(80);
        var curr = Report(80,
            R("Defender", F("Tamper protection off", Severity.Warning)),
            R("FleetGuard", F("Tamper protection off", Severity.Warning)));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Single(delta.NewFindings);
        Assert.Equal("Tamper protection off", delta.NewFindings[0]);
    }

    [Fact]
    public void ExtractActionableTitles_DeduplicatesAndIgnoresNoise()
    {
        var report = Report(80,
            R("A", F("Same"), F("Same"), F("Different")),
            R("B", F("Different"), F("Info-only", Severity.Info)));

        var titles = WatchDeltaCalculator.ExtractActionableTitles(report);

        Assert.Equal(2, titles.Count);
        Assert.Contains("Same", titles);
        Assert.Contains("Different", titles);
    }

    // ── Determinism ──────────────────────────────────────────────────────

    [Fact]
    public void Compute_NewFindings_AreSortedOrdinal()
    {
        var prev = Report(80);
        var curr = Report(70,
            R("X",
                F("Zeta finding"),
                F("Alpha finding"),
                F("Beta finding")));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(new[] { "Alpha finding", "Beta finding", "Zeta finding" },
                     delta.NewFindings);
    }

    [Fact]
    public void Compute_ResolvedFindings_AreSortedOrdinal()
    {
        var prev = Report(60,
            R("X",
                F("Charlie"),
                F("Alpha"),
                F("Bravo")));
        var curr = Report(80, R("X"));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(new[] { "Alpha", "Bravo", "Charlie" }, delta.ResolvedFindings);
    }

    // ── Null and whitespace tolerance ────────────────────────────────────

    [Fact]
    public void ExtractActionableTitles_WhitespaceTitle_IsDropped()
    {
        var report = Report(80,
            R("X",
                F(""),
                F("   "),
                F("Real")));

        var titles = WatchDeltaCalculator.ExtractActionableTitles(report);

        Assert.Single(titles);
        Assert.Contains("Real", titles);
    }

    [Fact]
    public void Compute_AuditResultWithNoFindings_DoesNotCrash()
    {
        var prev = Report(80);
        var curr = Report(80, R("Empty"), R("AlsoEmpty"));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Empty(delta.NewFindings);
        Assert.Empty(delta.ResolvedFindings);
    }

    // ── Score-change sign / convenience flags ────────────────────────────

    [Fact]
    public void Compute_LargeRegression_SignAndFlagsCorrect()
    {
        var prev = Report(95);
        var curr = Report(40);

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(-55, delta.ScoreChange);
        Assert.True(delta.ScoreRegressed);
        Assert.False(delta.ScoreImproved);
    }

    [Fact]
    public void Compute_LargeImprovement_SignAndFlagsCorrect()
    {
        var prev = Report(40);
        var curr = Report(95);

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(55, delta.ScoreChange);
        Assert.True(delta.ScoreImproved);
        Assert.False(delta.ScoreRegressed);
    }

    [Fact]
    public void Compute_PassesThroughCurrentTotals()
    {
        var prev = Report(80);
        var curr = Report(60,
            R("A", F("c1"), F("c2"), F("w1", Severity.Warning)));

        var delta = WatchDeltaCalculator.Compute(prev, curr);

        Assert.Equal(60, delta.CurrentScore);
        Assert.Equal(2, delta.CurrentCritical);
        Assert.Equal(1, delta.CurrentWarnings);
    }

    // ── Realistic multi-run sequence ─────────────────────────────────────

    [Fact]
    public void Compute_AcrossThreeRuns_DiffsAlwaysComparedToPrevious()
    {
        // Run 1: baseline (RDP exposed)
        // Run 2: SMBv1 added (new), RDP still there (no change)
        // Run 3: RDP fixed (resolved), SMBv1 still there (no change)
        var run1 = Report(85, R("Firewall", F("RDP exposed")));
        var run2 = Report(70, R("Firewall", F("RDP exposed"), F("SMBv1 enabled")));
        var run3 = Report(78, R("Firewall", F("SMBv1 enabled")));

        var d1 = WatchDeltaCalculator.Compute(null, run1);
        var d2 = WatchDeltaCalculator.Compute(run1, run2);
        var d3 = WatchDeltaCalculator.Compute(run2, run3);

        Assert.True(d1.IsBaseline);
        Assert.Empty(d1.NewFindings);

        Assert.Equal(new[] { "SMBv1 enabled" }, d2.NewFindings);
        Assert.Empty(d2.ResolvedFindings);
        Assert.Equal(-15, d2.ScoreChange);

        Assert.Empty(d3.NewFindings);
        Assert.Equal(new[] { "RDP exposed" }, d3.ResolvedFindings);
        Assert.Equal(8, d3.ScoreChange);
    }
}
