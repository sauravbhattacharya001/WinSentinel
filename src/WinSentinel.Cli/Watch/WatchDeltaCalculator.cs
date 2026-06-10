using WinSentinel.Core.Models;

namespace WinSentinel.Cli.Watch;

/// <summary>
/// Pure delta computation between two consecutive <see cref="SecurityReport"/>
/// snapshots produced by <c>winsentinel watch</c>. Lifted out of
/// <c>Program.HandleWatch</c> so the change-detection logic is unit-testable
/// without spinning up an audit run, a console session, or a SQLite history db.
///
/// Scope is deliberately data-only: no logging, no Console.* writes, no clock,
/// no I/O. The watch loop is responsible for cadence, presentation, and side
/// effects; this class is responsible for "what changed?".
/// </summary>
public static class WatchDeltaCalculator
{
    /// <summary>
    /// Severities that count as a "noisy" finding worth reporting in the
    /// watch status line. <see cref="Severity.Info"/> and
    /// <see cref="Severity.Pass"/> deliberately do not — they would dominate
    /// the diff with non-actionable noise.
    /// </summary>
    public static readonly IReadOnlySet<Severity> ActionableSeverities =
        new HashSet<Severity> { Severity.Critical, Severity.Warning };

    /// <summary>
    /// Compute the delta between the previous run (<paramref name="previous"/>)
    /// and the current run (<paramref name="current"/>).
    ///
    /// On the first iteration <paramref name="previous"/> is <c>null</c>; in
    /// that case there is no "new" or "resolved" finding (the entire current
    /// snapshot is just the baseline) and the score change is 0.
    /// </summary>
    /// <param name="previous">Previous run; <c>null</c> for the first run.</param>
    /// <param name="current">Current run; must not be <c>null</c>.</param>
    public static WatchDelta Compute(SecurityReport? previous, SecurityReport current)
    {
        ArgumentNullException.ThrowIfNull(current);

        var currentTitles = ExtractActionableTitles(current);

        if (previous is null)
        {
            // First iteration: every actionable finding is just the baseline,
            // not a "new" finding, and there is nothing to resolve.
            return new WatchDelta(
                NewFindings: Array.Empty<string>(),
                ResolvedFindings: Array.Empty<string>(),
                ScoreChange: 0,
                IsBaseline: true,
                CurrentScore: current.SecurityScore,
                CurrentCritical: current.TotalCritical,
                CurrentWarnings: current.TotalWarnings);
        }

        var previousTitles = ExtractActionableTitles(previous);

        // Stable, deterministic ordering matters for the rendered status line.
        var newFindings = currentTitles
            .Except(previousTitles, StringComparer.Ordinal)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToArray();

        var resolvedFindings = previousTitles
            .Except(currentTitles, StringComparer.Ordinal)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToArray();

        return new WatchDelta(
            NewFindings: newFindings,
            ResolvedFindings: resolvedFindings,
            ScoreChange: current.SecurityScore - previous.SecurityScore,
            IsBaseline: false,
            CurrentScore: current.SecurityScore,
            CurrentCritical: current.TotalCritical,
            CurrentWarnings: current.TotalWarnings);
    }

    /// <summary>
    /// Project a report into the set of finding titles that the watch loop
    /// considers actionable (Critical or Warning). De-duplicates titles —
    /// two modules raising "RDP exposed" should still count as one named
    /// problem in the diff.
    /// </summary>
    public static HashSet<string> ExtractActionableTitles(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var titles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var auditResult in report.Results)
        {
            if (auditResult is null) continue;
            foreach (var finding in auditResult.Findings)
            {
                if (finding is null) continue;
                if (!ActionableSeverities.Contains(finding.Severity)) continue;
                if (string.IsNullOrWhiteSpace(finding.Title)) continue;
                titles.Add(finding.Title);
            }
        }
        return titles;
    }
}

/// <summary>
/// Result of <see cref="WatchDeltaCalculator.Compute"/>. Pure data — safe to
/// unit-test, log, or serialize for telemetry. New/Resolved arrays are sorted
/// in <see cref="StringComparer.Ordinal"/> order so a status line never
/// flickers between equivalent runs.
/// </summary>
public sealed record WatchDelta(
    IReadOnlyList<string> NewFindings,
    IReadOnlyList<string> ResolvedFindings,
    int ScoreChange,
    bool IsBaseline,
    int CurrentScore,
    int CurrentCritical,
    int CurrentWarnings)
{
    /// <summary>True iff there is at least one new finding to alert on.</summary>
    public bool HasNew => NewFindings.Count > 0;

    /// <summary>True iff at least one previously-flagged finding has been resolved.</summary>
    public bool HasResolved => ResolvedFindings.Count > 0;

    /// <summary>True iff <see cref="ScoreChange"/> is positive (score went up).</summary>
    public bool ScoreImproved => ScoreChange > 0;

    /// <summary>True iff <see cref="ScoreChange"/> is negative (score went down).</summary>
    public bool ScoreRegressed => ScoreChange < 0;
}
