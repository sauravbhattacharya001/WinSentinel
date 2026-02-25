using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Reconstructs a chronological security event timeline from audit history.
/// Analyzes sequential audit runs to detect when findings appeared/resolved,
/// when scores changed, and when significant security events occurred.
/// </summary>
public class SecurityTimeline
{
    /// <summary>
    /// Build a timeline from a list of audit run records.
    /// Records should include findings (via GetRunDetails).
    /// </summary>
    /// <param name="runs">Audit runs ordered newest-first (as from GetHistory/GetRecentRuns).</param>
    /// <param name="options">Optional filtering/configuration.</param>
    public TimelineReport Build(List<AuditRunRecord> runs, TimelineOptions? options = null)
    {
        options ??= new TimelineOptions();
        var report = new TimelineReport
        {
            MinSeverity = options.MinSeverity,
            ModuleFilter = options.ModuleFilter,
            EventTypeFilter = options.EventTypes?.Count > 0 ? options.EventTypes : null,
        };

        if (runs.Count == 0) return report;

        // Work in chronological order
        var chronological = runs.OrderBy(r => r.Timestamp).ToList();
        report.RunsAnalyzed = chronological.Count;
        report.StartDate = chronological.First().Timestamp;
        report.EndDate = chronological.Last().Timestamp;

        var events = new List<TimelineEvent>();

        // Track state across runs
        int bestScore = int.MinValue;
        int worstScore = int.MaxValue;
        HashSet<string> previousFindings = new();  // finding titles from previous run
        Dictionary<string, string> previousSeverities = new();  // finding → severity
        bool hadCriticals = false;

        // Track finding lifetimes for resolution stats
        Dictionary<string, DateTimeOffset> findingFirstSeen = new();
        List<TimeSpan> resolutionTimes = new();

        for (int i = 0; i < chronological.Count; i++)
        {
            var run = chronological[i];
            var currentFindings = new HashSet<string>(run.Findings.Select(f => f.Title));
            var currentSeverities = run.Findings.ToDictionary(f => f.Title, f => f.Severity, StringComparer.OrdinalIgnoreCase);

            if (i == 0)
            {
                // First scan
                events.Add(new TimelineEvent
                {
                    Timestamp = run.Timestamp,
                    RunId = run.Id,
                    EventType = TimelineEventType.InitialScan,
                    Severity = TimelineSeverity.Info,
                    Title = "Initial Security Scan",
                    Description = $"First audit recorded. Score: {run.OverallScore}/100 ({run.Grade}). " +
                                  $"{run.CriticalCount} critical, {run.WarningCount} warnings.",
                    Score = run.OverallScore,
                });
                bestScore = run.OverallScore;
                worstScore = run.OverallScore;
                hadCriticals = run.CriticalCount > 0;

                // Track all initial findings
                foreach (var f in run.Findings)
                    findingFirstSeen[f.Title] = run.Timestamp;
            }
            else
            {
                var prevRun = chronological[i - 1];

                // Score changes
                int scoreDelta = run.OverallScore - prevRun.OverallScore;
                if (scoreDelta > 0)
                {
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.ScoreImproved,
                        Severity = scoreDelta >= 10 ? TimelineSeverity.Notice : TimelineSeverity.Info,
                        Title = $"Score Improved +{scoreDelta}",
                        Description = $"Security score improved from {prevRun.OverallScore} to {run.OverallScore} ({run.Grade}).",
                        Score = run.OverallScore,
                        PreviousScore = prevRun.OverallScore,
                        ScoreDelta = scoreDelta,
                    });
                }
                else if (scoreDelta < 0)
                {
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.ScoreRegressed,
                        Severity = scoreDelta <= -10 ? TimelineSeverity.Warning : TimelineSeverity.Notice,
                        Title = $"Score Regressed {scoreDelta}",
                        Description = $"Security score dropped from {prevRun.OverallScore} to {run.OverallScore} ({run.Grade}).",
                        Score = run.OverallScore,
                        PreviousScore = prevRun.OverallScore,
                        ScoreDelta = scoreDelta,
                    });
                }

                // New all-time high/low
                if (run.OverallScore > bestScore)
                {
                    bestScore = run.OverallScore;
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.NewHighScore,
                        Severity = TimelineSeverity.Notice,
                        Title = $"New High Score: {run.OverallScore}",
                        Description = $"New all-time best security score: {run.OverallScore}/100 ({run.Grade}).",
                        Score = run.OverallScore,
                    });
                }
                if (run.OverallScore < worstScore)
                {
                    worstScore = run.OverallScore;
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.NewLowScore,
                        Severity = TimelineSeverity.Warning,
                        Title = $"New Low Score: {run.OverallScore}",
                        Description = $"New all-time worst security score: {run.OverallScore}/100 ({run.Grade}).",
                        Score = run.OverallScore,
                    });
                }

                // Module score changes (significant = ±10 points)
                if (prevRun.ModuleScores.Count > 0 && run.ModuleScores.Count > 0)
                {
                    var prevModules = prevRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);
                    foreach (var mod in run.ModuleScores)
                    {
                        if (prevModules.TryGetValue(mod.ModuleName, out var prevModScore))
                        {
                            var modDelta = mod.Score - prevModScore;
                            if (Math.Abs(modDelta) >= 10)
                            {
                                events.Add(new TimelineEvent
                                {
                                    Timestamp = run.Timestamp,
                                    RunId = run.Id,
                                    EventType = TimelineEventType.ModuleScoreChanged,
                                    Severity = modDelta < -15 ? TimelineSeverity.Warning : TimelineSeverity.Info,
                                    Title = $"{mod.ModuleName}: {(modDelta > 0 ? "+" : "")}{modDelta}",
                                    Description = $"{mod.ModuleName} score changed from {prevModScore} to {mod.Score} ({(modDelta > 0 ? "improvement" : "regression")}).",
                                    Module = mod.ModuleName,
                                    Score = mod.Score,
                                    PreviousScore = prevModScore,
                                    ScoreDelta = modDelta,
                                });
                            }
                        }
                    }
                }

                // New findings
                var newFindings = currentFindings.Except(previousFindings).ToList();
                foreach (var title in newFindings)
                {
                    var finding = run.Findings.First(f => f.Title == title);
                    var isCritical = finding.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase);

                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = isCritical ? TimelineEventType.CriticalAlert : TimelineEventType.FindingAppeared,
                        Severity = isCritical ? TimelineSeverity.Critical :
                                   finding.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase) ? TimelineSeverity.Warning : TimelineSeverity.Info,
                        Title = $"New: {finding.Title}",
                        Description = $"[{finding.Severity}] {finding.Description}",
                        Module = finding.ModuleName,
                        FindingTitle = finding.Title,
                    });
                    findingFirstSeen.TryAdd(title, run.Timestamp);
                }

                // Resolved findings
                var resolved = previousFindings.Except(currentFindings).ToList();
                foreach (var title in resolved)
                {
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.FindingResolved,
                        Severity = TimelineSeverity.Notice,
                        Title = $"Resolved: {title}",
                        Description = $"Finding '{title}' is no longer present.",
                        FindingTitle = title,
                    });

                    // Calculate resolution time
                    if (findingFirstSeen.TryGetValue(title, out var firstSeen))
                    {
                        resolutionTimes.Add(run.Timestamp - firstSeen);
                        findingFirstSeen.Remove(title);
                    }
                }

                // Severity changes for persistent findings
                var persistent = currentFindings.Intersect(previousFindings);
                foreach (var title in persistent)
                {
                    if (currentSeverities.TryGetValue(title, out var curSev) &&
                        previousSeverities.TryGetValue(title, out var prevSev) &&
                        !curSev.Equals(prevSev, StringComparison.OrdinalIgnoreCase))
                    {
                        events.Add(new TimelineEvent
                        {
                            Timestamp = run.Timestamp,
                            RunId = run.Id,
                            EventType = TimelineEventType.SeverityChanged,
                            Severity = curSev.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? TimelineSeverity.Warning : TimelineSeverity.Info,
                            Title = $"{title}: {prevSev} → {curSev}",
                            Description = $"Finding severity changed from {prevSev} to {curSev}.",
                            FindingTitle = title,
                        });
                    }
                }

                // Criticals clear
                bool hasCriticals = run.CriticalCount > 0;
                if (hadCriticals && !hasCriticals)
                {
                    events.Add(new TimelineEvent
                    {
                        Timestamp = run.Timestamp,
                        RunId = run.Id,
                        EventType = TimelineEventType.CriticalsClear,
                        Severity = TimelineSeverity.Notice,
                        Title = "All Critical Issues Resolved",
                        Description = "No critical findings remain. Security posture significantly improved.",
                        Score = run.OverallScore,
                    });
                }
                hadCriticals = hasCriticals;
            }

            // Update state for next iteration
            previousFindings = currentFindings;
            previousSeverities = currentSeverities;
        }

        // Apply filters
        if (options.MinSeverity.HasValue)
            events = events.Where(e => e.Severity >= options.MinSeverity.Value).ToList();
        if (!string.IsNullOrEmpty(options.ModuleFilter))
            events = events.Where(e => e.Module == null || e.Module.Contains(options.ModuleFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        if (options.EventTypes?.Count > 0)
            events = events.Where(e => options.EventTypes.Contains(e.EventType)).ToList();
        if (options.MaxEvents.HasValue && events.Count > options.MaxEvents.Value)
            events = events.TakeLast(options.MaxEvents.Value).ToList();

        report.Events = events;

        // Build summary
        report.Summary = BuildSummary(events, resolutionTimes, findingFirstSeen, chronological);

        return report;
    }

    private static TimelineSummary BuildSummary(
        List<TimelineEvent> events,
        List<TimeSpan> resolutionTimes,
        Dictionary<string, DateTimeOffset> stillOpenFindings,
        List<AuditRunRecord> runs)
    {
        var summary = new TimelineSummary
        {
            TotalEvents = events.Count,
            FindingsResolved = events.Count(e => e.EventType == TimelineEventType.FindingResolved),
            FindingsStillOpen = stillOpenFindings.Count,
            ScoreImprovements = events.Count(e => e.EventType == TimelineEventType.ScoreImproved),
            ScoreRegressions = events.Count(e => e.EventType == TimelineEventType.ScoreRegressed),
            CriticalAlerts = events.Count(e => e.EventType == TimelineEventType.CriticalAlert),
        };

        // Net score change
        if (runs.Count >= 2)
            summary.NetScoreChange = runs.Last().OverallScore - runs.First().OverallScore;

        // Resolution time stats
        if (resolutionTimes.Count > 0)
        {
            var sorted = resolutionTimes.OrderBy(t => t).ToList();
            summary.AverageTimeToResolve = TimeSpan.FromTicks((long)sorted.Average(t => t.Ticks));
            summary.FastestResolution = sorted.First();
            summary.SlowestResolution = sorted.Last();
        }

        // Events by type
        summary.EventsByType = events
            .GroupBy(e => e.EventType)
            .ToDictionary(g => g.Key, g => g.Count());

        return summary;
    }

    /// <summary>
    /// Format the timeline as a human-readable text report.
    /// </summary>
    public static string FormatText(TimelineReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("══════════════════════════════════════════════════");
        sb.AppendLine("          Security Event Timeline");
        sb.AppendLine("══════════════════════════════════════════════════");
        sb.AppendLine();

        if (report.Events.Count == 0)
        {
            sb.AppendLine("  No events found for the specified criteria.");
            return sb.ToString();
        }

        // Header stats
        sb.AppendLine($"  Period: {report.StartDate?.ToLocalTime():MMM dd, yyyy} — {report.EndDate?.ToLocalTime():MMM dd, yyyy}");
        sb.AppendLine($"  Runs analyzed: {report.RunsAnalyzed}");
        sb.AppendLine($"  Events: {report.Summary.TotalEvents}");
        sb.AppendLine();

        // Group events by date
        var byDate = report.Events
            .GroupBy(e => e.Timestamp.ToLocalTime().Date)
            .OrderBy(g => g.Key);

        foreach (var group in byDate)
        {
            sb.AppendLine($"─── {group.Key:ddd, MMM dd yyyy} ───────────────────────");
            foreach (var evt in group.OrderBy(e => e.Timestamp))
            {
                var icon = GetEventIcon(evt.EventType);
                var sevTag = evt.Severity >= TimelineSeverity.Warning ? $" [{evt.Severity}]" : "";
                var time = evt.Timestamp.ToLocalTime().ToString("HH:mm");
                sb.AppendLine($"  {time}  {icon}  {evt.Title}{sevTag}");
                if (!string.IsNullOrEmpty(evt.Description) && evt.Severity >= TimelineSeverity.Notice)
                    sb.AppendLine($"         {evt.Description}");
            }
            sb.AppendLine();
        }

        // Summary section
        var s = report.Summary;
        sb.AppendLine("── Summary ──────────────────────────────────────");
        sb.AppendLine($"  Findings: {s.FindingsResolved} resolved, {s.FindingsStillOpen} still open");
        sb.AppendLine($"  Score:    {s.ScoreImprovements} improvements, {s.ScoreRegressions} regressions (net: {(s.NetScoreChange >= 0 ? "+" : "")}{s.NetScoreChange})");
        if (s.CriticalAlerts > 0)
            sb.AppendLine($"  Alerts:   {s.CriticalAlerts} critical alerts");
        if (s.AverageTimeToResolve.HasValue)
            sb.AppendLine($"  MTTR:     {FormatDuration(s.AverageTimeToResolve.Value)} avg ({FormatDuration(s.FastestResolution!.Value)} fastest, {FormatDuration(s.SlowestResolution!.Value)} slowest)");

        return sb.ToString();
    }

    private static string GetEventIcon(TimelineEventType type) => type switch
    {
        TimelineEventType.FindingAppeared => "🔴",
        TimelineEventType.FindingResolved => "✅",
        TimelineEventType.SeverityChanged => "🔄",
        TimelineEventType.ScoreImproved => "📈",
        TimelineEventType.ScoreRegressed => "📉",
        TimelineEventType.ModuleScoreChanged => "📊",
        TimelineEventType.InitialScan => "🏁",
        TimelineEventType.NewHighScore => "🏆",
        TimelineEventType.NewLowScore => "⚠️",
        TimelineEventType.CriticalAlert => "🚨",
        TimelineEventType.CriticalsClear => "🎉",
        _ => "•",
    };

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalDays >= 1) return $"{ts.TotalDays:F1}d";
        if (ts.TotalHours >= 1) return $"{ts.TotalHours:F1}h";
        return $"{ts.TotalMinutes:F0}m";
    }
}

/// <summary>
/// Configuration options for timeline generation.
/// </summary>
public class TimelineOptions
{
    /// <summary>Only include events at or above this severity.</summary>
    public TimelineSeverity? MinSeverity { get; set; }

    /// <summary>Filter to events from a specific module.</summary>
    public string? ModuleFilter { get; set; }

    /// <summary>Filter to specific event types.</summary>
    public List<TimelineEventType>? EventTypes { get; set; }

    /// <summary>Maximum number of events to return (most recent).</summary>
    public int? MaxEvents { get; set; }
}
