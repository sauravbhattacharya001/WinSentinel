using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a human-readable security changelog from audit history.
/// Each entry describes what changed between consecutive audit runs:
/// score movements, findings resolved/introduced, grade transitions,
/// and notable milestones (streaks, all-clear, regressions).
/// </summary>
public class SecurityChangelogService
{
    private readonly AuditHistoryService _history;

    public SecurityChangelogService(AuditHistoryService history)
    {
        _history = history;
    }

    /// <summary>
    /// Generate a changelog covering the specified number of days.
    /// </summary>
    public ChangelogReport Generate(int days = 30, string? moduleFilter = null)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count == 0)
            return new ChangelogReport { Period = days };

        // Runs come newest-first; we need oldest-first for chronological processing
        var chronological = runs.OrderBy(r => r.Timestamp).ToList();

        var report = new ChangelogReport
        {
            Period = days,
            TotalScans = chronological.Count,
            FirstScan = chronological[0].Timestamp,
            LastScan = chronological[^1].Timestamp,
            StartScore = chronological[0].OverallScore,
            EndScore = chronological[^1].OverallScore,
            StartGrade = chronological[0].Grade,
            EndGrade = chronological[^1].Grade
        };

        // Load detailed findings for each run to detect new/resolved findings
        var runDetails = new Dictionary<long, AuditRunRecord>();
        foreach (var run in chronological)
        {
            var detail = _history.GetRunDetails(run.Id);
            if (detail != null)
                runDetails[run.Id] = detail;
        }

        // Generate entries by comparing consecutive runs
        for (int i = 1; i < chronological.Count; i++)
        {
            var prev = chronological[i - 1];
            var curr = chronological[i];

            var entry = BuildEntry(prev, curr, runDetails, moduleFilter);
            if (entry.Events.Count > 0)
                report.Entries.Add(entry);
        }

        // Detect milestones
        report.Milestones = DetectMilestones(chronological);

        // Summary stats
        report.NetScoreChange = report.EndScore - report.StartScore;
        report.BestScore = chronological.Max(r => r.OverallScore);
        report.WorstScore = chronological.Min(r => r.OverallScore);

        var improvements = 0;
        var regressions = 0;
        for (int i = 1; i < chronological.Count; i++)
        {
            if (chronological[i].OverallScore > chronological[i - 1].OverallScore)
                improvements++;
            else if (chronological[i].OverallScore < chronological[i - 1].OverallScore)
                regressions++;
        }
        report.ImprovementCount = improvements;
        report.RegressionCount = regressions;

        return report;
    }

    private ChangelogEntry BuildEntry(
        AuditRunRecord prev, AuditRunRecord curr,
        Dictionary<long, AuditRunRecord> details,
        string? moduleFilter)
    {
        var entry = new ChangelogEntry
        {
            Timestamp = curr.Timestamp,
            PreviousScore = prev.OverallScore,
            CurrentScore = curr.OverallScore,
            PreviousGrade = prev.Grade,
            CurrentGrade = curr.Grade,
            ScoreChange = curr.OverallScore - prev.OverallScore
        };

        // Score change event
        if (entry.ScoreChange != 0)
        {
            var direction = entry.ScoreChange > 0 ? "improved" : "regressed";
            var icon = entry.ScoreChange > 0 ? "📈" : "📉";
            entry.Events.Add(new ChangelogEvent
            {
                Type = entry.ScoreChange > 0 ? ChangelogEventType.Improvement : ChangelogEventType.Regression,
                Icon = icon,
                Summary = $"Score {direction} {prev.OverallScore} → {curr.OverallScore} ({(entry.ScoreChange > 0 ? "+" : "")}{entry.ScoreChange})"
            });
        }

        // Grade change
        if (prev.Grade != curr.Grade)
        {
            var better = IsGradeBetter(curr.Grade, prev.Grade);
            entry.Events.Add(new ChangelogEvent
            {
                Type = better ? ChangelogEventType.GradeUp : ChangelogEventType.GradeDown,
                Icon = better ? "⭐" : "⚠️",
                Summary = $"Grade changed {prev.Grade} → {curr.Grade}"
            });
        }

        // Critical findings change
        var critDelta = curr.CriticalCount - prev.CriticalCount;
        if (critDelta < 0)
        {
            entry.Events.Add(new ChangelogEvent
            {
                Type = ChangelogEventType.FindingsResolved,
                Icon = "✅",
                Summary = $"{Math.Abs(critDelta)} critical finding{(Math.Abs(critDelta) != 1 ? "s" : "")} resolved"
            });
        }
        else if (critDelta > 0)
        {
            entry.Events.Add(new ChangelogEvent
            {
                Type = ChangelogEventType.FindingsIntroduced,
                Icon = "🚨",
                Summary = $"{critDelta} new critical finding{(critDelta != 1 ? "s" : "")} detected"
            });
        }

        // Warning findings change
        var warnDelta = curr.WarningCount - prev.WarningCount;
        if (warnDelta < 0)
        {
            entry.Events.Add(new ChangelogEvent
            {
                Type = ChangelogEventType.FindingsResolved,
                Icon = "✅",
                Summary = $"{Math.Abs(warnDelta)} warning{(Math.Abs(warnDelta) != 1 ? "s" : "")} resolved"
            });
        }
        else if (warnDelta > 0)
        {
            entry.Events.Add(new ChangelogEvent
            {
                Type = ChangelogEventType.FindingsIntroduced,
                Icon = "⚠️",
                Summary = $"{warnDelta} new warning{(warnDelta != 1 ? "s" : "")} detected"
            });
        }

        // Per-finding diff if details available
        if (details.TryGetValue(prev.Id, out var prevDetail) &&
            details.TryGetValue(curr.Id, out var currDetail))
        {
            var prevFindings = GetFindingKeys(prevDetail, moduleFilter);
            var currFindings = GetFindingKeys(currDetail, moduleFilter);

            var resolved = prevFindings.Except(currFindings).ToList();
            var introduced = currFindings.Except(prevFindings).ToList();

            foreach (var f in resolved.Take(5))
            {
                entry.FindingChanges.Add(new FindingChange
                {
                    Type = FindingChangeType.Resolved,
                    Title = f.Title,
                    Module = f.Module,
                    Severity = f.Severity
                });
            }
            if (resolved.Count > 5)
                entry.FindingChangesOmitted = resolved.Count - 5;

            foreach (var f in introduced.Take(5))
            {
                entry.FindingChanges.Add(new FindingChange
                {
                    Type = FindingChangeType.Introduced,
                    Title = f.Title,
                    Module = f.Module,
                    Severity = f.Severity
                });
            }
            if (introduced.Count > 5)
                entry.FindingChangesOmitted += introduced.Count - 5;

            // Per-module score changes
            var prevModules = prevDetail.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);
            var currModules = currDetail.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);

            foreach (var mod in currModules)
            {
                if (moduleFilter != null && !mod.Key.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prevModules.TryGetValue(mod.Key, out var prevScore) && prevScore != mod.Value)
                {
                    entry.ModuleChanges.Add(new ModuleScoreChange
                    {
                        ModuleName = mod.Key,
                        PreviousScore = prevScore,
                        CurrentScore = mod.Value,
                        Delta = mod.Value - prevScore
                    });
                }
            }
        }

        // Zero-critical milestone
        if (prev.CriticalCount > 0 && curr.CriticalCount == 0)
        {
            entry.Events.Add(new ChangelogEvent
            {
                Type = ChangelogEventType.Milestone,
                Icon = "🎉",
                Summary = "All critical findings cleared!"
            });
        }

        return entry;
    }

    private static HashSet<FindingKey> GetFindingKeys(AuditRunRecord run, string? moduleFilter)
    {
        var findings = run.Findings.AsEnumerable();
        if (moduleFilter != null)
            findings = findings.Where(f => f.ModuleName.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase));

        return findings.Select(f => new FindingKey(f.ModuleName, f.Title, f.Severity)).ToHashSet();
    }

    private static List<ChangelogMilestone> DetectMilestones(List<AuditRunRecord> runs)
    {
        var milestones = new List<ChangelogMilestone>();

        // Detect improvement streaks (3+ consecutive improvements)
        int streakStart = -1;
        int streakLen = 0;
        for (int i = 1; i < runs.Count; i++)
        {
            if (runs[i].OverallScore > runs[i - 1].OverallScore)
            {
                if (streakLen == 0) streakStart = i - 1;
                streakLen++;
            }
            else
            {
                if (streakLen >= 3)
                {
                    milestones.Add(new ChangelogMilestone
                    {
                        Type = MilestoneType.ImprovementStreak,
                        Timestamp = runs[streakStart].Timestamp,
                        Description = $"{streakLen}-scan improvement streak ({runs[streakStart].OverallScore} → {runs[streakStart + streakLen].OverallScore})"
                    });
                }
                streakLen = 0;
            }
        }
        if (streakLen >= 3)
        {
            milestones.Add(new ChangelogMilestone
            {
                Type = MilestoneType.ImprovementStreak,
                Timestamp = runs[streakStart].Timestamp,
                Description = $"{streakLen}-scan improvement streak ({runs[streakStart].OverallScore} → {runs[streakStart + streakLen].OverallScore})"
            });
        }

        // Perfect score
        foreach (var run in runs)
        {
            if (run.OverallScore == 100)
            {
                milestones.Add(new ChangelogMilestone
                {
                    Type = MilestoneType.PerfectScore,
                    Timestamp = run.Timestamp,
                    Description = "Achieved perfect security score (100/100)!"
                });
                break; // Only first occurrence
            }
        }

        // Grade transitions (first time reaching A+, A, etc.)
        var seenGrades = new HashSet<string>();
        foreach (var run in runs)
        {
            if (seenGrades.Add(run.Grade) && run.Grade is "A+" or "A")
            {
                milestones.Add(new ChangelogMilestone
                {
                    Type = MilestoneType.GradeAchievement,
                    Timestamp = run.Timestamp,
                    Description = $"First time achieving grade {run.Grade}"
                });
            }
        }

        // Biggest single-scan improvement
        int biggestJump = 0;
        int biggestIdx = -1;
        for (int i = 1; i < runs.Count; i++)
        {
            var delta = runs[i].OverallScore - runs[i - 1].OverallScore;
            if (delta > biggestJump)
            {
                biggestJump = delta;
                biggestIdx = i;
            }
        }
        if (biggestJump >= 5 && biggestIdx >= 0)
        {
            milestones.Add(new ChangelogMilestone
            {
                Type = MilestoneType.BiggestImprovement,
                Timestamp = runs[biggestIdx].Timestamp,
                Description = $"Biggest single-scan improvement: +{biggestJump} points ({runs[biggestIdx - 1].OverallScore} → {runs[biggestIdx].OverallScore})"
            });
        }

        // Zero-critical achievement
        for (int i = 1; i < runs.Count; i++)
        {
            if (runs[i - 1].CriticalCount > 0 && runs[i].CriticalCount == 0)
            {
                milestones.Add(new ChangelogMilestone
                {
                    Type = MilestoneType.ZeroCritical,
                    Timestamp = runs[i].Timestamp,
                    Description = "Reached zero critical findings"
                });
                break;
            }
        }

        return milestones.OrderBy(m => m.Timestamp).ToList();
    }

    public static bool IsGradeBetter(string current, string previous)
    {
        var order = new Dictionary<string, int>
        {
            ["A+"] = 7, ["A"] = 6, ["B"] = 5, ["C"] = 4,
            ["D"] = 3, ["E"] = 2, ["F"] = 1
        };
        var currVal = order.GetValueOrDefault(current, 0);
        var prevVal = order.GetValueOrDefault(previous, 0);
        return currVal > prevVal;
    }
}

// ── Models ──────────────────────────────────────────────────────────

/// <summary>Key for deduplicating findings across runs.</summary>
public record FindingKey(string Module, string Title, string Severity);

/// <summary>Full changelog report.</summary>
public class ChangelogReport
{
    public int Period { get; set; }
    public int TotalScans { get; set; }
    public DateTimeOffset? FirstScan { get; set; }
    public DateTimeOffset? LastScan { get; set; }
    public int StartScore { get; set; }
    public int EndScore { get; set; }
    public string StartGrade { get; set; } = "";
    public string EndGrade { get; set; } = "";
    public int NetScoreChange { get; set; }
    public int BestScore { get; set; }
    public int WorstScore { get; set; }
    public int ImprovementCount { get; set; }
    public int RegressionCount { get; set; }
    public List<ChangelogEntry> Entries { get; set; } = [];
    public List<ChangelogMilestone> Milestones { get; set; } = [];
}

/// <summary>One changelog entry (diff between two consecutive scans).</summary>
public class ChangelogEntry
{
    public DateTimeOffset Timestamp { get; set; }
    public int PreviousScore { get; set; }
    public int CurrentScore { get; set; }
    public string PreviousGrade { get; set; } = "";
    public string CurrentGrade { get; set; } = "";
    public int ScoreChange { get; set; }
    public List<ChangelogEvent> Events { get; set; } = [];
    public List<FindingChange> FindingChanges { get; set; } = [];
    public List<ModuleScoreChange> ModuleChanges { get; set; } = [];
    public int FindingChangesOmitted { get; set; }
}

/// <summary>A single event within a changelog entry.</summary>
public class ChangelogEvent
{
    public ChangelogEventType Type { get; set; }
    public string Icon { get; set; } = "";
    public string Summary { get; set; } = "";
}

public enum ChangelogEventType
{
    Improvement,
    Regression,
    GradeUp,
    GradeDown,
    FindingsResolved,
    FindingsIntroduced,
    Milestone
}

/// <summary>A specific finding that was resolved or introduced.</summary>
public class FindingChange
{
    public FindingChangeType Type { get; set; }
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public string Severity { get; set; } = "";
}

public enum FindingChangeType
{
    Resolved,
    Introduced
}

/// <summary>Module score change between consecutive scans.</summary>
public class ModuleScoreChange
{
    public string ModuleName { get; set; } = "";
    public int PreviousScore { get; set; }
    public int CurrentScore { get; set; }
    public int Delta { get; set; }
}

/// <summary>A notable milestone detected in the history.</summary>
public class ChangelogMilestone
{
    public MilestoneType Type { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string Description { get; set; } = "";
}

public enum MilestoneType
{
    ImprovementStreak,
    PerfectScore,
    GradeAchievement,
    BiggestImprovement,
    ZeroCritical
}
