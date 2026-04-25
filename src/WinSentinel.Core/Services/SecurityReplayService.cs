namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Replay — time-travel security debugger. Replay posture at any historical point,
/// bisect to find regression origins, and diff states between runs.
/// </summary>
public class SecurityReplayService
{
    private readonly AuditHistoryService _history;

    public SecurityReplayService(AuditHistoryService history)
    {
        _history = history;
    }

    /// <summary>
    /// Replay a snapshot of security posture at a specific historical run.
    /// </summary>
    public ReplayResult Snapshot(int days, string? target)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count == 0)
            return EmptyResult("snapshot", "No audit history found.");

        var latest = runs[0];
        AuditRunRecord chosen;
        int chosenIndex;

        if (target != null && int.TryParse(target, out var idx) && idx >= 0 && idx < runs.Count)
        {
            chosen = runs[idx];
            chosenIndex = idx;
        }
        else if (target != null && DateTimeOffset.TryParse(target, out var dt))
        {
            // Find closest run to the target date
            chosenIndex = 0;
            var minDiff = double.MaxValue;
            for (int i = 0; i < runs.Count; i++)
            {
                var diff = Math.Abs((runs[i].Timestamp - dt).TotalSeconds);
                if (diff < minDiff) { minDiff = diff; chosenIndex = i; }
            }
            chosen = runs[chosenIndex];
        }
        else
        {
            // Default: show the oldest run
            chosenIndex = runs.Count - 1;
            chosen = runs[chosenIndex];
        }

        var snapshot = BuildSnapshot(chosen, latest, chosenIndex);

        return new ReplayResult
        {
            AnalyzedAt = DateTimeOffset.UtcNow,
            Mode = "snapshot",
            Snapshot = snapshot,
            TotalRunsAvailable = runs.Count
        };
    }

    /// <summary>
    /// Binary search through history to find when a regression was introduced.
    /// </summary>
    public ReplayResult Bisect(int days, string? pattern, int? threshold)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count < 2)
            return EmptyResult("bisect", "Need at least 2 audit runs for bisect.");

        // Runs are newest-first. We search from oldest to newest for the transition.
        var reversed = runs.ToList();
        reversed.Reverse(); // Now oldest-first

        string criteria = pattern != null
            ? $"Finding matching \"{pattern}\""
            : threshold.HasValue
                ? $"Score below {threshold.Value}"
                : "Score below latest";

        if (pattern == null && !threshold.HasValue)
            threshold = runs[0].OverallScore; // Use current score as threshold

        bool MatchesBad(AuditRunRecord run)
        {
            if (pattern != null)
                return run.Findings.Any(f =>
                    f.Title.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    f.Description.Contains(pattern, StringComparison.OrdinalIgnoreCase));
            return run.OverallScore < threshold!.Value;
        }

        // Binary search: find first "bad" run
        var steps = new List<BisectStep>();
        int lo = 0, hi = reversed.Count - 1;
        int stepNum = 0;

        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            var run = reversed[mid];
            bool bad = MatchesBad(run);
            stepNum++;

            steps.Add(new BisectStep
            {
                StepNumber = stepNum,
                RunIndex = runs.Count - 1 - mid, // Convert back to newest-first index
                RunDate = run.Timestamp,
                Score = run.OverallScore,
                MatchesCriteria = bad,
                Direction = bad ? "bad" : "good"
            });

            if (bad)
                hi = mid;
            else
                lo = mid + 1;
        }

        var regressionRun = reversed[lo];
        var lastGoodIdx = lo > 0 ? lo - 1 : -1;

        var result = new BisectResult
        {
            SearchCriteria = criteria,
            TotalRunsSearched = reversed.Count,
            BisectSteps = stepNum,
            Steps = steps,
            RegressionIntroduced = new BisectPoint
            {
                RunIndex = runs.Count - 1 - lo,
                RunDate = regressionRun.Timestamp,
                Score = regressionRun.OverallScore,
                MatchesCriteria = MatchesBad(regressionRun)
            }
        };

        if (lastGoodIdx >= 0)
        {
            var good = reversed[lastGoodIdx];
            result.LastGoodRun = new BisectPoint
            {
                RunIndex = runs.Count - 1 - lastGoodIdx,
                RunDate = good.Timestamp,
                Score = good.OverallScore,
                MatchesCriteria = false
            };
            result.Narrative = $"Regression introduced on {regressionRun.Timestamp:yyyy-MM-dd HH:mm}. " +
                               $"Last good run was {good.Timestamp:yyyy-MM-dd HH:mm} (score {good.OverallScore} → {regressionRun.OverallScore}).";
        }
        else
        {
            result.Narrative = $"All {reversed.Count} runs match the criteria. Regression predates available history.";
        }

        return new ReplayResult
        {
            AnalyzedAt = DateTimeOffset.UtcNow,
            Mode = "bisect",
            Bisect = result,
            TotalRunsAvailable = runs.Count
        };
    }

    /// <summary>
    /// Diff two historical runs showing what changed between them.
    /// </summary>
    public ReplayResult Diff(int days, string? fromStr, string? toStr)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count < 2)
            return EmptyResult("diff", "Need at least 2 audit runs for diff.");

        int fromIdx = runs.Count - 1; // Default: oldest
        int toIdx = 0;                 // Default: newest

        if (fromStr != null && int.TryParse(fromStr, out var fi) && fi >= 0 && fi < runs.Count)
            fromIdx = fi;
        if (toStr != null && int.TryParse(toStr, out var ti) && ti >= 0 && ti < runs.Count)
            toIdx = ti;

        var fromRun = runs[fromIdx];
        var toRun = runs[toIdx];
        var latest = runs[0];

        var fromSnap = BuildSnapshot(fromRun, latest, fromIdx);
        var toSnap = BuildSnapshot(toRun, latest, toIdx);

        // Diff findings
        var fromFindings = fromRun.Findings.Select(f => (f.ModuleName, f.Title, f.Severity)).ToHashSet();
        var toFindings = toRun.Findings.Select(f => (f.ModuleName, f.Title, f.Severity)).ToHashSet();

        var added = toFindings.Except(fromFindings)
            .Select(f => new DiffEntry { Module = f.ModuleName, Finding = f.Title, Severity = f.Severity, ChangeType = "added" })
            .ToList();
        var removed = fromFindings.Except(toFindings)
            .Select(f => new DiffEntry { Module = f.ModuleName, Finding = f.Title, Severity = f.Severity, ChangeType = "removed" })
            .ToList();

        int scoreChange = toRun.OverallScore - fromRun.OverallScore;
        string dir = scoreChange > 0 ? "improved" : scoreChange < 0 ? "degraded" : "unchanged";

        var diffResult = new DiffResult
        {
            From = fromSnap,
            To = toSnap,
            ScoreChange = scoreChange,
            Added = added,
            Removed = removed,
            Narrative = $"Between {fromRun.Timestamp:yyyy-MM-dd} and {toRun.Timestamp:yyyy-MM-dd}, " +
                        $"security posture {dir} by {Math.Abs(scoreChange)} points. " +
                        $"{added.Count} new findings appeared, {removed.Count} were resolved."
        };

        return new ReplayResult
        {
            AnalyzedAt = DateTimeOffset.UtcNow,
            Mode = "diff",
            Diff = diffResult,
            TotalRunsAvailable = runs.Count
        };
    }

    private static ReplaySnapshot BuildSnapshot(AuditRunRecord run, AuditRunRecord latest, int index)
    {
        var modules = new List<ModuleSnapshot>();
        var latestModules = latest.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);

        foreach (var ms in run.ModuleScores)
        {
            latestModules.TryGetValue(ms.ModuleName, out var currentScore);
            modules.Add(new ModuleSnapshot
            {
                Name = ms.ModuleName,
                Score = ms.Score,
                CurrentScore = currentScore,
                Delta = currentScore - ms.Score,
                FindingCount = ms.FindingCount
            });
        }

        var topFindings = run.Findings
            .OrderByDescending(f => SeverityWeight(f.Severity))
            .Take(10)
            .Select(f => $"[{f.Severity}] {f.ModuleName}: {f.Title}")
            .ToList();

        return new ReplaySnapshot
        {
            RunIndex = index,
            RunDate = run.Timestamp,
            Score = run.OverallScore,
            CurrentScore = latest.OverallScore,
            ScoreDelta = latest.OverallScore - run.OverallScore,
            Modules = modules,
            TopFindings = topFindings,
            TotalFindings = run.TotalFindings,
            CriticalCount = run.CriticalCount,
            HighCount = run.WarningCount,
            Narrative = $"At run #{index} ({run.Timestamp:yyyy-MM-dd HH:mm}), score was {run.OverallScore}/100 ({run.Grade}). " +
                        $"Current score is {latest.OverallScore}/100, a change of {latest.OverallScore - run.OverallScore:+#;-#;0} points."
        };
    }

    private static int SeverityWeight(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 15,
        "high" or "warning" => 8,
        "medium" => 4,
        "low" or "info" => 1,
        _ => 0
    };

    private static ReplayResult EmptyResult(string mode, string message) => new()
    {
        AnalyzedAt = DateTimeOffset.UtcNow,
        Mode = mode,
        ErrorMessage = message
    };
}

// ── Result Models ──

public class ReplayResult
{
    public DateTimeOffset AnalyzedAt { get; set; }
    public string Mode { get; set; } = "snapshot";
    public ReplaySnapshot? Snapshot { get; set; }
    public BisectResult? Bisect { get; set; }
    public DiffResult? Diff { get; set; }
    public int TotalRunsAvailable { get; set; }
    public string? ErrorMessage { get; set; }
}

public class ReplaySnapshot
{
    public int RunIndex { get; set; }
    public DateTimeOffset RunDate { get; set; }
    public int Score { get; set; }
    public int CurrentScore { get; set; }
    public int ScoreDelta { get; set; }
    public List<ModuleSnapshot> Modules { get; set; } = new();
    public List<string> TopFindings { get; set; } = new();
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public string Narrative { get; set; } = "";
}

public class ModuleSnapshot
{
    public string Name { get; set; } = "";
    public int Score { get; set; }
    public int CurrentScore { get; set; }
    public int Delta { get; set; }
    public int FindingCount { get; set; }
}

public class BisectResult
{
    public string SearchCriteria { get; set; } = "";
    public int TotalRunsSearched { get; set; }
    public int BisectSteps { get; set; }
    public BisectPoint? RegressionIntroduced { get; set; }
    public BisectPoint? LastGoodRun { get; set; }
    public List<BisectStep> Steps { get; set; } = new();
    public string Narrative { get; set; } = "";
}

public class BisectPoint
{
    public int RunIndex { get; set; }
    public DateTimeOffset RunDate { get; set; }
    public int Score { get; set; }
    public bool MatchesCriteria { get; set; }
}

public class BisectStep
{
    public int StepNumber { get; set; }
    public int RunIndex { get; set; }
    public DateTimeOffset RunDate { get; set; }
    public int Score { get; set; }
    public bool MatchesCriteria { get; set; }
    public string Direction { get; set; } = "";
}

public class DiffResult
{
    public ReplaySnapshot From { get; set; } = new();
    public ReplaySnapshot To { get; set; } = new();
    public int ScoreChange { get; set; }
    public List<DiffEntry> Added { get; set; } = new();
    public List<DiffEntry> Removed { get; set; } = new();
    public string Narrative { get; set; } = "";
}

public class DiffEntry
{
    public string Module { get; set; } = "";
    public string Finding { get; set; } = "";
    public string Severity { get; set; } = "";
    public string ChangeType { get; set; } = "";
}
