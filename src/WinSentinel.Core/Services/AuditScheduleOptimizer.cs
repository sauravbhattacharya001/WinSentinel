using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes historical audit data to compute per-module finding volatility
/// and recommend optimal scan frequencies. Modules with high churn (findings
/// appearing/disappearing frequently) should be scanned more often; stable
/// modules can be scanned less frequently to save resources.
/// </summary>
public class AuditScheduleOptimizer
{
    // ── Public types ─────────────────────────────────────────────────

    /// <summary>Recommended scan cadence for a module.</summary>
    public enum ScanCadence
    {
        /// <summary>Scan every run — highly volatile module.</summary>
        EveryRun,
        /// <summary>Scan hourly — volatile module.</summary>
        Hourly,
        /// <summary>Scan daily — moderate volatility.</summary>
        Daily,
        /// <summary>Scan weekly — low volatility.</summary>
        Weekly,
        /// <summary>Scan monthly — very stable module.</summary>
        Monthly
    }

    /// <summary>Per-module volatility analysis and scan recommendation.</summary>
    public record ModuleVolatility(
        string ModuleName,
        string Category,
        int TotalAppearances,
        int ScoreChanges,
        double ScoreChangeRate,
        int FindingChurns,
        double FindingChurnRate,
        double VolatilityScore,
        ScanCadence RecommendedCadence,
        int AverageScore,
        int MinScore,
        int MaxScore,
        int ScoreRange,
        double ScoreStdDev);

    /// <summary>Overall schedule optimization result.</summary>
    public class ScheduleOptimizationResult
    {
        /// <summary>Number of historical runs analyzed.</summary>
        public int RunsAnalyzed { get; init; }

        /// <summary>Time span covered by the analysis.</summary>
        public TimeSpan AnalysisPeriod { get; init; }

        /// <summary>Per-module volatility analysis, ordered by volatility descending.</summary>
        public List<ModuleVolatility> Modules { get; init; } = [];

        /// <summary>Modules recommended for every-run scanning.</summary>
        public List<ModuleVolatility> HighPriority =>
            Modules.Where(m => m.RecommendedCadence <= ScanCadence.Hourly).ToList();

        /// <summary>Modules that can be scanned less frequently.</summary>
        public List<ModuleVolatility> LowPriority =>
            Modules.Where(m => m.RecommendedCadence >= ScanCadence.Weekly).ToList();

        /// <summary>Estimated scan time savings as a percentage (0-100).</summary>
        public double EstimatedSavingsPercent { get; init; }

        /// <summary>Average volatility score across all modules.</summary>
        public double AverageVolatility =>
            Modules.Count > 0 ? Modules.Average(m => m.VolatilityScore) : 0;

        /// <summary>Human-readable summary.</summary>
        public string Summary { get; init; } = "";
    }

    // ── Core analysis ────────────────────────────────────────────────

    /// <summary>
    /// Analyze audit history and produce per-module scan frequency recommendations.
    /// </summary>
    /// <param name="history">The audit history service to query.</param>
    /// <param name="days">Number of days of history to analyze.</param>
    /// <returns>Schedule optimization result with per-module recommendations.</returns>
    public ScheduleOptimizationResult Analyze(AuditHistoryService history, int days = 90)
    {
        var runs = history.GetHistory(days);
        if (runs.Count < 2)
        {
            return new ScheduleOptimizationResult
            {
                RunsAnalyzed = runs.Count,
                AnalysisPeriod = TimeSpan.Zero,
                Summary = runs.Count == 0
                    ? "No audit history available. Run at least 2 audits to get recommendations."
                    : "Only 1 audit run found. Need at least 2 runs for volatility analysis."
            };
        }

        // Load full details for each run
        var detailedRuns = new List<AuditRunRecord>();
        foreach (var run in runs.OrderBy(r => r.Timestamp))
        {
            var details = history.GetRunDetails(run.Id);
            if (details != null)
                detailedRuns.Add(details);
        }

        if (detailedRuns.Count < 2)
        {
            return new ScheduleOptimizationResult
            {
                RunsAnalyzed = detailedRuns.Count,
                AnalysisPeriod = TimeSpan.Zero,
                Summary = "Insufficient detailed run data for analysis."
            };
        }

        var period = detailedRuns[^1].Timestamp - detailedRuns[0].Timestamp;
        var modules = AnalyzeModules(detailedRuns);

        // Estimate savings: modules that can skip runs
        var totalModuleScans = modules.Count * detailedRuns.Count;
        var optimizedScans = modules.Sum(m => EstimateScansNeeded(m.RecommendedCadence, period, detailedRuns.Count));
        var savings = totalModuleScans > 0
            ? (1.0 - (double)optimizedScans / totalModuleScans) * 100.0
            : 0;

        var summary = GenerateSummary(modules, detailedRuns.Count, period, savings);

        return new ScheduleOptimizationResult
        {
            RunsAnalyzed = detailedRuns.Count,
            AnalysisPeriod = period,
            Modules = modules,
            EstimatedSavingsPercent = Math.Round(savings, 1),
            Summary = summary
        };
    }

    /// <summary>
    /// Analyze from pre-loaded run records (useful for testing without DB).
    /// </summary>
    public ScheduleOptimizationResult AnalyzeFromRuns(List<AuditRunRecord> runs)
    {
        if (runs.Count < 2)
        {
            return new ScheduleOptimizationResult
            {
                RunsAnalyzed = runs.Count,
                AnalysisPeriod = TimeSpan.Zero,
                Summary = runs.Count == 0
                    ? "No audit history available. Run at least 2 audits to get recommendations."
                    : "Only 1 audit run found. Need at least 2 runs for volatility analysis."
            };
        }

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var period = ordered[^1].Timestamp - ordered[0].Timestamp;
        var modules = AnalyzeModules(ordered);

        var totalModuleScans = modules.Count * ordered.Count;
        var optimizedScans = modules.Sum(m => EstimateScansNeeded(m.RecommendedCadence, period, ordered.Count));
        var savings = totalModuleScans > 0
            ? (1.0 - (double)optimizedScans / totalModuleScans) * 100.0
            : 0;

        var summary = GenerateSummary(modules, ordered.Count, period, savings);

        return new ScheduleOptimizationResult
        {
            RunsAnalyzed = ordered.Count,
            AnalysisPeriod = period,
            Modules = modules,
            EstimatedSavingsPercent = Math.Round(savings, 1),
            Summary = summary
        };
    }

    // ── Private helpers ──────────────────────────────────────────────

    private List<ModuleVolatility> AnalyzeModules(List<AuditRunRecord> runs)
    {
        // Collect all module names across all runs
        var allModules = runs
            .SelectMany(r => r.ModuleScores)
            .Select(ms => (ms.ModuleName, ms.Category))
            .Distinct()
            .ToList();

        var results = new List<ModuleVolatility>();

        foreach (var (moduleName, category) in allModules)
        {
            var scores = new List<int>();
            var findingSets = new List<HashSet<string>>();

            foreach (var run in runs)
            {
                var moduleScore = run.ModuleScores.FirstOrDefault(
                    ms => ms.ModuleName == moduleName);

                if (moduleScore != null)
                {
                    scores.Add(moduleScore.Score);

                    var titles = run.Findings
                        .Where(f => f.ModuleName == moduleName)
                        .Select(f => f.Title)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    findingSets.Add(titles);
                }
            }

            if (scores.Count < 2) continue;

            // Score changes: how many times did the score change between consecutive runs
            int scoreChanges = 0;
            for (int i = 1; i < scores.Count; i++)
            {
                if (scores[i] != scores[i - 1])
                    scoreChanges++;
            }

            // Finding churn: how many times did findings appear/disappear
            int findingChurns = 0;
            for (int i = 1; i < findingSets.Count; i++)
            {
                var added = findingSets[i].Except(findingSets[i - 1]).Count();
                var removed = findingSets[i - 1].Except(findingSets[i]).Count();
                findingChurns += added + removed;
            }

            double scoreChangeRate = (double)scoreChanges / (scores.Count - 1);
            double findingChurnRate = (double)findingChurns / (findingSets.Count - 1);

            // Volatility score: weighted combination (0-100)
            // Score changes are weighted more (40%) + finding churn rate (60%)
            double volatility = Math.Min(100,
                scoreChangeRate * 40.0 +
                Math.Min(findingChurnRate, 5.0) / 5.0 * 60.0);

            double avg = scores.Average();
            int min = scores.Min();
            int max = scores.Max();
            double stdDev = Math.Sqrt(scores.Average(s => Math.Pow(s - avg, 2)));

            var cadence = ClassifyCadence(volatility, scoreChangeRate);

            results.Add(new ModuleVolatility(
                ModuleName: moduleName,
                Category: category,
                TotalAppearances: scores.Count,
                ScoreChanges: scoreChanges,
                ScoreChangeRate: Math.Round(scoreChangeRate, 3),
                FindingChurns: findingChurns,
                FindingChurnRate: Math.Round(findingChurnRate, 3),
                VolatilityScore: Math.Round(volatility, 1),
                RecommendedCadence: cadence,
                AverageScore: (int)Math.Round(avg),
                MinScore: min,
                MaxScore: max,
                ScoreRange: max - min,
                ScoreStdDev: Math.Round(stdDev, 2)));
        }

        return results.OrderByDescending(m => m.VolatilityScore).ToList();
    }

    private static ScanCadence ClassifyCadence(double volatility, double scoreChangeRate)
    {
        if (volatility >= 70 || scoreChangeRate >= 0.8)
            return ScanCadence.EveryRun;
        if (volatility >= 50 || scoreChangeRate >= 0.6)
            return ScanCadence.Hourly;
        if (volatility >= 25 || scoreChangeRate >= 0.3)
            return ScanCadence.Daily;
        if (volatility >= 10 || scoreChangeRate >= 0.1)
            return ScanCadence.Weekly;
        return ScanCadence.Monthly;
    }

    private static int EstimateScansNeeded(ScanCadence cadence, TimeSpan period, int totalRuns)
    {
        if (period.TotalHours < 1) return totalRuns;

        return cadence switch
        {
            ScanCadence.EveryRun => totalRuns,
            ScanCadence.Hourly => Math.Min(totalRuns, Math.Max(1, (int)period.TotalHours)),
            ScanCadence.Daily => Math.Min(totalRuns, Math.Max(1, (int)period.TotalDays)),
            ScanCadence.Weekly => Math.Min(totalRuns, Math.Max(1, (int)(period.TotalDays / 7))),
            ScanCadence.Monthly => Math.Min(totalRuns, Math.Max(1, (int)(period.TotalDays / 30))),
            _ => totalRuns
        };
    }

    private static string GenerateSummary(List<ModuleVolatility> modules, int runCount, TimeSpan period, double savings)
    {
        if (modules.Count == 0)
            return "No modules found in audit history.";

        var lines = new List<string>
        {
            $"Analyzed {runCount} audit runs over {FormatPeriod(period)}.",
            $"{modules.Count} modules evaluated for scan frequency optimization.",
            ""
        };

        var everyRun = modules.Count(m => m.RecommendedCadence == ScanCadence.EveryRun);
        var hourly = modules.Count(m => m.RecommendedCadence == ScanCadence.Hourly);
        var daily = modules.Count(m => m.RecommendedCadence == ScanCadence.Daily);
        var weekly = modules.Count(m => m.RecommendedCadence == ScanCadence.Weekly);
        var monthly = modules.Count(m => m.RecommendedCadence == ScanCadence.Monthly);

        lines.Add("Recommended cadence distribution:");
        if (everyRun > 0) lines.Add($"  Every Run: {everyRun} module(s)");
        if (hourly > 0) lines.Add($"  Hourly:    {hourly} module(s)");
        if (daily > 0) lines.Add($"  Daily:     {daily} module(s)");
        if (weekly > 0) lines.Add($"  Weekly:    {weekly} module(s)");
        if (monthly > 0) lines.Add($"  Monthly:   {monthly} module(s)");

        lines.Add("");
        lines.Add($"Estimated scan time savings: {savings:F1}%");

        if (modules.Count > 0)
        {
            var mostVolatile = modules[0];
            lines.Add($"Most volatile: {mostVolatile.ModuleName} (score: {mostVolatile.VolatilityScore:F1})");
        }

        if (modules.Count > 0)
        {
            var mostStable = modules[^1];
            lines.Add($"Most stable:   {mostStable.ModuleName} (score: {mostStable.VolatilityScore:F1})");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatPeriod(TimeSpan period)
    {
        if (period.TotalDays >= 1)
            return $"{(int)period.TotalDays} day(s)";
        if (period.TotalHours >= 1)
            return $"{(int)period.TotalHours} hour(s)";
        return $"{(int)period.TotalMinutes} minute(s)";
    }
}
