namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Analyzes audit history to identify the noisiest finding sources —
/// modules and individual findings that fire most frequently across scans.
/// Helps users focus their ignore-rule and tuning efforts where it matters most.
/// </summary>
public class NoiseAnalyzer
{
    /// <summary>
    /// Analyze noise across historical audit runs.
    /// </summary>
    public NoiseAnalysisResult Analyze(List<AuditRunRecord> runs, int top = 15)
    {
        if (runs.Count == 0)
            return new NoiseAnalysisResult();

        var totalRuns = runs.Count;
        var allFindings = runs.SelectMany(r => r.Findings).ToList();
        var totalOccurrences = allFindings.Count;

        // --- Finding-level noise ---
        var findingGroups = allFindings
            .GroupBy(f => f.Title)
            .Select(g =>
            {
                var runsContaining = runs.Count(r => r.Findings.Any(f => f.Title == g.Key));
                var sample = g.First();
                var rate = totalRuns > 0 ? (double)runsContaining / totalRuns * 100 : 0;
                var isPerennial = runsContaining == totalRuns && totalRuns >= 2;

                return new NoisyFinding
                {
                    Title = g.Key,
                    ModuleName = sample.ModuleName,
                    Severity = sample.Severity,
                    Occurrences = g.Count(),
                    OccurrenceRate = Math.Round(rate, 1),
                    IsPerennial = isPerennial,
                    SuggestedAction = SuggestAction(sample.Severity, rate, isPerennial)
                };
            })
            .OrderByDescending(f => f.Occurrences)
            .ThenByDescending(f => f.OccurrenceRate)
            .Take(top)
            .ToList();

        // --- Module-level noise ---
        var moduleGroups = allFindings
            .GroupBy(f => f.ModuleName)
            .Select(g =>
            {
                var moduleRuns = runs.Where(r => r.ModuleScores.Any(m => m.ModuleName == g.Key)).ToList();
                var category = runs.SelectMany(r => r.ModuleScores)
                    .FirstOrDefault(m => m.ModuleName == g.Key)?.Category ?? "";

                return new NoisyModule
                {
                    ModuleName = g.Key,
                    Category = category,
                    TotalFindings = g.Count(),
                    AvgFindingsPerScan = totalRuns > 0 ? Math.Round((double)g.Count() / totalRuns, 1) : 0,
                    UniqueFindingTitles = g.Select(f => f.Title).Distinct().Count(),
                    NoiseShare = totalOccurrences > 0 ? Math.Round((double)g.Count() / totalOccurrences * 100, 1) : 0
                };
            })
            .OrderByDescending(m => m.TotalFindings)
            .Take(top)
            .ToList();

        // --- Stats ---
        var allFindingStats = allFindings
            .GroupBy(f => f.Title)
            .Select(g =>
            {
                var runsContaining = runs.Count(r => r.Findings.Any(f => f.Title == g.Key));
                var rate = totalRuns > 0 ? (double)runsContaining / totalRuns * 100 : 0;
                return new { Title = g.Key, Rate = rate, Severity = g.First().Severity, IsPerennial = runsContaining == totalRuns && totalRuns >= 2 };
            })
            .ToList();

        var perennial = allFindingStats.Count(f => f.IsPerennial);
        var highFreq = allFindingStats.Count(f => f.Rate > 80);
        var lowFreq = allFindingStats.Count(f => f.Rate < 20);
        var suppressible = allFindingStats.Count(f =>
            f.IsPerennial || (f.Rate > 80 && f.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase)));

        var avgPerScan = totalRuns > 0 ? Math.Round((double)totalOccurrences / totalRuns, 1) : 0;

        var noiseLevel = perennial switch
        {
            0 when highFreq <= 2 => "Low",
            _ when perennial <= 3 && highFreq <= 5 => "Moderate",
            _ when perennial <= 8 && highFreq <= 15 => "High",
            _ => "Excessive"
        };

        return new NoiseAnalysisResult
        {
            RunsAnalyzed = totalRuns,
            DaysSpan = runs.Count >= 2
                ? (int)(runs.Max(r => r.Timestamp) - runs.Min(r => r.Timestamp)).TotalDays
                : 0,
            TotalFindingOccurrences = totalOccurrences,
            UniqueFindingTitles = allFindingStats.Count,
            TopNoisyFindings = findingGroups,
            TopNoisyModules = moduleGroups,
            Stats = new NoiseStats
            {
                PerennialFindings = perennial,
                HighFrequencyFindings = highFreq,
                LowFrequencyFindings = lowFreq,
                AvgFindingsPerScan = avgPerScan,
                EstimatedSuppressibleFindings = suppressible,
                NoiseLevelRating = noiseLevel
            }
        };
    }

    private static string SuggestAction(string severity, double rate, bool isPerennial)
    {
        if (isPerennial && severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
            return "Suppress with --ignore (informational & always present)";
        if (isPerennial)
            return "Investigate root cause — this never goes away";
        if (rate > 80 && severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
            return "Consider suppressing (high-frequency informational)";
        if (rate > 80)
            return "Prioritize fix — recurring in most scans";
        if (rate > 50)
            return "Intermittent — check for environmental triggers";
        return "Sporadic — may self-resolve";
    }
}
