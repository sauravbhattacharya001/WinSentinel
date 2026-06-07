namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Predictive threat forecasting engine that analyzes audit history to predict
/// which findings are most likely to appear or worsen next, using trend
/// extrapolation and pattern analysis.
/// </summary>
public sealed class SecurityProphecyService
{
    private readonly AuditHistoryService _history;

    public SecurityProphecyService(AuditHistoryService history) => _history = history;

    /// <summary>Predict future threat landscape from audit history.</summary>
    public ProphecyReport Predict(SecurityReport report, int historyDays = 90, int forecastDays = 30)
    {
        var runs = _history.GetHistoryWithFindings(historyDays);
        if (runs.Count < 3) return new ProphecyReport { AnalyzedRuns = runs.Count, ForecastDays = forecastDays };

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var splitIndex = Math.Max(1, ordered.Count * 2 / 3);
        var olderRuns = ordered.Take(splitIndex).ToList();
        var recentRuns = ordered.Skip(splitIndex).ToList();
        if (recentRuns.Count == 0) { recentRuns = [ordered.Last()]; olderRuns = ordered.Take(ordered.Count - 1).ToList(); }

        var rising = new List<ThreatPrediction>();
        var dormant = new List<ThreatPrediction>();
        var fading = new List<ThreatPrediction>();
        var moduleMomentum = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);

        // Aggregate findings by category across time periods
        var olderStats = AggregateFindings(olderRuns);
        var recentStats = AggregateFindings(recentRuns);

        var allCategories = new HashSet<string>(olderStats.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var k in recentStats.Keys) allCategories.Add(k);

        foreach (var cat in allCategories)
        {
            olderStats.TryGetValue(cat, out var older);
            recentStats.TryGetValue(cat, out var recent);
            older ??= new FindingStats();
            recent ??= new FindingStats();

            var olderRate = olderRuns.Count > 0 ? (double)older.Count / olderRuns.Count : 0;
            var recentRate = recentRuns.Count > 0 ? (double)recent.Count / recentRuns.Count : 0;

            var severityWeight = SeverityWeight(recent.MaxSeverity ?? older.MaxSeverity ?? "Info");
            var momentum = (recentRate - olderRate) * severityWeight;

            var pred = new ThreatPrediction
            {
                Category = cat,
                Module = recent.PrimaryModule ?? older.PrimaryModule ?? "Unknown",
                Description = recent.SampleTitle ?? older.SampleTitle ?? cat,
                Momentum = Math.Round(momentum, 2),
                Severity = recent.MaxSeverity ?? older.MaxSeverity ?? "Info",
                OccurrencesRecent = recent.Count,
                OccurrencesOlder = older.Count,
                Confidence = runs.Count >= 10 ? "High" : runs.Count >= 5 ? "Medium" : "Low"
            };

            if (momentum > 0.1)
                rising.Add(pred);
            else if (momentum < -0.1)
                fading.Add(pred);

            // Dormant: appeared in older, absent recently
            if (older.Count > 0 && recent.Count == 0)
            {
                var recurrenceProb = Math.Min(1.0, older.Count / (double)(olderRuns.Count * 2));
                pred.RecurrenceProbability = Math.Round(recurrenceProb, 2);
                if (recurrenceProb > 0.2)
                    dormant.Add(pred);
            }
        }

        // Module momentum from ModuleScores
        var allModules = ordered.SelectMany(r => r.ModuleScores).Select(m => m.ModuleName).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var mod in allModules)
        {
            var olderAvg = olderRuns.SelectMany(r => r.ModuleScores).Where(m => string.Equals(m.ModuleName, mod, StringComparison.OrdinalIgnoreCase)).Select(m => (double)m.FindingCount).DefaultIfEmpty(0).Average();
            var recentAvg = recentRuns.SelectMany(r => r.ModuleScores).Where(m => string.Equals(m.ModuleName, mod, StringComparison.OrdinalIgnoreCase)).Select(m => (double)m.FindingCount).DefaultIfEmpty(0).Average();
            moduleMomentum[mod] = Math.Round(recentAvg - olderAvg, 2);
        }

        // Storm probability
        var risingWeight = rising.Sum(r => Math.Abs(r.Momentum));
        var fadingWeight = fading.Sum(f => Math.Abs(f.Momentum));
        var total = risingWeight + fadingWeight + 1;
        var stormProb = Math.Clamp((int)(risingWeight / total * 100), 0, 100);

        var outlook = stormProb switch
        {
            <= 15 => "Clearing",
            <= 35 => "Stable",
            <= 55 => "Gathering",
            <= 80 => "Stormy",
            _ => "Critical"
        };

        // Natural language prophecies
        var prophecies = new List<string>();
        foreach (var r in rising.OrderByDescending(x => x.Momentum).Take(3))
            prophecies.Add($"'{r.Category}' findings are accelerating — expect more {r.Severity.ToLower()}-severity issues from {r.Module} in the next {forecastDays} days.");

        foreach (var d in dormant.OrderByDescending(x => x.RecurrenceProbability).Take(2))
            prophecies.Add($"'{d.Category}' has been quiet but historically recurs — {(int)(d.RecurrenceProbability * 100)}% chance it returns.");

        if (fading.Count > rising.Count)
            prophecies.Add("Overall trend is positive — more threats are fading than rising.");
        else if (rising.Count > fading.Count * 2)
            prophecies.Add("Threat landscape is deteriorating — rising threats outnumber fading ones significantly.");

        // Recommendations
        var recommendations = new List<string>();
        foreach (var r in rising.OrderByDescending(x => x.Momentum).Take(3))
            recommendations.Add($"Prioritize {r.Module} — {r.Category} findings are trending upward.");

        foreach (var d in dormant.OrderByDescending(x => x.RecurrenceProbability).Take(2))
            recommendations.Add($"Set up monitoring for {d.Category} in {d.Module} — it tends to recur.");

        if (stormProb > 50)
            recommendations.Add("Consider increasing audit frequency to catch emerging threats early.");
        if (stormProb <= 20 && runs.Count >= 5)
            recommendations.Add("Posture is improving — good time to raise your security baseline.");

        return new ProphecyReport
        {
            StormProbability = stormProb,
            Outlook = outlook,
            RisingThreats = rising.OrderByDescending(r => r.Momentum).ToList(),
            DormantThreats = dormant.OrderByDescending(d => d.RecurrenceProbability).ToList(),
            FadingThreats = fading.OrderBy(f => f.Momentum).ToList(),
            Prophecies = prophecies,
            Recommendations = recommendations,
            ModuleMomentum = moduleMomentum,
            AnalyzedRuns = runs.Count,
            ForecastDays = forecastDays
        };
    }

    // ── Helpers ──────────────────────────────────────────────────

    sealed class FindingStats
    {
        public int Count { get; set; }
        public string? MaxSeverity { get; set; }
        public string? PrimaryModule { get; set; }
        public string? SampleTitle { get; set; }
    }

    static int SeverityRank(string sev) => sev switch
    {
        "Critical" => 3,
        "Warning" => 2,
        "Info" => 1,
        _ => 0
    };

    Dictionary<string, FindingStats> AggregateFindings(List<AuditRunRecord> runs)
    {
        var map = new Dictionary<string, FindingStats>(StringComparer.OrdinalIgnoreCase);
        foreach (var run in runs)
        {
            foreach (var finding in run.Findings)
            {
                var cat = finding.ModuleName ?? "Uncategorized";
                if (!map.TryGetValue(cat, out var stats))
                {
                    stats = new FindingStats { PrimaryModule = finding.ModuleName, SampleTitle = finding.Title };
                    map[cat] = stats;
                }
                stats.Count++;
                if (SeverityRank(finding.Severity) > SeverityRank(stats.MaxSeverity ?? "Pass"))
                    stats.MaxSeverity = finding.Severity;
            }
        }
        return map;
    }

    static double SeverityWeight(string sev) => sev switch
    {
        "Critical" => 4.0,
        "Warning" => 2.5,
        "Info" => 1.5,
        _ => 1.0
    };
}

// ── Models ──────────────────────────────────────────────────────

public sealed class ProphecyReport
{
    public int StormProbability { get; set; }
    public string Outlook { get; set; } = "";
    public List<ThreatPrediction> RisingThreats { get; set; } = [];
    public List<ThreatPrediction> DormantThreats { get; set; } = [];
    public List<ThreatPrediction> FadingThreats { get; set; } = [];
    public List<string> Prophecies { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public Dictionary<string, double> ModuleMomentum { get; set; } = new();
    public int AnalyzedRuns { get; set; }
    public int ForecastDays { get; set; }
}

public sealed class ThreatPrediction
{
    public string Category { get; set; } = "";
    public string Module { get; set; } = "";
    public string Description { get; set; } = "";
    public double Momentum { get; set; }
    public string Severity { get; set; } = "";
    public int OccurrencesRecent { get; set; }
    public int OccurrencesOlder { get; set; }
    public double RecurrenceProbability { get; set; }
    public string Confidence { get; set; } = "";
}
