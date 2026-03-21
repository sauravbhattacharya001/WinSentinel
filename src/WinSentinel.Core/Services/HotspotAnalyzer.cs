using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Identifies security hotspots — categories and modules that consistently
/// produce the most findings across audit history. Uses frequency, severity
/// weighting, and persistence to compute a composite "heat score" that
/// highlights chronic problem areas deserving focused remediation.
/// </summary>
public class HotspotAnalyzer
{
    // ── Severity weights for heat score calculation ───────────────────
    private const double CriticalWeight = 4.0;
    private const double WarningWeight = 2.0;
    private const double InfoWeight = 0.5;

    /// <summary>A single hotspot entry (category or module).</summary>
    public record Hotspot(
        string Name,
        string Kind,
        double HeatScore,
        int Appearances,
        int TotalRuns,
        double AppearanceRate,
        int TotalFindings,
        int CriticalFindings,
        int WarningFindings,
        int InfoFindings,
        double AvgFindingsPerRun,
        string Trend,
        string HeatLevel);

    /// <summary>Complete hotspot analysis result.</summary>
    public class HotspotResult
    {
        public List<Hotspot> CategoryHotspots { get; init; } = [];
        public List<Hotspot> ModuleHotspots { get; init; } = [];
        public int RunsAnalyzed { get; init; }
        public int DaysSpan { get; init; }
        public string HottestCategory { get; init; } = "";
        public string HottestModule { get; init; } = "";
        public double OverallHeat { get; init; }
        public string OverallHeatLevel { get; init; } = "";
    }

    /// <summary>
    /// Analyze audit history to identify security hotspots.
    /// </summary>
    /// <param name="runs">Historical audit runs, most recent first.</param>
    /// <param name="maxRuns">Maximum runs to analyze (0 = all).</param>
    public HotspotResult Analyze(List<AuditRunRecord> runs, int maxRuns = 0)
    {
        if (runs.Count == 0)
        {
            return new HotspotResult
            {
                OverallHeatLevel = "None",
            };
        }

        var subset = maxRuns > 0 && maxRuns < runs.Count ? runs.Take(maxRuns).ToList() : runs;
        var totalRuns = subset.Count;

        var oldest = subset.Min(r => r.Timestamp);
        var newest = subset.Max(r => r.Timestamp);
        var daysSpan = Math.Max(1, (int)(newest - oldest).TotalDays);

        // Accumulate per-category and per-module stats
        var categoryStats = new Dictionary<string, HotspotAccumulator>(StringComparer.OrdinalIgnoreCase);
        var moduleStats = new Dictionary<string, HotspotAccumulator>(StringComparer.OrdinalIgnoreCase);

        foreach (var run in subset)
        {
            var categoriesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var modulesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var ms in run.ModuleScores)
            {
                var cat = string.IsNullOrWhiteSpace(ms.Category) ? "Uncategorized" : ms.Category;

                if (!moduleStats.TryGetValue(ms.ModuleName, out var mAcc))
                {
                    mAcc = new HotspotAccumulator { Name = ms.ModuleName, Kind = "Module" };
                    moduleStats[ms.ModuleName] = mAcc;
                }
                mAcc.CriticalFindings += ms.CriticalCount;
                mAcc.WarningFindings += ms.WarningCount;
                mAcc.InfoFindings += Math.Max(0, ms.FindingCount - ms.CriticalCount - ms.WarningCount);
                mAcc.TotalFindings += ms.FindingCount;
                if (ms.FindingCount > 0 && modulesSeen.Add(ms.ModuleName))
                    mAcc.Appearances++;

                if (!categoryStats.TryGetValue(cat, out var cAcc))
                {
                    cAcc = new HotspotAccumulator { Name = cat, Kind = "Category" };
                    categoryStats[cat] = cAcc;
                }
                cAcc.CriticalFindings += ms.CriticalCount;
                cAcc.WarningFindings += ms.WarningCount;
                cAcc.InfoFindings += Math.Max(0, ms.FindingCount - ms.CriticalCount - ms.WarningCount);
                cAcc.TotalFindings += ms.FindingCount;
                if (ms.FindingCount > 0 && categoriesSeen.Add(cat))
                    cAcc.Appearances++;
            }
        }

        // Compute trend from last 2 runs if available
        var recentRun = subset.Count >= 1 ? subset[0] : null;
        var previousRun = subset.Count >= 2 ? subset[1] : null;

        var categoryHotspots = ComputeHotspots(categoryStats.Values, totalRuns, recentRun, previousRun, "Category");
        var moduleHotspots = ComputeHotspots(moduleStats.Values, totalRuns, recentRun, previousRun, "Module");

        var hottestCat = categoryHotspots.Count > 0 ? categoryHotspots[0].Name : "None";
        var hottestMod = moduleHotspots.Count > 0 ? moduleHotspots[0].Name : "None";

        var overallHeat = categoryHotspots.Count > 0
            ? categoryHotspots.Average(h => h.HeatScore)
            : 0;

        return new HotspotResult
        {
            CategoryHotspots = categoryHotspots,
            ModuleHotspots = moduleHotspots,
            RunsAnalyzed = totalRuns,
            DaysSpan = daysSpan,
            HottestCategory = hottestCat,
            HottestModule = hottestMod,
            OverallHeat = overallHeat,
            OverallHeatLevel = ClassifyHeat(overallHeat),
        };
    }

    private static List<Hotspot> ComputeHotspots(
        IEnumerable<HotspotAccumulator> accumulators,
        int totalRuns,
        AuditRunRecord? recentRun,
        AuditRunRecord? previousRun,
        string kind)
    {
        var hotspots = new List<Hotspot>();

        foreach (var acc in accumulators)
        {
            if (acc.TotalFindings == 0) continue;

            var appearanceRate = totalRuns > 0 ? (double)acc.Appearances / totalRuns : 0;
            var avgPerRun = acc.Appearances > 0 ? (double)acc.TotalFindings / acc.Appearances : 0;

            // Heat = severity-weighted findings × persistence rate
            var severityScore = acc.CriticalFindings * CriticalWeight
                              + acc.WarningFindings * WarningWeight
                              + acc.InfoFindings * InfoWeight;
            var heatScore = severityScore * (0.5 + 0.5 * appearanceRate);

            var trend = ComputeTrend(acc.Name, kind, recentRun, previousRun);

            hotspots.Add(new Hotspot(
                acc.Name,
                kind,
                Math.Round(heatScore, 1),
                acc.Appearances,
                totalRuns,
                Math.Round(appearanceRate * 100, 1),
                acc.TotalFindings,
                acc.CriticalFindings,
                acc.WarningFindings,
                acc.InfoFindings,
                Math.Round(avgPerRun, 1),
                trend,
                ClassifyHeat(heatScore)));
        }

        return hotspots.OrderByDescending(h => h.HeatScore).ToList();
    }

    private static string ComputeTrend(string name, string kind, AuditRunRecord? recent, AuditRunRecord? previous)
    {
        if (recent == null || previous == null) return "—";

        int recentCount, previousCount;
        if (kind == "Category")
        {
            recentCount = recent.ModuleScores.Where(m => m.Category.Equals(name, StringComparison.OrdinalIgnoreCase)).Sum(m => m.FindingCount);
            previousCount = previous.ModuleScores.Where(m => m.Category.Equals(name, StringComparison.OrdinalIgnoreCase)).Sum(m => m.FindingCount);
        }
        else
        {
            recentCount = recent.ModuleScores.Where(m => m.ModuleName.Equals(name, StringComparison.OrdinalIgnoreCase)).Sum(m => m.FindingCount);
            previousCount = previous.ModuleScores.Where(m => m.ModuleName.Equals(name, StringComparison.OrdinalIgnoreCase)).Sum(m => m.FindingCount);
        }

        if (recentCount > previousCount) return "↑ Worsening";
        if (recentCount < previousCount) return "↓ Improving";
        return "→ Stable";
    }

    private static string ClassifyHeat(double score)
    {
        return score switch
        {
            >= 50 => "🔴 Critical",
            >= 25 => "🟠 High",
            >= 10 => "🟡 Medium",
            >= 3 => "🔵 Low",
            _ => "⚪ Minimal"
        };
    }

    private class HotspotAccumulator
    {
        public string Name { get; set; } = "";
        public string Kind { get; set; } = "";
        public int Appearances { get; set; }
        public int TotalFindings { get; set; }
        public int CriticalFindings { get; set; }
        public int WarningFindings { get; set; }
        public int InfoFindings { get; set; }
    }
}
