using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Tunable thresholds for <see cref="AnomalyWatchdogService"/>.
/// Defaults preserve the original (pre-refactor) detection behaviour so this
/// type is drop-in safe; callers that need different sensitivity can supply
/// a custom instance.
/// </summary>
public sealed class WatchdogConfig
{
    /// <summary>Z-score at which a score drop / finding spike is treated as a Warning.</summary>
    public double ZThresholdWarn { get; init; } = 1.5;

    /// <summary>Z-score at which a score drop / finding spike is treated as Critical.</summary>
    public double ZThresholdCrit { get; init; } = 2.5;

    /// <summary>Absolute score drop (regardless of z-score) that triggers a Warning anomaly.</summary>
    public int MinorScoreDrop { get; init; } = 10;

    /// <summary>Absolute score drop (regardless of z-score) that is escalated to Critical.</summary>
    public int MajorScoreDrop { get; init; } = 20;

    /// <summary>Absolute jump in total finding count that triggers a Warning spike.</summary>
    public int FindingSpikeAbsolute { get; init; } = 5;

    /// <summary>Extra critical-finding deltas that escalate a spike to Critical.</summary>
    public int CriticalCountSpikeDelta { get; init; } = 2;

    /// <summary>Module score at or below this value classifies the trend as "Collapsed".</summary>
    public int ModuleCollapsedScore { get; init; } = 20;

    /// <summary>Per-module score drop (vs previous run) that triggers a regression entry.</summary>
    public int ModuleScoreDrop { get; init; } = 5;

    /// <summary>Number of consecutive backward drops that classify the trend as "Declining".</summary>
    public int ModuleDecliningStreak { get; init; } = 3;

    /// <summary>Number of consecutive backward drops that classify the trend as "Volatile".</summary>
    public int ModuleVolatileStreak { get; init; } = 2;

    /// <summary>How many recent runs (with module data) the regression detector looks at.</summary>
    public int RecentModuleRunWindow { get; init; } = 10;

    /// <summary>Latest overall score at/below which a "consider --fix-all" recommendation is emitted.</summary>
    public int LowScoreRecommendationThreshold { get; init; } = 50;
}

/// <summary>
/// Security Anomaly Watchdog - proactively detects score drops, finding spikes,
/// and module regressions using statistical analysis of audit history.
/// </summary>
public class AnomalyWatchdogService
{
    private readonly WatchdogConfig _cfg;

    public AnomalyWatchdogService(double zThresholdWarn = 1.5, double zThresholdCrit = 2.5)
        : this(new WatchdogConfig { ZThresholdWarn = zThresholdWarn, ZThresholdCrit = zThresholdCrit })
    {
    }

    public AnomalyWatchdogService(WatchdogConfig config)
    {
        _cfg = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// Analyze audit history for anomalies.
    /// </summary>
    public WatchdogReport Analyze(List<AuditRunRecord> runs, int days)
    {
        ArgumentNullException.ThrowIfNull(runs);

        var report = new WatchdogReport { DaysAnalyzed = days, RunsAnalyzed = runs.Count };

        if (runs.Count < 2)
        {
            report.Recommendations.Add("Need at least 2 audit runs for anomaly detection. Run more audits!");
            return report;
        }

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var scores = ordered.Select(r => (double)r.OverallScore).ToList();
        var findings = ordered.Select(r => (double)r.TotalFindings).ToList();

        // Compute stats
        var stats = new WatchdogStats
        {
            MeanScore = Mean(scores),
            StdDevScore = StdDev(scores),
            MeanFindings = Mean(findings),
            StdDevFindings = StdDev(findings),
            LatestScore = ordered.Last().OverallScore,
            LatestFindings = ordered.Last().TotalFindings
        };

        if (stats.StdDevScore > 0)
            stats.ScoreZScore = Math.Round((stats.LatestScore!.Value - stats.MeanScore) / stats.StdDevScore, 2);
        if (stats.StdDevFindings > 0)
            stats.FindingsZScore = Math.Round((stats.LatestFindings!.Value - stats.MeanFindings) / stats.StdDevFindings, 2);

        report.Stats = stats;

        DetectScoreAnomalies(ordered, stats, report);
        DetectFindingSpikes(ordered, stats, report);
        DetectModuleRegressions(ordered, report);

        report.TotalAnomalies = report.ScoreAnomalies.Count + report.FindingSpikes.Count + report.ModuleRegressions.Count;

        if (report.ScoreAnomalies.Any(a => a.Severity == "Critical") ||
            report.FindingSpikes.Any(f => f.Severity == "Critical") ||
            report.ModuleRegressions.Any(m => m.Trend == "Collapsed"))
        {
            report.OverallStatus = "ALERT";
        }
        else if (report.TotalAnomalies > 0)
        {
            report.OverallStatus = "WARN";
        }

        GenerateRecommendations(report);

        return report;
    }

    private void DetectScoreAnomalies(List<AuditRunRecord> ordered, WatchdogStats stats, WatchdogReport report)
    {
        for (int i = 1; i < ordered.Count; i++)
        {
            var curr = ordered[i];
            var prev = ordered[i - 1];
            var drop = prev.OverallScore - curr.OverallScore;

            if (drop <= 0) continue;

            double zScore = stats.StdDevScore > 0
                ? Math.Round(drop / stats.StdDevScore, 2)
                : 0;

            if (zScore >= _cfg.ZThresholdWarn || drop >= _cfg.MinorScoreDrop)
            {
                var isCritical = zScore >= _cfg.ZThresholdCrit || drop >= _cfg.MajorScoreDrop;
                report.ScoreAnomalies.Add(new ScoreAnomaly
                {
                    Timestamp = curr.Timestamp,
                    Score = curr.OverallScore,
                    PreviousScore = prev.OverallScore,
                    Drop = drop,
                    ZScore = zScore,
                    Severity = isCritical ? "Critical" : "Warning",
                    Reason = drop >= _cfg.MajorScoreDrop ? "Major score collapse" :
                             zScore >= _cfg.ZThresholdCrit ? "Statistically significant drop" :
                             "Notable score decrease"
                });
            }
        }
    }

    private void DetectFindingSpikes(List<AuditRunRecord> ordered, WatchdogStats stats, WatchdogReport report)
    {
        for (int i = 1; i < ordered.Count; i++)
        {
            var curr = ordered[i];
            var prev = ordered[i - 1];
            var increase = curr.TotalFindings - prev.TotalFindings;

            if (increase <= 0) continue;

            double zScore = stats.StdDevFindings > 0
                ? Math.Round(increase / stats.StdDevFindings, 2)
                : 0;

            if (zScore >= _cfg.ZThresholdWarn || increase >= _cfg.FindingSpikeAbsolute)
            {
                var isCritical = zScore >= _cfg.ZThresholdCrit
                              || curr.CriticalCount > prev.CriticalCount + _cfg.CriticalCountSpikeDelta;
                report.FindingSpikes.Add(new FindingSpike
                {
                    Timestamp = curr.Timestamp,
                    TotalFindings = curr.TotalFindings,
                    PreviousFindings = prev.TotalFindings,
                    Increase = increase,
                    ZScore = zScore,
                    CriticalCount = curr.CriticalCount,
                    Severity = isCritical ? "Critical" : "Warning"
                });
            }
        }
    }

    private void DetectModuleRegressions(List<AuditRunRecord> ordered, WatchdogReport report)
    {
        // Look at the most recent N runs that actually contain module data.
        var recentWithModules = ordered.Where(r => r.ModuleScores.Count > 0)
                                       .TakeLast(_cfg.RecentModuleRunWindow)
                                       .ToList();
        if (recentWithModules.Count < 2) return;

        var latestRun = recentWithModules[^1];
        var previousRun = recentWithModules[^2];

        var latestModules = latestRun.ModuleScores
            .GroupBy(m => m.ModuleName)
            .ToDictionary(g => g.Key, g => g.Last().Score);
        var previousModules = previousRun.ModuleScores
            .GroupBy(m => m.ModuleName)
            .ToDictionary(g => g.Key, g => g.Last().Score);

        foreach (var (module, currentScore) in latestModules)
        {
            if (!previousModules.TryGetValue(module, out var prevScore)) continue;
            var drop = prevScore - currentScore;
            if (drop <= 0) continue;

            // Count consecutive drops walking back through the recent window.
            int consecutiveDrops = 0;
            int lastScore = currentScore;
            for (int i = recentWithModules.Count - 2; i >= 0; i--)
            {
                var ms = recentWithModules[i].ModuleScores.FirstOrDefault(m => m.ModuleName == module);
                if (ms == null) break;
                if (ms.Score > lastScore)
                {
                    consecutiveDrops++;
                    lastScore = ms.Score;
                }
                else
                {
                    break;
                }
            }

            if (drop >= _cfg.ModuleScoreDrop || consecutiveDrops >= _cfg.ModuleVolatileStreak)
            {
                var trend = currentScore <= _cfg.ModuleCollapsedScore ? "Collapsed" :
                            consecutiveDrops >= _cfg.ModuleDecliningStreak ? "Declining" :
                            "Volatile";

                report.ModuleRegressions.Add(new ModuleRegression
                {
                    ModuleName = module,
                    CurrentScore = currentScore,
                    PreviousScore = prevScore,
                    ScoreDrop = drop,
                    ConsecutiveDrops = consecutiveDrops,
                    Trend = trend
                });
            }
        }
    }

    private void GenerateRecommendations(WatchdogReport report)
    {
        if (report.ScoreAnomalies.Any(a => a.Severity == "Critical"))
            report.Recommendations.Add("🚨 Critical score drops detected — run a full audit and review recent system changes.");

        if (report.FindingSpikes.Any(f => f.CriticalCount > 3))
            report.Recommendations.Add("⚠️ Multiple critical findings emerging — prioritize remediation of critical items.");

        if (report.ModuleRegressions.Any(m => m.Trend == "Collapsed"))
            report.Recommendations.Add("💀 Module(s) collapsed to near-zero — investigate if a service or config was disabled.");

        if (report.ModuleRegressions.Any(m => m.ConsecutiveDrops >= _cfg.ModuleDecliningStreak))
            report.Recommendations.Add("📉 Sustained module regression detected — check for persistent misconfiguration.");

        if (report.TotalAnomalies == 0)
            report.Recommendations.Add("✅ No anomalies detected. Security posture is stable.");

        if (report.Stats.LatestScore.HasValue && report.Stats.LatestScore.Value < _cfg.LowScoreRecommendationThreshold)
            report.Recommendations.Add("🔴 Current score is below 50 — consider running --fix-all to remediate known issues.");
    }

    private static double Mean(List<double> values) =>
        values.Count == 0 ? 0 : Math.Round(values.Average(), 2);

    private static double StdDev(List<double> values)
    {
        if (values.Count < 2) return 0;
        var mean = values.Average();
        var sumSquares = values.Sum(v => (v - mean) * (v - mean));
        return Math.Round(Math.Sqrt(sumSquares / (values.Count - 1)), 2);
    }
}
