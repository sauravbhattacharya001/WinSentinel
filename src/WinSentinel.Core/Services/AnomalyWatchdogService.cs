using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Security Anomaly Watchdog — proactively detects score drops, finding spikes,
/// and module regressions using statistical analysis of audit history.
/// </summary>
public class AnomalyWatchdogService
{
    private readonly double _zThresholdWarn;
    private readonly double _zThresholdCrit;

    public AnomalyWatchdogService(double zThresholdWarn = 1.5, double zThresholdCrit = 2.5)
    {
        _zThresholdWarn = zThresholdWarn;
        _zThresholdCrit = zThresholdCrit;
    }

    /// <summary>
    /// Analyze audit history for anomalies.
    /// </summary>
    public WatchdogReport Analyze(List<AuditRunRecord> runs, int days)
    {
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
            stats.ScoreZScore = Math.Round((stats.LatestScore.Value - stats.MeanScore) / stats.StdDevScore, 2);
        if (stats.StdDevFindings > 0)
            stats.FindingsZScore = Math.Round((stats.LatestFindings.Value - stats.MeanFindings) / stats.StdDevFindings, 2);

        report.Stats = stats;

        // Detect score anomalies (drops)
        DetectScoreAnomalies(ordered, stats, report);

        // Detect finding spikes
        DetectFindingSpikes(ordered, stats, report);

        // Detect module regressions
        DetectModuleRegressions(ordered, report);

        // Set overall status
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

        // Generate recommendations
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

            // Check if drop is anomalous using z-score on score deltas
            double zScore = 0;
            if (stats.StdDevScore > 0)
                zScore = Math.Round(drop / stats.StdDevScore, 2);

            if (zScore >= _zThresholdWarn || drop >= 10)
            {
                report.ScoreAnomalies.Add(new ScoreAnomaly
                {
                    Timestamp = curr.Timestamp,
                    Score = curr.OverallScore,
                    PreviousScore = prev.OverallScore,
                    Drop = drop,
                    ZScore = zScore,
                    Severity = zScore >= _zThresholdCrit || drop >= 20 ? "Critical" : "Warning",
                    Reason = drop >= 20 ? "Major score collapse" :
                             zScore >= _zThresholdCrit ? "Statistically significant drop" :
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

            double zScore = 0;
            if (stats.StdDevFindings > 0)
                zScore = Math.Round(increase / stats.StdDevFindings, 2);

            if (zScore >= _zThresholdWarn || increase >= 5)
            {
                report.FindingSpikes.Add(new FindingSpike
                {
                    Timestamp = curr.Timestamp,
                    TotalFindings = curr.TotalFindings,
                    PreviousFindings = prev.TotalFindings,
                    Increase = increase,
                    ZScore = zScore,
                    CriticalCount = curr.CriticalCount,
                    Severity = zScore >= _zThresholdCrit || curr.CriticalCount > prev.CriticalCount + 2 ? "Critical" : "Warning"
                });
            }
        }
    }

    private void DetectModuleRegressions(List<AuditRunRecord> ordered, WatchdogReport report)
    {
        // Get the last few runs with module data
        var recentWithModules = ordered.Where(r => r.ModuleScores.Count > 0).TakeLast(10).ToList();
        if (recentWithModules.Count < 2) return;

        var latestRun = recentWithModules.Last();
        var previousRun = recentWithModules[^2];

        // Group module scores
        var latestModules = latestRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);
        var previousModules = previousRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);

        foreach (var (module, currentScore) in latestModules)
        {
            if (!previousModules.TryGetValue(module, out var prevScore)) continue;
            var drop = prevScore - currentScore;
            if (drop <= 0) continue;

            // Count consecutive drops for this module
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
                else break;
            }

            if (drop >= 5 || consecutiveDrops >= 2)
            {
                var trend = currentScore <= 20 ? "Collapsed" :
                            consecutiveDrops >= 3 ? "Declining" : "Volatile";

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

        if (report.ModuleRegressions.Any(m => m.ConsecutiveDrops >= 3))
            report.Recommendations.Add("📉 Sustained module regression detected — check for persistent misconfiguration.");

        if (report.TotalAnomalies == 0)
            report.Recommendations.Add("✅ No anomalies detected. Security posture is stable.");

        if (report.Stats.LatestScore.HasValue && report.Stats.LatestScore.Value < 50)
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
