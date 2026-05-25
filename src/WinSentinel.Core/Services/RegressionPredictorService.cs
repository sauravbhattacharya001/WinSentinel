namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Security Regression Predictor — analyzes audit history to identify
/// findings that repeatedly regress after being fixed, predicts which recent fixes
/// are most likely to fail, and generates stabilization recommendations.
/// </summary>
public sealed class RegressionPredictorService
{
    private readonly AuditHistoryService _history;

    public RegressionPredictorService(AuditHistoryService history) => _history = history;

    public RegressionReport Analyze(int days = 90, string? moduleFilter = null, int topN = 15)
    {
        var runs = _history.GetHistoryWithFindings(days);
        if (runs.Count < 3) return new RegressionReport { AnalyzedRuns = runs.Count, AnalyzedDays = days };

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var report = new RegressionReport
        {
            AnalyzedRuns = ordered.Count,
            AnalyzedDays = days,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var findingLifecycles = BuildFindingLifecycles(ordered, moduleFilter);

        var yoyoFindings = DetectRegressions(findingLifecycles, ordered.Count);
        report.YoYoFindings = yoyoFindings
            .OrderByDescending(f => f.RegressionCount)
            .ThenByDescending(f => SeverityWeight(f.Severity))
            .Take(topN)
            .ToList();

        report.TotalRegressionsFound = yoyoFindings.Sum(f => f.RegressionCount);

        var currentFindings = new HashSet<string>(
            ordered.Last().Findings.Select(f => f.Title), StringComparer.OrdinalIgnoreCase);

        var recentlyFixed = FindRecentlyFixed(ordered, currentFindings);
        report.AtRiskFixes = PredictRegressions(recentlyFixed, findingLifecycles, ordered.Count, topN);

        report.ModuleProfiles = BuildModuleProfiles(yoyoFindings, ordered);

        var totalFixes = findingLifecycles.Values.Sum(lc => lc.FixCount);
        report.OverallRegressionRate = totalFixes > 0
            ? Math.Round((double)report.TotalRegressionsFound / totalFixes, 3)
            : 0;

        report.RegressionScore = CalculateRegressionScore(report);
        report.RiskLevel = report.RegressionScore switch
        {
            >= 75 => "Critical",
            >= 50 => "High",
            >= 25 => "Medium",
            _ => "Low"
        };

        report.Recommendations = GenerateRecommendations(report);

        return report;
    }

    // ── Finding Lifecycle Tracking ───────────────────────────────────

    private sealed class FindingLifecycle
    {
        public string Title { get; set; } = "";
        public string Module { get; set; } = "";
        public string Severity { get; set; } = "";
        public bool[] Presence { get; set; } = [];
        public int FixCount { get; set; }
        public int RegressionCount { get; set; }
        public List<int> FixDurations { get; set; } = [];
    }

    private static Dictionary<string, FindingLifecycle> BuildFindingLifecycles(
        List<AuditRunRecord> runs, string? moduleFilter)
    {
        var lifecycles = new Dictionary<string, FindingLifecycle>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < runs.Count; i++)
        {
            foreach (var f in runs[i].Findings)
            {
                if (moduleFilter != null &&
                    !f.ModuleName.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!lifecycles.TryGetValue(f.Title, out var lc))
                {
                    lc = new FindingLifecycle
                    {
                        Title = f.Title,
                        Module = f.ModuleName,
                        Severity = f.Severity,
                        Presence = new bool[runs.Count]
                    };
                    lifecycles[f.Title] = lc;
                }
                lc.Presence[i] = true;
                if (SeverityWeight(f.Severity) > SeverityWeight(lc.Severity))
                    lc.Severity = f.Severity;
            }
        }

        foreach (var lc in lifecycles.Values)
        {
            bool wasPresent = false;
            int fixedAtRun = -1;

            for (int i = 0; i < lc.Presence.Length; i++)
            {
                if (wasPresent && !lc.Presence[i])
                {
                    lc.FixCount++;
                    fixedAtRun = i;
                }
                else if (!wasPresent && lc.Presence[i] && fixedAtRun >= 0)
                {
                    lc.RegressionCount++;
                    lc.FixDurations.Add(i - fixedAtRun);
                    fixedAtRun = -1;
                }
                wasPresent = lc.Presence[i];
            }
        }

        return lifecycles;
    }

    // ── Regression Detection ─────────────────────────────────────────

    private static List<RegressionFinding> DetectRegressions(
        Dictionary<string, FindingLifecycle> lifecycles, int totalRuns)
    {
        var results = new List<RegressionFinding>();

        foreach (var lc in lifecycles.Values)
        {
            if (lc.RegressionCount == 0) continue;

            var appearances = lc.Presence.Count(p => p);
            var avgFixDuration = lc.FixDurations.Count > 0
                ? lc.FixDurations.Average()
                : 0;

            var regressionRate = lc.FixCount > 0
                ? (double)lc.RegressionCount / lc.FixCount
                : 0;

            results.Add(new RegressionFinding
            {
                Title = lc.Title,
                Module = lc.Module,
                Severity = lc.Severity,
                RegressionCount = lc.RegressionCount,
                TotalAppearances = appearances,
                RegressionRate = Math.Round(regressionRate, 2),
                AverageFixDuration = Math.Round(avgFixDuration, 1),
                Pattern = ClassifyPattern(lc),
                RootCauseHint = InferRootCause(lc, totalRuns)
            });
        }

        return results;
    }

    private static string ClassifyPattern(FindingLifecycle lc)
    {
        if (lc.RegressionCount >= 3) return "Chronic";

        if (lc.FixDurations.Count >= 2)
        {
            var avg = lc.FixDurations.Average();
            var variance = lc.FixDurations.Sum(d => (d - avg) * (d - avg)) / lc.FixDurations.Count;
            var cv = avg > 0 ? Math.Sqrt(variance) / avg : 0;
            if (cv < 0.4) return "Periodic";
        }

        return "Sporadic";
    }

    private static string InferRootCause(FindingLifecycle lc, int totalRuns)
    {
        if (lc.FixDurations.Count > 0 && lc.FixDurations.Average() <= 2)
            return "Quick regression suggests superficial fix — root cause likely unaddressed";

        if (lc.RegressionCount >= 3)
            return "Chronic regression indicates systemic issue or recurring configuration drift";

        var appearances = lc.Presence.Count(p => p);
        if (appearances > totalRuns * 0.7)
            return "Finding present in most scans — likely a persistent environmental issue";

        if (lc.FixDurations.Count >= 2)
        {
            var avg = lc.FixDurations.Average();
            var variance = lc.FixDurations.Sum(d => (d - avg) * (d - avg)) / lc.FixDurations.Count;
            if (Math.Sqrt(variance) / Math.Max(avg, 0.01) < 0.4)
                return "Periodic pattern suggests scheduled process or policy that reverts the fix";
        }

        return "Insufficient data for root cause inference";
    }

    // ── Recently Fixed Detection ─────────────────────────────────────

    private static Dictionary<string, (string Module, string Severity, int LastSeenRun)> FindRecentlyFixed(
        List<AuditRunRecord> runs, HashSet<string> currentFindings)
    {
        var recentlyFixed = new Dictionary<string, (string Module, string Severity, int LastSeenRun)>(
            StringComparer.OrdinalIgnoreCase);

        var lookback = Math.Min(5, runs.Count - 1);
        for (int i = runs.Count - 2; i >= runs.Count - 1 - lookback && i >= 0; i--)
        {
            foreach (var f in runs[i].Findings)
            {
                if (!currentFindings.Contains(f.Title) && !recentlyFixed.ContainsKey(f.Title))
                {
                    recentlyFixed[f.Title] = (f.ModuleName, f.Severity, i);
                }
            }
        }

        return recentlyFixed;
    }

    // ── Regression Prediction ────────────────────────────────────────

    private static List<RegressionPrediction> PredictRegressions(
        Dictionary<string, (string Module, string Severity, int LastSeenRun)> recentlyFixed,
        Dictionary<string, FindingLifecycle> lifecycles,
        int totalRuns,
        int topN)
    {
        var predictions = new List<RegressionPrediction>();

        foreach (var (title, info) in recentlyFixed)
        {
            double probability;
            string confidence;
            int pastRegressions = 0;

            if (lifecycles.TryGetValue(title, out var lc))
            {
                pastRegressions = lc.RegressionCount;
                var regressionRate = lc.FixCount > 0 ? (double)lc.RegressionCount / lc.FixCount : 0;
                probability = regressionRate;

                if (pastRegressions >= 2) probability = Math.Min(1.0, probability + 0.2);
                else if (pastRegressions >= 1) probability = Math.Min(1.0, probability + 0.1);

                if (lc.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
                    probability = Math.Min(1.0, probability + 0.05);

                if (lc.FixDurations.Count > 0 && lc.FixDurations.Average() <= 2)
                    probability = Math.Min(1.0, probability + 0.15);

                confidence = lc.FixCount >= 3 ? "High" : lc.FixCount >= 1 ? "Medium" : "Low";
            }
            else
            {
                probability = 0.1;
                confidence = "Low";
            }

            var runsSinceFix = totalRuns - 1 - info.LastSeenRun;

            predictions.Add(new RegressionPrediction
            {
                Title = title,
                Module = info.Module,
                Severity = info.Severity,
                RegressionProbability = Math.Round(probability, 2),
                Confidence = confidence,
                RunsSinceFix = runsSinceFix,
                PastRegressions = pastRegressions,
                RecommendedAction = GetRecommendedAction(probability, pastRegressions, info.Severity)
            });
        }

        return predictions
            .OrderByDescending(p => p.RegressionProbability)
            .ThenByDescending(p => SeverityWeight(p.Severity))
            .Take(topN)
            .ToList();
    }

    private static string GetRecommendedAction(double probability, int pastRegressions, string severity)
    {
        if (probability >= 0.7)
            return "Investigate root cause immediately — this fix is likely to fail again";
        if (probability >= 0.5)
            return "Add monitoring/alerting for this finding — moderate regression risk";
        if (pastRegressions >= 2)
            return "Review fix approach — previous remediation attempts have not held";
        if (severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) && probability >= 0.3)
            return "Verify fix with additional validation — critical finding with regression history";
        return "Monitor in upcoming scans";
    }

    // ── Module Profiles ──────────────────────────────────────────────

    private static List<ModuleRegressionProfile> BuildModuleProfiles(
        List<RegressionFinding> yoyoFindings,
        List<AuditRunRecord> runs)
    {
        var latest = runs.Last();
        var moduleFindings = latest.Findings
            .GroupBy(f => f.ModuleName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var moduleRegressions = yoyoFindings
            .GroupBy(f => f.Module, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var profiles = new List<ModuleRegressionProfile>();
        var allModules = new HashSet<string>(moduleFindings.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var k in moduleRegressions.Keys) allModules.Add(k);

        foreach (var module in allModules)
        {
            moduleFindings.TryGetValue(module, out var totalFindings);
            moduleRegressions.TryGetValue(module, out var regressions);
            var regCount = regressions?.Sum(r => r.RegressionCount) ?? 0;
            var regRate = totalFindings > 0 ? (double)regCount / totalFindings : 0;

            profiles.Add(new ModuleRegressionProfile
            {
                ModuleName = module,
                TotalFindings = totalFindings,
                RegressionCount = regCount,
                RegressionRate = Math.Round(regRate, 2),
                Stability = regRate switch
                {
                    >= 0.5 => "Volatile",
                    >= 0.2 => "Shaky",
                    _ => "Stable"
                },
                TopYoYoFinding = regressions?.OrderByDescending(r => r.RegressionCount)
                    .FirstOrDefault()?.Title ?? "—"
            });
        }

        return profiles.OrderByDescending(p => p.RegressionRate).ToList();
    }

    // ── Scoring & Recommendations ────────────────────────────────────

    private static int CalculateRegressionScore(RegressionReport report)
    {
        double score = 0;
        score += Math.Min(30, report.OverallRegressionRate * 100);
        score += Math.Min(25, report.YoYoFindings.Count * 5);

        var chronicCount = report.YoYoFindings.Count(f => f.Pattern == "Chronic");
        score += Math.Min(25, chronicCount * 10);

        var highRiskPredictions = report.AtRiskFixes.Count(p => p.RegressionProbability >= 0.5);
        score += Math.Min(20, highRiskPredictions * 5);

        return (int)Math.Min(100, Math.Round(score));
    }

    private static List<string> GenerateRecommendations(RegressionReport report)
    {
        var recs = new List<string>();

        if (report.YoYoFindings.Any(f => f.Pattern == "Chronic"))
        {
            var chronic = report.YoYoFindings.Where(f => f.Pattern == "Chronic").ToList();
            recs.Add($"\ud83d\udd34 {chronic.Count} chronic regression(s) detected — these findings keep returning despite fixes. Investigate root causes rather than applying surface-level remediations.");
        }

        if (report.YoYoFindings.Any(f => f.AverageFixDuration <= 2))
        {
            recs.Add("\u26a1 Some findings regress within 1-2 scans of being fixed — consider whether fixes are being reverted by automation, group policy, or scheduled tasks.");
        }

        var volatileModules = report.ModuleProfiles.Where(m => m.Stability == "Volatile").ToList();
        if (volatileModules.Count > 0)
        {
            var names = string.Join(", ", volatileModules.Select(m => m.ModuleName));
            recs.Add($"\ud83d\udd04 Volatile modules ({names}) have high regression rates — consider dedicated hardening sprints for these areas.");
        }

        var highRisk = report.AtRiskFixes.Where(p => p.RegressionProbability >= 0.7).ToList();
        if (highRisk.Count > 0)
        {
            recs.Add($"\u26a0\ufe0f {highRisk.Count} recently-fixed finding(s) have >70% regression probability — schedule verification scans within the next few days.");
        }

        if (report.OverallRegressionRate >= 0.3)
        {
            recs.Add("\ud83d\udcca Overall regression rate is above 30% — remediation quality may be suffering. Consider implementing fix verification workflows.");
        }

        if (report.RegressionScore <= 10)
        {
            recs.Add("\u2705 Low regression risk — fixes are holding well. Continue current remediation practices.");
        }

        if (recs.Count == 0)
        {
            recs.Add("\ud83d\udccb Some regressions detected but within acceptable limits. Monitor trends over time.");
        }

        return recs;
    }

    private static double SeverityWeight(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0
    };
}
