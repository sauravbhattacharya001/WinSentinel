using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Computes security KPI (Key Performance Indicator) metrics from audit history.
/// Provides MTTD, MTTR, recurrence rates, security debt, and health scoring.
/// </summary>
public class SecurityKpiService
{
    /// <summary>
    /// Compute KPI metrics from a list of detailed audit run records.
    /// Runs should be ordered oldest-first (ascending by timestamp).
    /// </summary>
    public SecurityKpiReport Compute(List<AuditRunRecord> runs, int requestedDays)
    {
        var report = new SecurityKpiReport();

        if (runs.Count == 0)
            return report;

        // Sort ascending by timestamp
        runs = runs.OrderBy(r => r.Timestamp).ToList();

        var first = runs.First();
        var last = runs.Last();

        report.RunsAnalyzed = runs.Count;
        report.DaysSpan = Math.Max(1, (int)(last.Timestamp - first.Timestamp).TotalDays);
        report.PeriodStart = first.Timestamp;
        report.PeriodEnd = last.Timestamp;
        report.TotalScans = runs.Count;

        // ── Score KPIs ─────────────────────────────────────
        report.CurrentScore = last.OverallScore;
        report.AverageScore = runs.Average(r => r.OverallScore);
        report.ScoreChange = last.OverallScore - first.OverallScore;
        report.ScoreTrend = report.ScoreChange > 5 ? "Improving"
            : report.ScoreChange < -5 ? "Declining"
            : "Stable";

        if (runs.Count > 1)
        {
            var scores = runs.Select(r => (double)r.OverallScore).ToList();
            var mean = scores.Average();
            var variance = scores.Sum(s => (s - mean) * (s - mean)) / scores.Count;
            report.ScoreVolatility = Math.Round(Math.Sqrt(variance), 1);
        }

        // ── Finding KPIs ───────────────────────────────────
        report.CurrentFindings = last.TotalFindings;
        report.AverageFindingsPerScan = Math.Round(runs.Average(r => r.TotalFindings), 1);
        report.FindingNetChange = last.TotalFindings - first.TotalFindings;

        // Track finding appearances across runs for new/resolved/recurring
        var findingFirstSeen = new Dictionary<string, int>(); // key -> run index
        var findingLastSeen = new Dictionary<string, int>();
        var findingAppearances = new Dictionary<string, List<int>>(); // key -> list of run indices

        for (int i = 0; i < runs.Count; i++)
        {
            foreach (var f in runs[i].Findings)
            {
                var key = $"{f.ModuleName}|{f.Title}";
                if (!findingFirstSeen.ContainsKey(key))
                    findingFirstSeen[key] = i;
                findingLastSeen[key] = i;

                if (!findingAppearances.ContainsKey(key))
                    findingAppearances[key] = [];
                findingAppearances[key].Add(i);
            }
        }

        // New findings: first seen after the first run
        report.NewFindings = findingFirstSeen.Count(kv => kv.Value > 0);

        // Resolved: present in earlier runs but not in the last run
        var lastRunFindings = new HashSet<string>(
            last.Findings.Select(f => $"{f.ModuleName}|{f.Title}"));
        report.ResolvedFindings = findingLastSeen.Count(kv =>
            kv.Value < runs.Count - 1 && !lastRunFindings.Contains(kv.Key));

        // Recurring: findings that disappeared then reappeared (gaps in appearance)
        int recurringCount = 0;
        foreach (var kv in findingAppearances)
        {
            var indices = kv.Value;
            if (indices.Count < 2) continue;
            for (int i = 1; i < indices.Count; i++)
            {
                if (indices[i] - indices[i - 1] > 1)
                {
                    recurringCount++;
                    break;
                }
            }
        }
        report.RecurringFindings = recurringCount;
        report.RecurrenceRate = findingAppearances.Count > 0
            ? Math.Round(100.0 * recurringCount / findingAppearances.Count, 1)
            : 0;

        // ── Severity KPIs ──────────────────────────────────
        report.CurrentCritical = last.CriticalCount;
        report.CurrentWarnings = last.WarningCount;
        report.PeakCritical = runs.Max(r => r.CriticalCount);
        report.AvgCriticalPerScan = Math.Round(runs.Average(r => r.CriticalCount), 1);

        // MTTR estimation: for findings that were resolved, estimate how long they persisted
        var criticalDurations = new List<double>();
        var warningDurations = new List<double>();

        foreach (var kv in findingAppearances)
        {
            var indices = kv.Value;
            var lastIdx = indices.Last();
            // Only count if resolved (not in last run)
            if (lastRunFindings.Contains(kv.Key)) continue;

            var firstIdx = indices.First();
            var durationDays = (runs[lastIdx].Timestamp - runs[firstIdx].Timestamp).TotalDays;
            if (durationDays < 0.01) durationDays = report.DaysSpan / (double)runs.Count; // min 1 scan interval

            // Determine severity from last appearance
            var severity = runs[lastIdx].Findings
                .FirstOrDefault(f => $"{f.ModuleName}|{f.Title}" == kv.Key)?.Severity;

            if (severity == "Critical")
                criticalDurations.Add(durationDays);
            else if (severity == "Warning")
                warningDurations.Add(durationDays);
        }

        report.MeanTimeToRemediateCritical = criticalDurations.Count > 0
            ? Math.Round(criticalDurations.Average(), 1) : null;
        report.MeanTimeToRemediateWarning = warningDurations.Count > 0
            ? Math.Round(warningDurations.Average(), 1) : null;

        // ── Security Debt ──────────────────────────────────
        static double ComputeDebt(AuditRunRecord run)
            => run.CriticalCount * 10.0 + run.WarningCount * 3.0 + run.InfoCount * 0.5;

        var currentDebt = ComputeDebt(last);
        var initialDebt = ComputeDebt(first);
        report.SecurityDebt = Math.Round(currentDebt, 1);
        report.DebtChange = Math.Round(currentDebt - initialDebt, 1);
        report.DebtTrend = report.DebtChange > 5 ? "Increasing"
            : report.DebtChange < -5 ? "Decreasing"
            : "Stable";

        // ── Scan Cadence ───────────────────────────────────
        if (runs.Count > 1)
        {
            var gaps = new List<double>();
            for (int i = 1; i < runs.Count; i++)
            {
                gaps.Add((runs[i].Timestamp - runs[i - 1].Timestamp).TotalDays);
            }
            report.AvgDaysBetweenScans = Math.Round(gaps.Average(), 1);
            report.MaxScanGap = Math.Round(gaps.Max(), 1);
        }

        report.ScansPerWeek = report.DaysSpan > 0
            ? Math.Round(7.0 * runs.Count / report.DaysSpan, 1) : runs.Count;

        // ── Module KPIs ────────────────────────────────────
        if (last.ModuleScores.Count > 0)
        {
            var weakest = last.ModuleScores.OrderBy(m => m.Score).First();
            report.WeakestModule = weakest.ModuleName;
            report.WeakestModuleScore = weakest.Score;
        }

        if (runs.Count > 1 && first.ModuleScores.Count > 0 && last.ModuleScores.Count > 0)
        {
            var firstModules = first.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);
            int bestChange = 0, worstChange = 0;

            foreach (var mod in last.ModuleScores)
            {
                if (!firstModules.TryGetValue(mod.ModuleName, out var oldScore)) continue;
                var change = mod.Score - oldScore;

                if (change > bestChange)
                {
                    bestChange = change;
                    report.MostImprovedModule = mod.ModuleName;
                    report.MostImprovedChange = change;
                }
                if (change < worstChange)
                {
                    worstChange = change;
                    report.MostRegressedModule = mod.ModuleName;
                    report.MostRegressedChange = change;
                }
            }
        }

        // ── Overall Health Score ───────────────────────────
        // Weighted combination of KPIs into a single 0-100 health score
        var healthScore = 0.0;

        // Score component (40% weight): based on current score
        healthScore += 0.40 * report.CurrentScore;

        // Trend component (15%): positive trend = bonus
        var trendBonus = report.ScoreChange > 10 ? 100 : report.ScoreChange > 0 ? 70 : report.ScoreChange == 0 ? 50 : report.ScoreChange > -10 ? 30 : 0;
        healthScore += 0.15 * trendBonus;

        // Critical findings (20%): 0 criticals = 100, penalize harshly
        var criticalPenalty = Math.Max(0, 100 - report.CurrentCritical * 25);
        healthScore += 0.20 * criticalPenalty;

        // Recurrence (10%): low recurrence = good
        var recurrenceScore = Math.Max(0, 100 - report.RecurrenceRate * 2);
        healthScore += 0.10 * recurrenceScore;

        // Scan cadence (15%): scanning regularly = good
        var cadenceScore = report.ScansPerWeek >= 7 ? 100 : report.ScansPerWeek >= 3 ? 80 : report.ScansPerWeek >= 1 ? 60 : report.ScansPerWeek >= 0.5 ? 40 : 20;
        healthScore += 0.15 * cadenceScore;

        report.HealthScore = (int)Math.Round(Math.Clamp(healthScore, 0, 100));
        report.HealthRating = report.HealthScore switch
        {
            >= 90 => "Excellent",
            >= 75 => "Good",
            >= 60 => "Fair",
            >= 40 => "Poor",
            _ => "Critical"
        };

        // ── Recommendations ────────────────────────────────
        if (report.CurrentCritical > 0)
            report.Recommendations.Add($"Address {report.CurrentCritical} critical finding(s) immediately — these represent high-risk exposure.");

        if (report.RecurrenceRate > 20)
            report.Recommendations.Add($"Recurrence rate is {report.RecurrenceRate}% — investigate root causes of recurring findings to prevent regressions.");

        if (report.ScansPerWeek < 1)
            report.Recommendations.Add("Scan cadence is below 1/week — consider scheduling regular automated audits.");

        if (report.ScoreVolatility > 10)
            report.Recommendations.Add($"Score volatility is high ({report.ScoreVolatility}) — stabilize configuration management to reduce score fluctuations.");

        if (report.MeanTimeToRemediateCritical > 7)
            report.Recommendations.Add($"Critical MTTR is {report.MeanTimeToRemediateCritical:F1} days — aim to remediate critical findings within 48 hours.");

        if (report.DebtTrend == "Increasing")
            report.Recommendations.Add("Security debt is increasing — prioritize finding resolution to prevent accumulation.");

        if (report.WeakestModuleScore < 50)
            report.Recommendations.Add($"Module '{report.WeakestModule}' scores only {report.WeakestModuleScore}/100 — focus hardening efforts here.");

        if (report.Recommendations.Count == 0)
            report.Recommendations.Add("Security posture is healthy — maintain current practices and scan cadence.");

        return report;
    }
}
