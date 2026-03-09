using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates finding burndown data from audit history — tracks resolution velocity,
/// projects zero-finding dates, and grades remediation performance.
/// </summary>
public class FindingBurndownService
{
    /// <summary>
    /// Generate a complete burndown report from audit run history.
    /// </summary>
    /// <param name="runs">Audit runs ordered newest-first (as stored by AuditHistoryService).</param>
    /// <param name="periodDays">Days per sprint/period for aggregation (default 7).</param>
    /// <returns>Complete burndown report with projections and grades.</returns>
    public BurndownReport Generate(IReadOnlyList<AuditRunRecord> runs, int periodDays = 7)
    {
        if (runs == null) throw new ArgumentNullException(nameof(runs));

        var report = new BurndownReport();

        if (runs.Count == 0)
        {
            report.Grade = "N/A";
            report.GradeReason = "No audit data available.";
            return report;
        }

        // Sort chronologically
        var chronological = runs.OrderBy(r => r.Timestamp).ToList();
        report.TotalRuns = chronological.Count;
        report.WindowStart = chronological[0].Timestamp;
        report.WindowEnd = chronological[^1].Timestamp;

        // Track findings across runs by composite key
        var allKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var previousKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int cumulativeResolved = 0;
        int cumulativeIntroduced = 0;

        // Per-severity tracking
        var sevTracker = new Dictionary<string, SeverityTrackingState>(StringComparer.OrdinalIgnoreCase);

        // Finding first-seen / last-seen for resolution time calculation
        var findingFirstSeen = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        var findingLastSeen = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        var findingSeverity = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var resolvedDurations = new Dictionary<string, List<double>>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < chronological.Count; i++)
        {
            var run = chronological[i];
            var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int criticalOpen = 0, warningOpen = 0, infoOpen = 0;

            foreach (var f in run.Findings)
            {
                if (f.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase))
                    continue;

                var key = MakeKey(f.ModuleName, f.Title);
                currentKeys.Add(key);
                allKeys.Add(key);

                if (!findingFirstSeen.ContainsKey(key))
                    findingFirstSeen[key] = run.Timestamp;
                findingLastSeen[key] = run.Timestamp;
                findingSeverity[key] = f.Severity;

                var sevNorm = NormalizeSeverity(f.Severity);
                if (sevNorm == "Critical") criticalOpen++;
                else if (sevNorm == "Warning") warningOpen++;
                else infoOpen++;

                if (!sevTracker.ContainsKey(sevNorm))
                    sevTracker[sevNorm] = new SeverityTrackingState();
            }

            int newCount = 0, resolvedCount = 0;
            if (i > 0)
            {
                foreach (var k in currentKeys)
                {
                    if (!previousKeys.Contains(k))
                    {
                        newCount++;
                        cumulativeIntroduced++;
                    }
                }
                foreach (var k in previousKeys)
                {
                    if (!currentKeys.Contains(k))
                    {
                        resolvedCount++;
                        cumulativeResolved++;

                        // Track resolution duration
                        if (findingFirstSeen.TryGetValue(k, out var firstSeen) &&
                            findingSeverity.TryGetValue(k, out var sev))
                        {
                            var sevNorm = NormalizeSeverity(sev);
                            var days = (run.Timestamp - firstSeen).TotalDays;
                            if (!resolvedDurations.ContainsKey(sevNorm))
                                resolvedDurations[sevNorm] = [];
                            resolvedDurations[sevNorm].Add(days);
                        }
                    }
                }
            }
            else
            {
                // First run — all are "introduced"
                newCount = currentKeys.Count;
                cumulativeIntroduced = newCount;
            }

            // Update severity peak tracking
            foreach (var (sev, state) in sevTracker)
            {
                int count = sev switch
                {
                    "Critical" => criticalOpen,
                    "Warning" => warningOpen,
                    _ => infoOpen
                };
                state.PeakOpen = Math.Max(state.PeakOpen, count);
            }

            report.DataPoints.Add(new BurndownDataPoint
            {
                Date = run.Timestamp,
                OpenFindings = currentKeys.Count,
                CriticalOpen = criticalOpen,
                WarningOpen = warningOpen,
                InfoOpen = infoOpen,
                NewFindings = newCount,
                ResolvedFindings = resolvedCount,
                CumulativeResolved = cumulativeResolved,
                CumulativeIntroduced = cumulativeIntroduced
            });

            previousKeys = currentKeys;
        }

        report.TotalUniqueFindingsSeen = allKeys.Count;
        report.TotalResolved = cumulativeResolved;
        report.TotalIntroduced = cumulativeIntroduced;

        // Build periods
        report.Periods = BuildPeriods(report.DataPoints, periodDays);

        // Build projection
        report.Projection = BuildProjection(report.DataPoints, chronological[^1].Timestamp);

        // Build severity breakdown
        var lastDataPoint = report.DataPoints[^1];
        foreach (var sev in new[] { "Critical", "Warning", "Info" })
        {
            int currentOpen = sev switch
            {
                "Critical" => lastDataPoint.CriticalOpen,
                "Warning" => lastDataPoint.WarningOpen,
                _ => lastDataPoint.InfoOpen
            };
            var sevBurndown = new SeverityBurndown
            {
                Severity = sev,
                CurrentOpen = currentOpen,
                PeakOpen = sevTracker.TryGetValue(sev, out var st) ? st.PeakOpen : currentOpen,
                TotalResolved = resolvedDurations.TryGetValue(sev, out var rd) ? rd.Count : 0,
                AvgDaysToResolve = resolvedDurations.TryGetValue(sev, out var rd2) && rd2.Count > 0
                    ? Math.Round(rd2.Average(), 1) : 0
            };
            // Count introduced per severity across all data points
            report.SeverityBreakdown.Add(sevBurndown);
        }

        // Grade
        (report.Grade, report.GradeReason) = CalculateGrade(report);

        return report;
    }

    private List<BurndownPeriod> BuildPeriods(List<BurndownDataPoint> points, int periodDays)
    {
        if (points.Count < 2) return [];

        var periods = new List<BurndownPeriod>();
        var start = points[0].Date;
        var end = points[^1].Date;
        var totalSpan = (end - start).TotalDays;

        if (totalSpan < 1) return [];

        var periodStart = start;
        int periodNum = 1;

        while (periodStart < end)
        {
            var periodEnd = periodStart.AddDays(periodDays);
            if (periodEnd > end) periodEnd = end;

            var periodPoints = points.Where(p => p.Date >= periodStart && p.Date <= periodEnd).ToList();
            if (periodPoints.Count > 0)
            {
                var first = periodPoints[0];
                var last = periodPoints[^1];
                int resolved = periodPoints.Sum(p => p.ResolvedFindings);
                int introduced = periodPoints.Sum(p => p.NewFindings);
                double days = Math.Max(1, (last.Date - first.Date).TotalDays);

                periods.Add(new BurndownPeriod
                {
                    Start = periodStart,
                    End = periodEnd,
                    Label = $"Period {periodNum}",
                    StartCount = first.OpenFindings,
                    EndCount = last.OpenFindings,
                    Introduced = introduced,
                    Resolved = resolved,
                    VelocityPerDay = Math.Round(resolved / days, 2),
                    RunCount = periodPoints.Count
                });
            }

            periodStart = periodEnd.AddSeconds(1);
            periodNum++;
        }

        return periods;
    }

    private BurndownProjection BuildProjection(List<BurndownDataPoint> points, DateTimeOffset now)
    {
        var proj = new BurndownProjection();

        if (points.Count < 2)
        {
            proj.CurrentOpen = points.Count > 0 ? points[^1].OpenFindings : 0;
            proj.Summary = "Insufficient data for projection (need at least 2 runs).";
            return proj;
        }

        var first = points[0];
        var last = points[^1];
        double totalDays = Math.Max(1, (last.Date - first.Date).TotalDays);

        int totalResolved = points.Sum(p => p.ResolvedFindings);
        int totalIntroduced = points.Sum(p => p.NewFindings);

        proj.CurrentOpen = last.OpenFindings;
        proj.AvgResolvedPerDay = Math.Round(totalResolved / totalDays, 2);
        proj.AvgIntroducedPerDay = Math.Round(totalIntroduced / totalDays, 2);
        proj.NetVelocityPerDay = Math.Round(proj.AvgResolvedPerDay - proj.AvgIntroducedPerDay, 2);

        if (proj.NetVelocityPerDay > 0 && proj.CurrentOpen > 0)
        {
            int daysToZero = (int)Math.Ceiling(proj.CurrentOpen / proj.NetVelocityPerDay);
            proj.DaysToZero = daysToZero;
            proj.ProjectedZeroDate = now.AddDays(daysToZero);

            // Confidence based on data consistency
            var velocities = new List<double>();
            for (int i = 1; i < points.Count; i++)
            {
                double daysBetween = Math.Max(0.01, (points[i].Date - points[i - 1].Date).TotalDays);
                velocities.Add((points[i].ResolvedFindings - points[i].NewFindings) / daysBetween);
            }
            double mean = velocities.Average();
            double variance = velocities.Sum(v => (v - mean) * (v - mean)) / velocities.Count;
            double stddev = Math.Sqrt(variance);
            double cv = mean != 0 ? stddev / Math.Abs(mean) : 10;
            proj.ConfidencePercent = Math.Clamp((int)(100 - cv * 30), 5, 95);

            proj.Summary = $"At current velocity ({proj.NetVelocityPerDay:F1} net/day), projected zero-findings by {proj.ProjectedZeroDate:yyyy-MM-dd} (~{daysToZero} days). Confidence: {proj.ConfidencePercent}%.";
        }
        else if (proj.CurrentOpen == 0)
        {
            proj.ConfidencePercent = 100;
            proj.Summary = "All findings resolved! Zero open findings.";
        }
        else
        {
            proj.ConfidencePercent = 0;
            proj.Summary = proj.NetVelocityPerDay == 0
                ? "Finding count is stable — new findings equal resolved findings."
                : "Findings are accumulating faster than they are resolved. No projected zero date.";
        }

        return proj;
    }

    private (string grade, string reason) CalculateGrade(BurndownReport report)
    {
        if (report.DataPoints.Count < 2)
            return ("N/A", "Insufficient data for grading.");

        var first = report.DataPoints[0];
        var last = report.DataPoints[^1];

        // Grade based on: net reduction %, velocity, critical trend
        double reductionPct = first.OpenFindings > 0
            ? (double)(first.OpenFindings - last.OpenFindings) / first.OpenFindings * 100
            : last.OpenFindings == 0 ? 100 : -100;

        bool criticalDown = last.CriticalOpen <= first.CriticalOpen;
        bool zeroFindings = last.OpenFindings == 0;
        double netVel = report.Projection.NetVelocityPerDay;

        if (zeroFindings)
            return ("A+", "Zero open findings — exemplary security posture.");
        if (reductionPct >= 50 && criticalDown && netVel > 0)
            return ("A", $"Findings reduced by {reductionPct:F0}% with positive velocity.");
        if (reductionPct >= 25 && criticalDown)
            return ("B+", $"Good progress — {reductionPct:F0}% reduction, criticals decreasing.");
        if (reductionPct >= 10)
            return ("B", $"Steady improvement — {reductionPct:F0}% reduction.");
        if (reductionPct >= 0)
            return ("C", $"Findings stable (net {reductionPct:F0}% change). Increase resolution velocity.");
        if (reductionPct >= -25)
            return ("D", $"Findings growing ({Math.Abs(reductionPct):F0}% increase). Remediation falling behind.");
        return ("F", $"Significant finding growth ({Math.Abs(reductionPct):F0}% increase). Urgent remediation needed.");
    }

    private static string MakeKey(string moduleName, string title) =>
        $"{moduleName}::{title}";

    private static string NormalizeSeverity(string severity)
    {
        if (severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return "Critical";
        if (severity.Equals("Warning", StringComparison.OrdinalIgnoreCase)) return "Warning";
        return "Info";
    }

    private class SeverityTrackingState
    {
        public int PeakOpen { get; set; }
    }
}
