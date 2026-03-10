using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Computes operational security KPIs from audit history: MTTR, finding velocity,
/// recurrence rate, resolution efficiency, severity breakdown trends, and module
/// health scores. Provides actionable metrics for security operations teams.
/// </summary>
public class SecurityMetricsAggregator
{
    // ── Public types ─────────────────────────────────────────────────

    /// <summary>Overall security metrics report.</summary>
    public class MetricsReport
    {
        public int RunsAnalyzed { get; init; }
        public TimeSpan AnalysisPeriod { get; init; }
        public DateTimeOffset? FirstRun { get; init; }
        public DateTimeOffset? LastRun { get; init; }
        public double MttrHours { get; init; }
        public double MttdHours { get; init; }
        public double FindingVelocityPerDay { get; init; }
        public double ResolutionVelocityPerDay { get; init; }
        public double ResolutionEfficiency { get; init; }
        public double RecurrenceRatePercent { get; init; }
        public int TotalUnique { get; init; }
        public int CurrentlyOpen { get; init; }
        public int TotalResolved { get; init; }
        public int TotalRecurrent { get; init; }
        public SeverityBreakdown CurrentSeverity { get; init; } = new();
        public List<SeverityTrendPoint> SeverityTrend { get; init; } = [];
        public List<ModuleHealth> Modules { get; init; } = [];
        public List<RecurringFinding> TopRecurring { get; init; } = [];
        public string HealthGrade { get; init; } = "";
        public double HealthScore { get; init; }
        public string Summary { get; init; } = "";
    }

    public record SeverityBreakdown
    {
        public int Critical { get; init; }
        public int Warning { get; init; }
        public int Info { get; init; }
        public int Total => Critical + Warning + Info;
    }

    public record SeverityTrendPoint(
        DateTimeOffset WindowStart, DateTimeOffset WindowEnd,
        int RunCount, SeverityBreakdown Severity, int OverallScore);

    public record ModuleHealth(
        string ModuleName, string Category,
        int CurrentFindings, int PeakFindings, double AvgFindings,
        int TotalIntroduced, int TotalResolved,
        double MttrHours, double RecurrenceRatePercent, string HealthGrade);

    public record RecurringFinding(
        string ModuleName, string Title, string Severity,
        int Occurrences, int Recurrences, double AvgDaysBeforeRecurrence);

    // ── Core analysis ────────────────────────────────────────────────

    public MetricsReport Analyze(
        IReadOnlyList<AuditRunRecord> runs,
        int windowCount = 6,
        int topRecurringCount = 10)
    {
        if (runs == null) throw new ArgumentNullException(nameof(runs));

        if (runs.Count == 0)
            return new MetricsReport
            {
                RunsAnalyzed = 0, AnalysisPeriod = TimeSpan.Zero,
                HealthGrade = "N/A",
                Summary = "No audit runs available for analysis."
            };

        var sorted = runs.OrderBy(r => r.Timestamp).ToList();
        var first = sorted[0].Timestamp;
        var last = sorted[^1].Timestamp;
        var period = last - first;

        var lifecycles = TrackLifecycles(sorted);

        double mttrHours = 0;
        var allResolutions = lifecycles.Values.SelectMany(l => l.Resolutions).ToList();
        if (allResolutions.Count > 0)
            mttrHours = allResolutions.Average(r => r.TotalHours);

        double mttdHours = 0;
        if (sorted.Count > 1)
        {
            var gaps = new List<double>();
            for (int i = 1; i < sorted.Count; i++)
                gaps.Add((sorted[i].Timestamp - sorted[i - 1].Timestamp).TotalHours);
            mttdHours = gaps.Average();
        }

        int totalIntroduced = lifecycles.Values.Sum(l => l.IntroducedCount);
        int totalResolved = lifecycles.Values.Sum(l => l.Resolutions.Count);
        double days = Math.Max(period.TotalDays, 1);
        double findingVelocity = totalIntroduced / days;
        double resolutionVelocity = totalResolved / days;
        double resolutionEfficiency = totalIntroduced > 0
            ? (double)totalResolved / totalIntroduced : 1.0;

        var recurrentFindings = lifecycles.Values.Where(l => l.Recurrences > 0).ToList();
        int totalRecurrent = recurrentFindings.Count;
        double recurrenceRate = totalResolved > 0
            ? (double)totalRecurrent / totalResolved * 100 : 0;

        var latestFindings = sorted[^1].Findings
            .Where(f => !f.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase)).ToList();

        var currentSeverity = new SeverityBreakdown
        {
            Critical = latestFindings.Count(f => f.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
            Warning = latestFindings.Count(f => f.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase)),
            Info = latestFindings.Count(f => f.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
        };

        var severityTrend = ComputeSeverityTrend(sorted, windowCount);
        var moduleHealth = ComputeModuleHealth(sorted, lifecycles);

        var topRecurring = recurrentFindings
            .OrderByDescending(l => l.Recurrences)
            .ThenByDescending(l => l.LastSeverity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
            .Take(topRecurringCount)
            .Select(l => new RecurringFinding(
                l.ModuleName, l.Title, l.LastSeverity,
                l.IntroducedCount, l.Recurrences,
                l.RecurrenceGaps.Count > 0 ? l.RecurrenceGaps.Average(g => g.TotalDays) : 0))
            .ToList();

        double healthScore = ComputeHealthScore(mttrHours, recurrenceRate, currentSeverity, resolutionEfficiency);
        string healthGrade = ScoreToGrade(healthScore);

        string summary = BuildSummary(sorted.Count, period, mttrHours, mttdHours,
            findingVelocity, resolutionVelocity, resolutionEfficiency,
            recurrenceRate, latestFindings.Count, currentSeverity, healthGrade, healthScore);

        return new MetricsReport
        {
            RunsAnalyzed = sorted.Count, AnalysisPeriod = period,
            FirstRun = first, LastRun = last,
            MttrHours = Math.Round(mttrHours, 2),
            MttdHours = Math.Round(mttdHours, 2),
            FindingVelocityPerDay = Math.Round(findingVelocity, 2),
            ResolutionVelocityPerDay = Math.Round(resolutionVelocity, 2),
            ResolutionEfficiency = Math.Round(resolutionEfficiency, 3),
            RecurrenceRatePercent = Math.Round(recurrenceRate, 1),
            TotalUnique = lifecycles.Count,
            CurrentlyOpen = latestFindings.Count,
            TotalResolved = totalResolved,
            TotalRecurrent = totalRecurrent,
            CurrentSeverity = currentSeverity,
            SeverityTrend = severityTrend,
            Modules = moduleHealth,
            TopRecurring = topRecurring,
            HealthGrade = healthGrade,
            HealthScore = Math.Round(healthScore, 1),
            Summary = summary
        };
    }

    // ── Finding lifecycle tracking ───────────────────────────────────

    private class FindingLifecycle
    {
        public string Key { get; init; } = "";
        public string ModuleName { get; init; } = "";
        public string Title { get; init; } = "";
        public string LastSeverity { get; set; } = "";
        public int IntroducedCount { get; set; }
        public int Recurrences { get; set; }
        public List<TimeSpan> Resolutions { get; } = [];
        public List<TimeSpan> RecurrenceGaps { get; } = [];
        public DateTimeOffset? LastAppeared { get; set; }
        public DateTimeOffset? LastResolved { get; set; }
    }

    private static Dictionary<string, FindingLifecycle> TrackLifecycles(List<AuditRunRecord> sorted)
    {
        var lifecycles = new Dictionary<string, FindingLifecycle>(StringComparer.OrdinalIgnoreCase);
        HashSet<string>? previousKeys = null;

        foreach (var run in sorted)
        {
            var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var finding in run.Findings)
            {
                if (finding.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase)) continue;

                var key = $"{finding.ModuleName}||{finding.Title}";
                currentKeys.Add(key);

                if (!lifecycles.TryGetValue(key, out var lc))
                {
                    lc = new FindingLifecycle { Key = key, ModuleName = finding.ModuleName, Title = finding.Title };
                    lifecycles[key] = lc;
                }

                lc.LastSeverity = finding.Severity;
                bool wasPresent = previousKeys?.Contains(key) ?? false;

                if (!wasPresent)
                {
                    lc.IntroducedCount++;
                    if (lc.LastResolved.HasValue)
                    {
                        lc.Recurrences++;
                        lc.RecurrenceGaps.Add(run.Timestamp - lc.LastResolved.Value);
                        lc.LastResolved = null;
                    }
                }

                lc.LastAppeared = run.Timestamp;
            }

            if (previousKeys != null)
            {
                foreach (var prevKey in previousKeys)
                {
                    if (!currentKeys.Contains(prevKey) && lifecycles.TryGetValue(prevKey, out var lc))
                    {
                        if (lc.LastAppeared.HasValue)
                            lc.Resolutions.Add(run.Timestamp - lc.LastAppeared.Value);
                        lc.LastResolved = run.Timestamp;
                    }
                }
            }

            previousKeys = currentKeys;
        }

        return lifecycles;
    }

    // ── Severity trend ───────────────────────────────────────────────

    private static List<SeverityTrendPoint> ComputeSeverityTrend(List<AuditRunRecord> sorted, int windowCount)
    {
        if (sorted.Count <= 1 || windowCount <= 0) return [];

        var totalTicks = (sorted[^1].Timestamp - sorted[0].Timestamp).Ticks;
        if (totalTicks <= 0) return [];

        var windowSize = TimeSpan.FromTicks(totalTicks / windowCount);
        if (windowSize.Ticks <= 0) return [];

        var trend = new List<SeverityTrendPoint>();
        var first = sorted[0].Timestamp;

        for (int i = 0; i < windowCount; i++)
        {
            var wStart = first + TimeSpan.FromTicks(windowSize.Ticks * i);
            var wEnd = i == windowCount - 1
                ? sorted[^1].Timestamp.AddSeconds(1)
                : first + TimeSpan.FromTicks(windowSize.Ticks * (i + 1));

            var windowRuns = sorted.Where(r => r.Timestamp >= wStart && r.Timestamp < wEnd).ToList();
            if (windowRuns.Count == 0) continue;

            var last = windowRuns[^1];
            var findings = last.Findings
                .Where(f => !f.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase)).ToList();

            trend.Add(new SeverityTrendPoint(wStart, wEnd, windowRuns.Count,
                new SeverityBreakdown
                {
                    Critical = findings.Count(f => f.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
                    Warning = findings.Count(f => f.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase)),
                    Info = findings.Count(f => f.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
                },
                last.OverallScore));
        }

        return trend;
    }

    // ── Module health ────────────────────────────────────────────────

    private static List<ModuleHealth> ComputeModuleHealth(
        List<AuditRunRecord> sorted, Dictionary<string, FindingLifecycle> lifecycles)
    {
        var moduleNames = sorted.SelectMany(r => r.ModuleScores).Select(m => m.ModuleName)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var results = new List<ModuleHealth>();

        foreach (var mod in moduleNames)
        {
            var modLcs = lifecycles.Values
                .Where(l => l.ModuleName.Equals(mod, StringComparison.OrdinalIgnoreCase)).ToList();

            var perRun = sorted
                .Select(r => r.Findings.Count(f =>
                    f.ModuleName.Equals(mod, StringComparison.OrdinalIgnoreCase)
                    && !f.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            int current = perRun.Count > 0 ? perRun[^1] : 0;
            int peak = perRun.Count > 0 ? perRun.Max() : 0;
            double avg = perRun.Count > 0 ? perRun.Average() : 0;
            int introduced = modLcs.Sum(l => l.IntroducedCount);
            int resolved = modLcs.Sum(l => l.Resolutions.Count);
            int recurrent = modLcs.Count(l => l.Recurrences > 0);

            double mttr = modLcs.SelectMany(l => l.Resolutions).Any()
                ? modLcs.SelectMany(l => l.Resolutions).Average(r => r.TotalHours) : 0;
            double recRate = resolved > 0 ? (double)recurrent / resolved * 100 : 0;

            string cat = sorted.SelectMany(r => r.ModuleScores)
                .Where(m => m.ModuleName.Equals(mod, StringComparison.OrdinalIgnoreCase))
                .Select(m => m.Category).LastOrDefault() ?? "";

            double score = 100;
            score -= current * 5;
            score -= Math.Min(15, recRate * 0.3);
            if (mttr > 48) score -= Math.Min(20, (mttr - 48) / 8);
            if (introduced > 0 && resolved < introduced)
                score -= Math.Min(15, (introduced - resolved) * 3);
            score = Math.Clamp(score, 0, 100);

            results.Add(new ModuleHealth(mod, cat, current, peak, Math.Round(avg, 1),
                introduced, resolved, Math.Round(mttr, 2), Math.Round(recRate, 1),
                ScoreToGrade(score)));
        }

        return results.OrderByDescending(m => m.CurrentFindings).ToList();
    }

    // ── Scoring ──────────────────────────────────────────────────────

    private static double ComputeHealthScore(
        double mttrHours, double recurrenceRate, SeverityBreakdown severity, double resolutionEfficiency)
    {
        double score = 100;
        if (mttrHours > 72) score -= Math.Min(25, (mttrHours - 72) / 10);
        score -= Math.Min(20, recurrenceRate * 0.5);
        score -= severity.Critical * 8;
        score -= severity.Warning * 2;
        score -= severity.Info * 0.5;
        if (resolutionEfficiency >= 1.0) score += 5;
        else if (resolutionEfficiency < 0.5) score -= 10;
        return Math.Clamp(score, 0, 100);
    }

    private static string ScoreToGrade(double score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };

    // ── Summary ──────────────────────────────────────────────────────

    private static string BuildSummary(
        int runs, TimeSpan period, double mttrHours, double mttdHours,
        double findingVelocity, double resolutionVelocity, double resolutionEfficiency,
        double recurrenceRate, int currentlyOpen, SeverityBreakdown severity,
        string grade, double healthScore)
    {
        var lines = new List<string>
        {
            $"Security Metrics Report — Grade: {grade} ({healthScore:F1}/100)",
            $"  Analyzed {runs} runs over {period.TotalDays:F0} days",
            "",
            "Key Performance Indicators:",
            $"  MTTR (Mean Time to Resolve):   {FormatDuration(mttrHours)}",
            $"  MTTD (Mean Time to Detect):    {FormatDuration(mttdHours)}",
            $"  Finding Velocity:              {findingVelocity:F2}/day introduced, {resolutionVelocity:F2}/day resolved",
            $"  Resolution Efficiency:         {resolutionEfficiency:P1}",
            $"  Recurrence Rate:               {recurrenceRate:F1}%",
            "",
            $"Current State: {currentlyOpen} open findings",
            $"  Critical: {severity.Critical}  Warning: {severity.Warning}  Info: {severity.Info}"
        };

        if (resolutionEfficiency < 0.8)
            lines.Add("\n⚠ Resolution efficiency below 80% — findings accumulating faster than resolved.");
        if (recurrenceRate > 20)
            lines.Add("⚠ High recurrence rate — consider root-cause analysis on recurring findings.");
        if (severity.Critical > 0)
            lines.Add($"⚠ {severity.Critical} critical finding(s) require immediate attention.");

        return string.Join("\n", lines);
    }

    private static string FormatDuration(double hours) => hours switch
    {
        < 1 => $"{hours * 60:F0} minutes",
        < 24 => $"{hours:F1} hours",
        _ => $"{hours / 24:F1} days"
    };
}
