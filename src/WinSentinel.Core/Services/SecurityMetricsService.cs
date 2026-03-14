using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Computes operational security KPIs from scan history.
/// <para>
/// While <see cref="TrendAnalyzer"/> tracks score trends and <see cref="SlaTracker"/>
/// monitors SLA compliance, this service focuses on operational performance metrics
/// that security teams use for continuous improvement:
/// <list type="bullet">
///   <item>Mean Time to Detect (MTTD) — how quickly new findings appear in scans</item>
///   <item>Mean Time to Remediate (MTTR) — how quickly findings get resolved</item>
///   <item>Fix Rate — percentage of findings resolved over a time window</item>
///   <item>Recurrence Rate — findings that reappear after resolution</item>
///   <item>Category Risk Distribution — risk-weighted breakdown by category</item>
///   <item>Finding Velocity — net new vs resolved findings per period</item>
///   <item>Trend Direction — overall improving, stable, or degrading posture</item>
/// </list>
/// </para>
/// </summary>
public class SecurityMetricsService
{
    // ── Models ───────────────────────────────────────────────────

    /// <summary>Direction of security posture change.</summary>
    public enum PostureDirection
    {
        /// <summary>Security posture is improving (fewer/less-severe findings).</summary>
        Improving,
        /// <summary>Security posture is roughly stable.</summary>
        Stable,
        /// <summary>Security posture is degrading (more/higher-severity findings).</summary>
        Degrading
    }

    /// <summary>A tracked finding with detection and resolution timestamps.</summary>
    public class TrackedFinding
    {
        public string Title { get; set; } = "";
        public string Category { get; set; } = "";

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Severity Severity { get; set; }

        public DateTimeOffset DetectedAt { get; set; }
        public DateTimeOffset? ResolvedAt { get; set; }
        public int RecurrenceCount { get; set; }
        public bool IsResolved => ResolvedAt.HasValue;

        public TimeSpan? TimeToRemediate =>
            ResolvedAt.HasValue ? ResolvedAt.Value - DetectedAt : null;
    }

    /// <summary>Risk breakdown for a single category.</summary>
    public class CategoryRisk
    {
        public string Category { get; set; } = "";
        public int TotalFindings { get; set; }
        public int OpenFindings { get; set; }
        public int CriticalCount { get; set; }
        public int WarningCount { get; set; }
        public int InfoCount { get; set; }

        /// <summary>Risk score: Critical=10, Warning=3, Info=1.</summary>
        public double RiskScore { get; set; }

        /// <summary>Percentage of total risk.</summary>
        public double RiskPercentage { get; set; }
    }

    /// <summary>Finding velocity for a time period.</summary>
    public class VelocityPeriod
    {
        public DateTimeOffset PeriodStart { get; set; }
        public DateTimeOffset PeriodEnd { get; set; }
        public int NewFindings { get; set; }
        public int ResolvedFindings { get; set; }

        /// <summary>Net change (positive = more findings, negative = fewer).</summary>
        public int NetChange => NewFindings - ResolvedFindings;
    }

    /// <summary>Complete metrics report.</summary>
    public class MetricsReport
    {
        public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? WindowStart { get; set; }
        public DateTimeOffset? WindowEnd { get; set; }

        // Aggregate KPIs
        public int TotalTracked { get; set; }
        public int OpenFindings { get; set; }
        public int ResolvedFindings { get; set; }
        public double FixRatePercent { get; set; }
        public double RecurrenceRatePercent { get; set; }

        /// <summary>Mean time to remediate (resolved findings only). Null if none resolved.</summary>
        public TimeSpan? MeanTimeToRemediate { get; set; }

        /// <summary>Median time to remediate. Null if none resolved.</summary>
        public TimeSpan? MedianTimeToRemediate { get; set; }

        /// <summary>MTTR broken down by severity.</summary>
        public Dictionary<string, TimeSpan> MttrBySeverity { get; set; } = new();

        /// <summary>Average scan interval (proxy for MTTD).</summary>
        public TimeSpan? MeanScanInterval { get; set; }

        /// <summary>Category risk breakdown, ordered by risk score descending.</summary>
        public List<CategoryRisk> CategoryRisks { get; set; } = new();

        /// <summary>Finding velocity per period (weekly by default).</summary>
        public List<VelocityPeriod> Velocity { get; set; } = new();

        /// <summary>Overall posture direction.</summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public PostureDirection Direction { get; set; } = PostureDirection.Stable;

        /// <summary>Summary sentence.</summary>
        public string Summary { get; set; } = "";
    }

    // ── Core API ─────────────────────────────────────────────────

    /// <summary>
    /// Build tracked findings from a sequence of scan snapshots (chronological order).
    /// Each snapshot is a list of findings from one scan run.
    /// </summary>
    public List<TrackedFinding> BuildTrackingHistory(
        List<(DateTimeOffset Timestamp, List<Finding> Findings)> scanSnapshots)
    {
        ArgumentNullException.ThrowIfNull(scanSnapshots);
        var tracked = new Dictionary<string, TrackedFinding>();
        var previousTitles = new HashSet<string>();
        var resolvedTitles = new HashSet<string>();

        foreach (var (timestamp, findings) in scanSnapshots.OrderBy(s => s.Timestamp))
        {
            var currentTitles = new HashSet<string>();

            foreach (var f in findings.Where(f => f.Severity >= Severity.Info))
            {
                var key = $"{f.Category}::{f.Title}";
                currentTitles.Add(key);

                if (!tracked.ContainsKey(key))
                {
                    var tf = new TrackedFinding
                    {
                        Title = f.Title,
                        Category = f.Category,
                        Severity = f.Severity,
                        DetectedAt = timestamp
                    };

                    // Check if this was previously resolved (recurrence)
                    if (resolvedTitles.Contains(key))
                    {
                        tf.RecurrenceCount = 1;
                        resolvedTitles.Remove(key);
                    }

                    tracked[key] = tf;
                }
                else if (tracked[key].IsResolved)
                {
                    // Recurrence: was resolved, now back
                    tracked[key].RecurrenceCount++;
                    tracked[key].ResolvedAt = null;
                    tracked[key].DetectedAt = timestamp;
                }
            }

            // Mark findings absent in this scan as resolved
            foreach (var key in previousTitles.Except(currentTitles))
            {
                if (tracked.TryGetValue(key, out var tf) && !tf.IsResolved)
                {
                    tf.ResolvedAt = timestamp;
                    resolvedTitles.Add(key);
                }
            }

            previousTitles = currentTitles;
        }

        return tracked.Values.ToList();
    }

    /// <summary>
    /// Compute metrics from tracked findings.
    /// </summary>
    public MetricsReport ComputeMetrics(
        List<TrackedFinding> tracked,
        List<DateTimeOffset>? scanTimestamps = null,
        TimeSpan? velocityPeriod = null)
    {
        ArgumentNullException.ThrowIfNull(tracked);

        var report = new MetricsReport();

        if (tracked.Count == 0)
        {
            report.Summary = "No findings tracked — nothing to report.";
            return report;
        }

        report.TotalTracked = tracked.Count;
        report.OpenFindings = tracked.Count(t => !t.IsResolved);
        report.ResolvedFindings = tracked.Count(t => t.IsResolved);
        report.FixRatePercent = tracked.Count > 0
            ? Math.Round(100.0 * report.ResolvedFindings / report.TotalTracked, 1)
            : 0;

        // Recurrence
        var recurred = tracked.Count(t => t.RecurrenceCount > 0);
        report.RecurrenceRatePercent = tracked.Count > 0
            ? Math.Round(100.0 * recurred / tracked.Count, 1)
            : 0;

        // MTTR
        var resolved = tracked
            .Where(t => t.TimeToRemediate.HasValue)
            .Select(t => t.TimeToRemediate!.Value)
            .ToList();

        if (resolved.Count > 0)
        {
            report.MeanTimeToRemediate = TimeSpan.FromTicks(
                (long)resolved.Average(t => t.Ticks));
            var sorted = resolved.OrderBy(t => t).ToList();
            report.MedianTimeToRemediate = sorted[sorted.Count / 2];

            // MTTR by severity
            foreach (var group in tracked
                .Where(t => t.TimeToRemediate.HasValue)
                .GroupBy(t => t.Severity))
            {
                var avg = TimeSpan.FromTicks(
                    (long)group.Average(t => t.TimeToRemediate!.Value.Ticks));
                report.MttrBySeverity[group.Key.ToString()] = avg;
            }
        }

        // Scan interval (MTTD proxy)
        if (scanTimestamps is { Count: >= 2 })
        {
            var ordered = scanTimestamps.OrderBy(t => t).ToList();
            var intervals = new List<TimeSpan>();
            for (int i = 1; i < ordered.Count; i++)
                intervals.Add(ordered[i] - ordered[i - 1]);
            report.MeanScanInterval = TimeSpan.FromTicks(
                (long)intervals.Average(t => t.Ticks));

            report.WindowStart = ordered.First();
            report.WindowEnd = ordered.Last();
        }

        // Category risk
        var catGroups = tracked.GroupBy(t => t.Category).ToList();
        double totalRisk = 0;
        foreach (var g in catGroups)
        {
            var cr = new CategoryRisk
            {
                Category = g.Key,
                TotalFindings = g.Count(),
                OpenFindings = g.Count(t => !t.IsResolved),
                CriticalCount = g.Count(t => t.Severity == Severity.Critical),
                WarningCount = g.Count(t => t.Severity == Severity.Warning),
                InfoCount = g.Count(t => t.Severity == Severity.Info),
            };
            cr.RiskScore = cr.CriticalCount * 10.0 + cr.WarningCount * 3.0 + cr.InfoCount * 1.0;
            totalRisk += cr.RiskScore;
            report.CategoryRisks.Add(cr);
        }
        foreach (var cr in report.CategoryRisks)
            cr.RiskPercentage = totalRisk > 0
                ? Math.Round(100.0 * cr.RiskScore / totalRisk, 1)
                : 0;
        report.CategoryRisks = report.CategoryRisks
            .OrderByDescending(c => c.RiskScore).ToList();

        // Velocity
        var period = velocityPeriod ?? TimeSpan.FromDays(7);
        if (tracked.Count > 0)
        {
            var earliest = tracked.Min(t => t.DetectedAt);
            var latest = DateTimeOffset.UtcNow;
            var cursor = earliest;
            while (cursor < latest)
            {
                var periodEnd = cursor + period;
                if (periodEnd > latest) periodEnd = latest;

                var vp = new VelocityPeriod
                {
                    PeriodStart = cursor,
                    PeriodEnd = periodEnd,
                    NewFindings = tracked.Count(t =>
                        t.DetectedAt >= cursor && t.DetectedAt < periodEnd),
                    ResolvedFindings = tracked.Count(t =>
                        t.ResolvedAt.HasValue &&
                        t.ResolvedAt.Value >= cursor && t.ResolvedAt.Value < periodEnd)
                };
                if (vp.NewFindings > 0 || vp.ResolvedFindings > 0)
                    report.Velocity.Add(vp);

                cursor = periodEnd;
            }
        }

        // Direction
        report.Direction = DetermineDirection(report);

        // Summary
        report.Summary = BuildSummary(report);

        return report;
    }

    /// <summary>
    /// Convenience: build tracking + compute metrics from scan snapshots in one call.
    /// </summary>
    public MetricsReport Analyze(
        List<(DateTimeOffset Timestamp, List<Finding> Findings)> scanSnapshots,
        TimeSpan? velocityPeriod = null)
    {
        var tracked = BuildTrackingHistory(scanSnapshots);
        var timestamps = scanSnapshots.Select(s => s.Timestamp).ToList();
        return ComputeMetrics(tracked, timestamps, velocityPeriod);
    }

    // ── Reporting ────────────────────────────────────────────────

    /// <summary>Generate a plain-text metrics report.</summary>
    public string ToTextReport(MetricsReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var sb = new StringBuilder();

        sb.AppendLine("═══════════════════════════════════════════════════");
        sb.AppendLine("          SECURITY METRICS REPORT");
        sb.AppendLine("═══════════════════════════════════════════════════");
        sb.AppendLine();

        sb.AppendLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm} UTC");
        if (report.WindowStart.HasValue && report.WindowEnd.HasValue)
            sb.AppendLine($"  Window:    {report.WindowStart:yyyy-MM-dd} → {report.WindowEnd:yyyy-MM-dd}");
        sb.AppendLine($"  Direction: {report.Direction}");
        sb.AppendLine();

        sb.AppendLine("── Key Performance Indicators ──────────────────────");
        sb.AppendLine($"  Total Tracked:     {report.TotalTracked}");
        sb.AppendLine($"  Open:              {report.OpenFindings}");
        sb.AppendLine($"  Resolved:          {report.ResolvedFindings}");
        sb.AppendLine($"  Fix Rate:          {report.FixRatePercent}%");
        sb.AppendLine($"  Recurrence Rate:   {report.RecurrenceRatePercent}%");
        sb.AppendLine();

        if (report.MeanTimeToRemediate.HasValue)
        {
            sb.AppendLine("── Remediation Timing ─────────────────────────────");
            sb.AppendLine($"  Mean TTR:   {FormatDuration(report.MeanTimeToRemediate.Value)}");
            if (report.MedianTimeToRemediate.HasValue)
                sb.AppendLine($"  Median TTR: {FormatDuration(report.MedianTimeToRemediate.Value)}");
            foreach (var (sev, mttr) in report.MttrBySeverity)
                sb.AppendLine($"  MTTR ({sev}): {FormatDuration(mttr)}");
            sb.AppendLine();
        }

        if (report.MeanScanInterval.HasValue)
        {
            sb.AppendLine($"  Mean Scan Interval (MTTD proxy): {FormatDuration(report.MeanScanInterval.Value)}");
            sb.AppendLine();
        }

        if (report.CategoryRisks.Count > 0)
        {
            sb.AppendLine("── Category Risk Distribution ─────────────────────");
            sb.AppendLine($"  {"Category",-22} {"Risk",7} {"  %",5}  {"Open",5} {"Crit",5} {"Warn",5} {"Info",5}");
            sb.AppendLine($"  {"─────────────────────",-22} {"───────",7} {"─────",5}  {"─────",5} {"─────",5} {"─────",5} {"─────",5}");
            foreach (var cr in report.CategoryRisks)
            {
                sb.AppendLine($"  {cr.Category,-22} {cr.RiskScore,7:F1} {cr.RiskPercentage,4:F0}%  {cr.OpenFindings,5} {cr.CriticalCount,5} {cr.WarningCount,5} {cr.InfoCount,5}");
            }
            sb.AppendLine();
        }

        if (report.Velocity.Count > 0)
        {
            sb.AppendLine("── Finding Velocity ───────────────────────────────");
            sb.AppendLine($"  {"Period",-25} {"New",5} {"Resolved",9} {"Net",5}");
            sb.AppendLine($"  {"─────────────────────────",-25} {"─────",5} {"─────────",9} {"─────",5}");
            foreach (var vp in report.Velocity)
            {
                var label = $"{vp.PeriodStart:MM/dd} → {vp.PeriodEnd:MM/dd}";
                sb.AppendLine($"  {label,-25} {vp.NewFindings,5} {vp.ResolvedFindings,9} {vp.NetChange,5:+#;-#;0}");
            }
            sb.AppendLine();
        }

        sb.AppendLine($"  Summary: {report.Summary}");
        sb.AppendLine("═══════════════════════════════════════════════════");

        return sb.ToString();
    }

    /// <summary>Serialize report to JSON.</summary>
    public string ToJson(MetricsReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    // ── Internals ────────────────────────────────────────────────

    private PostureDirection DetermineDirection(MetricsReport report)
    {
        // Use velocity trend: if recent periods show net negative (more resolved
        // than new), posture is improving.
        if (report.Velocity.Count < 2)
            return PostureDirection.Stable;

        var recentHalf = report.Velocity
            .Skip(report.Velocity.Count / 2).ToList();
        var avgNet = recentHalf.Average(v => v.NetChange);

        if (avgNet < -0.5) return PostureDirection.Improving;
        if (avgNet > 0.5) return PostureDirection.Degrading;
        return PostureDirection.Stable;
    }

    private string BuildSummary(MetricsReport report)
    {
        var parts = new List<string>();

        parts.Add($"{report.TotalTracked} findings tracked");
        parts.Add($"{report.FixRatePercent}% fix rate");

        if (report.MeanTimeToRemediate.HasValue)
            parts.Add($"MTTR {FormatDuration(report.MeanTimeToRemediate.Value)}");

        if (report.RecurrenceRatePercent > 0)
            parts.Add($"{report.RecurrenceRatePercent}% recurrence");

        var dir = report.Direction switch
        {
            PostureDirection.Improving => "posture improving",
            PostureDirection.Degrading => "posture degrading",
            _ => "posture stable"
        };
        parts.Add(dir);

        return string.Join(", ", parts) + ".";
    }

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalDays >= 1)
            return $"{ts.TotalDays:F1}d";
        if (ts.TotalHours >= 1)
            return $"{ts.TotalHours:F1}h";
        return $"{ts.TotalMinutes:F0}m";
    }
}
