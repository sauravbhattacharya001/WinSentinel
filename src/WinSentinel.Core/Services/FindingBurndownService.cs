using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates finding burndown charts and velocity statistics from audit history.
/// Shows how findings are being resolved over time with projected zero-date.
/// </summary>
public class FindingBurndownService
{
    /// <summary>Analyze audit history and produce a burndown report.</summary>
    public BurndownReport Analyze(List<AuditRunRecord> runs, BurndownOptions options)
    {
        if (runs.Count == 0)
            return new BurndownReport { HasData = false };

        // Sort oldest → newest
        var sorted = runs.OrderBy(r => r.Timestamp).ToList();

        var dataPoints = sorted.Select(r => new BurndownDataPoint
        {
            Timestamp = r.Timestamp,
            TotalFindings = r.TotalFindings,
            CriticalCount = r.CriticalCount,
            WarningCount = r.WarningCount,
            InfoCount = r.InfoCount,
            Score = r.OverallScore
        }).ToList();

        // Calculate velocity (findings resolved per day)
        var velocityStats = CalculateVelocity(dataPoints);

        // Project zero-findings date
        DateTimeOffset? projectedZero = null;
        if (velocityStats.AverageDailyReduction > 0 && dataPoints.Count > 0 && dataPoints[^1].TotalFindings > 0)
        {
            var latest = dataPoints[^1];
            var daysToZero = latest.TotalFindings / velocityStats.AverageDailyReduction;
            if (daysToZero <= 365) // Only project if reasonable
                projectedZero = latest.Timestamp.AddDays(daysToZero);
        }

        // Per-severity burndown
        var severityTrends = new Dictionary<string, List<int>>();
        severityTrends["Critical"] = dataPoints.Select(d => d.CriticalCount).ToList();
        severityTrends["Warning"] = dataPoints.Select(d => d.WarningCount).ToList();
        severityTrends["Info"] = dataPoints.Select(d => d.InfoCount).ToList();

        // Weekly buckets for velocity chart
        var weeklyVelocity = CalculateWeeklyVelocity(dataPoints);

        return new BurndownReport
        {
            HasData = true,
            DataPoints = dataPoints,
            Velocity = velocityStats,
            ProjectedZeroDate = projectedZero,
            SeverityTrends = severityTrends,
            WeeklyVelocity = weeklyVelocity,
            AnalyzedFrom = sorted[0].Timestamp,
            AnalyzedTo = sorted[^1].Timestamp,
            TotalRuns = sorted.Count
        };
    }

    private static VelocityStats CalculateVelocity(List<BurndownDataPoint> points)
    {
        var stats = new VelocityStats();
        if (points.Count < 2) return stats;

        var first = points[0];
        var last = points[^1];
        var totalDays = (last.Timestamp - first.Timestamp).TotalDays;

        if (totalDays < 0.01) return stats;

        var totalChange = first.TotalFindings - last.TotalFindings;
        stats.AverageDailyReduction = totalChange / totalDays;
        stats.TotalResolved = Math.Max(0, totalChange);
        stats.TotalNew = Math.Max(0, -totalChange);

        // Per-interval changes
        for (int i = 1; i < points.Count; i++)
        {
            var delta = points[i - 1].TotalFindings - points[i].TotalFindings;
            if (delta > 0) stats.ResolutionIntervals++;
            else if (delta < 0) stats.RegressionIntervals++;
            else stats.FlatIntervals++;

            stats.BestSingleDrop = Math.Max(stats.BestSingleDrop, delta);
            stats.WorstSingleSpike = Math.Max(stats.WorstSingleSpike, -delta);
        }

        // Streak tracking
        int currentStreak = 0;
        bool improving = false;
        for (int i = 1; i < points.Count; i++)
        {
            var delta = points[i - 1].TotalFindings - points[i].TotalFindings;
            if (delta > 0)
            {
                if (improving) currentStreak++;
                else { improving = true; currentStreak = 1; }
                stats.BestImprovementStreak = Math.Max(stats.BestImprovementStreak, currentStreak);
            }
            else
            {
                improving = false;
                currentStreak = 0;
            }
        }

        return stats;
    }

    private static List<WeeklyBucket> CalculateWeeklyVelocity(List<BurndownDataPoint> points)
    {
        if (points.Count < 2) return [];

        var buckets = new List<WeeklyBucket>();
        var startOfWeek = points[0].Timestamp;

        var weekPoints = new List<BurndownDataPoint>();
        foreach (var p in points)
        {
            if ((p.Timestamp - startOfWeek).TotalDays >= 7 && weekPoints.Count > 0)
            {
                buckets.Add(MakeBucket(startOfWeek, weekPoints));
                startOfWeek = p.Timestamp;
                weekPoints = [];
            }
            weekPoints.Add(p);
        }
        if (weekPoints.Count > 0)
            buckets.Add(MakeBucket(startOfWeek, weekPoints));

        return buckets;
    }

    private static WeeklyBucket MakeBucket(DateTimeOffset weekStart, List<BurndownDataPoint> points)
    {
        var first = points[0].TotalFindings;
        var last = points[^1].TotalFindings;
        return new WeeklyBucket
        {
            WeekStart = weekStart,
            StartFindings = first,
            EndFindings = last,
            Delta = last - first,
            Scans = points.Count
        };
    }

    /// <summary>Render the burndown report as an ASCII chart + stats.</summary>
    public static string RenderText(BurndownReport report)
    {
        if (!report.HasData)
            return "  No audit history data available.";

        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════╗");
        sb.AppendLine("  ║     📉 Finding Burndown Chart               ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════╝");
        sb.AppendLine();

        // ASCII chart
        RenderAsciiChart(sb, report.DataPoints);

        // Velocity stats
        sb.AppendLine("  VELOCITY");
        sb.AppendLine("  ──────────────────────────────────────────");
        var v = report.Velocity;
        if (v.AverageDailyReduction > 0)
            sb.AppendLine($"  Avg reduction:   {v.AverageDailyReduction:F1} findings/day");
        else if (v.AverageDailyReduction < 0)
            sb.AppendLine($"  Avg increase:    {Math.Abs(v.AverageDailyReduction):F1} findings/day ⚠");
        else
            sb.AppendLine("  Avg change:      0 (flat)");

        sb.AppendLine($"  Total resolved:  {v.TotalResolved}");
        sb.AppendLine($"  Total new:       {v.TotalNew}");
        sb.AppendLine($"  Best single drop: {v.BestSingleDrop}");
        if (v.WorstSingleSpike > 0)
            sb.AppendLine($"  Worst spike:     +{v.WorstSingleSpike}");
        sb.AppendLine($"  Improving scans: {v.ResolutionIntervals} | Regressing: {v.RegressionIntervals} | Flat: {v.FlatIntervals}");
        if (v.BestImprovementStreak > 1)
            sb.AppendLine($"  Best streak:     {v.BestImprovementStreak} consecutive improvements");
        sb.AppendLine();

        // Projection
        sb.AppendLine("  PROJECTION");
        sb.AppendLine("  ──────────────────────────────────────────");
        if (report.ProjectedZeroDate.HasValue)
        {
            var daysLeft = (report.ProjectedZeroDate.Value - DateTimeOffset.Now).TotalDays;
            sb.AppendLine($"  Zero findings:   {report.ProjectedZeroDate.Value.LocalDateTime:MMM d, yyyy} (~{(int)daysLeft} days)");
        }
        else if (report.DataPoints.Count > 0 && report.DataPoints[^1].TotalFindings == 0)
        {
            sb.AppendLine("  Status:          ✅ Already at zero findings!");
        }
        else
        {
            sb.AppendLine("  Status:          ⚠ Findings increasing or flat — no projected zero date");
        }
        sb.AppendLine();

        // Severity breakdown over time
        sb.AppendLine("  SEVERITY TREND");
        sb.AppendLine("  ──────────────────────────────────────────");
        if (report.DataPoints.Count >= 2)
        {
            var first = report.DataPoints[0];
            var last = report.DataPoints[^1];
            AppendSeverityLine(sb, "Critical", first.CriticalCount, last.CriticalCount);
            AppendSeverityLine(sb, "Warning", first.WarningCount, last.WarningCount);
            AppendSeverityLine(sb, "Info", first.InfoCount, last.InfoCount);
        }
        sb.AppendLine();

        // Weekly velocity
        if (report.WeeklyVelocity.Count >= 2)
        {
            sb.AppendLine("  WEEKLY VELOCITY");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var week in report.WeeklyVelocity.TakeLast(8))
            {
                var arrow = week.Delta < 0 ? "↓" : week.Delta > 0 ? "↑" : "→";
                var sign = week.Delta > 0 ? "+" : "";
                sb.AppendLine($"  {week.WeekStart.LocalDateTime:MMM dd}  {week.EndFindings,4} findings  {arrow} {sign}{week.Delta}  ({week.Scans} scans)");
            }
            sb.AppendLine();
        }

        sb.AppendLine($"  Period: {report.AnalyzedFrom.LocalDateTime:g} → {report.AnalyzedTo.LocalDateTime:g} ({report.TotalRuns} scans)");
        sb.AppendLine();

        return sb.ToString();
    }

    private static void RenderAsciiChart(StringBuilder sb, List<BurndownDataPoint> points)
    {
        const int chartWidth = 50;
        const int chartHeight = 12;

        if (points.Count == 0) return;

        var maxFindings = points.Max(p => p.TotalFindings);
        if (maxFindings == 0) maxFindings = 1;

        // Sample points if too many
        var sampled = points;
        if (points.Count > chartWidth)
        {
            var step = (double)points.Count / chartWidth;
            sampled = Enumerable.Range(0, chartWidth)
                .Select(i => points[Math.Min((int)(i * step), points.Count - 1)])
                .ToList();
        }

        // Render rows top-down
        for (int row = chartHeight; row >= 0; row--)
        {
            var threshold = (int)((double)row / chartHeight * maxFindings);
            if (row == chartHeight)
                sb.Append($"  {maxFindings,4} │");
            else if (row == chartHeight / 2)
                sb.Append($"  {maxFindings / 2,4} │");
            else if (row == 0)
                sb.Append($"     0 │");
            else
                sb.Append("       │");

            foreach (var p in sampled)
            {
                var normalizedHeight = (int)((double)p.TotalFindings / maxFindings * chartHeight);
                if (normalizedHeight >= row && row > 0)
                    sb.Append('█');
                else if (normalizedHeight >= row)
                    sb.Append('▄');
                else
                    sb.Append(' ');
            }
            sb.AppendLine();
        }

        sb.Append("       └");
        sb.AppendLine(new string('─', sampled.Count));

        // Date labels
        if (sampled.Count >= 2)
        {
            var firstDate = sampled[0].Timestamp.LocalDateTime.ToString("MMM dd");
            var lastDate = sampled[^1].Timestamp.LocalDateTime.ToString("MMM dd");
            var padding = sampled.Count - firstDate.Length - lastDate.Length;
            sb.Append("        ");
            sb.Append(firstDate);
            if (padding > 0) sb.Append(new string(' ', padding));
            sb.AppendLine(lastDate);
        }
        sb.AppendLine();
    }

    private static void AppendSeverityLine(StringBuilder sb, string label, int start, int end)
    {
        var delta = end - start;
        var arrow = delta < 0 ? "↓" : delta > 0 ? "↑" : "→";
        var sign = delta > 0 ? "+" : "";
        sb.AppendLine($"  {label,-12} {start,3} → {end,3}  ({arrow} {sign}{delta})");
    }

    /// <summary>Render the burndown report as JSON.</summary>
    public static string RenderJson(BurndownReport report)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(report, jsonOptions);
    }

    /// <summary>Render as CSV (timestamp,total,critical,warning,info,score).</summary>
    public static string RenderCsv(BurndownReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("timestamp,total_findings,critical,warning,info,score");
        foreach (var p in report.DataPoints)
            sb.AppendLine($"{p.Timestamp:o},{p.TotalFindings},{p.CriticalCount},{p.WarningCount},{p.InfoCount},{p.Score}");
        return sb.ToString();
    }
}

/// <summary>Options for burndown analysis.</summary>
public class BurndownOptions
{
    public int Days { get; set; } = 90;
}

/// <summary>Complete burndown report.</summary>
public class BurndownReport
{
    public bool HasData { get; set; }
    public List<BurndownDataPoint> DataPoints { get; set; } = [];
    public VelocityStats Velocity { get; set; } = new();
    public DateTimeOffset? ProjectedZeroDate { get; set; }
    public Dictionary<string, List<int>> SeverityTrends { get; set; } = new();
    public List<WeeklyBucket> WeeklyVelocity { get; set; } = [];
    public DateTimeOffset AnalyzedFrom { get; set; }
    public DateTimeOffset AnalyzedTo { get; set; }
    public int TotalRuns { get; set; }
}

/// <summary>A single data point in the burndown.</summary>
public class BurndownDataPoint
{
    public DateTimeOffset Timestamp { get; set; }
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int Score { get; set; }
}

/// <summary>Velocity statistics for finding resolution.</summary>
public class VelocityStats
{
    public double AverageDailyReduction { get; set; }
    public int TotalResolved { get; set; }
    public int TotalNew { get; set; }
    public int BestSingleDrop { get; set; }
    public int WorstSingleSpike { get; set; }
    public int ResolutionIntervals { get; set; }
    public int RegressionIntervals { get; set; }
    public int FlatIntervals { get; set; }
    public int BestImprovementStreak { get; set; }
}

/// <summary>Weekly aggregated velocity bucket.</summary>
public class WeeklyBucket
{
    public DateTimeOffset WeekStart { get; set; }
    public int StartFindings { get; set; }
    public int EndFindings { get; set; }
    public int Delta { get; set; }
    public int Scans { get; set; }
}
