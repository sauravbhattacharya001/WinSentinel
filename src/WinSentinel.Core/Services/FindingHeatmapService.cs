using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates temporal heatmaps of security findings to identify
/// attack patterns and vulnerable time windows.
/// </summary>
public class FindingHeatmapService
{
    private static readonly string[] DayNames =
        { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };

    private static readonly string[] DayAbbrevs =
        { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };

    /// <summary>
    /// Build a heatmap from findings, bucketed by day-of-week and hour-of-day.
    /// </summary>
    public HeatmapResult Build(IEnumerable<Finding> findings, HeatmapOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        options ??= new HeatmapOptions();

        var grid = new HeatmapCell[7, 24];
        for (int d = 0; d < 7; d++)
            for (int h = 0; h < 24; h++)
                grid[d, h] = new HeatmapCell { DayOfWeek = (DayOfWeek)((d + 1) % 7), Hour = h };

        foreach (var f in findings)
        {
            if (options.MinSeverity.HasValue && f.Severity < options.MinSeverity.Value)
                continue;
            if (!string.IsNullOrEmpty(options.CategoryFilter) &&
                !f.Category.Equals(options.CategoryFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            var ts = options.TimeZone != null
                ? TimeZoneInfo.ConvertTime(f.Timestamp, options.TimeZone)
                : f.Timestamp;

            int dayIdx = DayIndex(ts.DayOfWeek);
            int hour = ts.Hour;

            var cell = grid[dayIdx, hour];
            cell.Count++;
            cell.WeightedScore += SeverityWeight(f.Severity);
            if (!cell.SeverityCounts.ContainsKey(f.Severity))
                cell.SeverityCounts[f.Severity] = 0;
            cell.SeverityCounts[f.Severity]++;
            if (!cell.Categories.Contains(f.Category) && !string.IsNullOrEmpty(f.Category))
                cell.Categories.Add(f.Category);
        }

        var cells = new List<HeatmapCell>();
        double maxWeight = 0;
        for (int d = 0; d < 7; d++)
            for (int h = 0; h < 24; h++)
            {
                cells.Add(grid[d, h]);
                if (grid[d, h].WeightedScore > maxWeight)
                    maxWeight = grid[d, h].WeightedScore;
            }

        if (maxWeight > 0)
            foreach (var c in cells)
                c.Intensity = Math.Round(c.WeightedScore / maxWeight * 10.0, 1);

        var patterns = DetectPatterns(grid, maxWeight);
        var totalCount = cells.Sum(c => c.Count);
        var hotspots = cells
            .Where(c => c.Count > 0)
            .OrderByDescending(c => c.WeightedScore)
            .Take(options.TopHotspots)
            .Select(c => new Hotspot
            {
                DayOfWeek = c.DayOfWeek, Hour = c.Hour,
                Count = c.Count, WeightedScore = c.WeightedScore, Intensity = c.Intensity
            })
            .ToList();

        var summary = new HeatmapSummary
        {
            TotalFindings = totalCount,
            TotalWeightedScore = cells.Sum(c => c.WeightedScore),
            PeakDay = cells.GroupBy(c => c.DayOfWeek)
                .OrderByDescending(g => g.Sum(c => c.WeightedScore)).First().Key,
            PeakHour = cells.GroupBy(c => c.Hour)
                .OrderByDescending(g => g.Sum(c => c.WeightedScore)).First().Key,
            WeekdayPercent = Math.Round(
                cells.Where(c => IsWeekday(c.DayOfWeek)).Sum(c => c.Count) * 100.0 / Math.Max(1, totalCount), 1),
            BusinessHoursPercent = Math.Round(
                cells.Where(c => c.Hour >= 9 && c.Hour < 17).Sum(c => c.Count) * 100.0 / Math.Max(1, totalCount), 1),
            OffHoursPercent = Math.Round(
                cells.Where(c => c.Hour < 9 || c.Hour >= 17).Sum(c => c.Count) * 100.0 / Math.Max(1, totalCount), 1)
        };

        return new HeatmapResult { Grid = grid, Cells = cells, Hotspots = hotspots, Patterns = patterns, Summary = summary };
    }

    /// <summary>Generate a text report of the heatmap.</summary>
    public string ToTextReport(HeatmapResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
        sb.AppendLine("║           FINDING TEMPORAL HEATMAP REPORT               ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine("── Summary ──────────────────────────────────────────────");
        sb.AppendLine($"  Total findings:       {result.Summary.TotalFindings}");
        sb.AppendLine($"  Weighted score:       {result.Summary.TotalWeightedScore:F1}");
        sb.AppendLine($"  Peak day:             {result.Summary.PeakDay}");
        sb.AppendLine($"  Peak hour:            {result.Summary.PeakHour}:00");
        sb.AppendLine($"  Weekday:              {result.Summary.WeekdayPercent}%");
        sb.AppendLine($"  Business hours (9-17):{result.Summary.BusinessHoursPercent}%");
        sb.AppendLine($"  Off-hours:            {result.Summary.OffHoursPercent}%");
        sb.AppendLine();
        sb.AppendLine("── Heatmap (intensity 0-10) ─────────────────────────────");
        sb.Append("       ");
        for (int h = 0; h < 24; h++) sb.Append($"{h,3}");
        sb.AppendLine();
        for (int d = 0; d < 7; d++)
        {
            sb.Append($"  {DayAbbrevs[d]} ");
            for (int h = 0; h < 24; h++)
            {
                var ch = result.Grid[d, h].Intensity switch
                {
                    0 => "  ·", < 2 => "  ░", < 5 => "  ▒", < 8 => "  ▓", _ => "  █"
                };
                sb.Append(ch);
            }
            sb.AppendLine();
        }
        sb.AppendLine();
        if (result.Hotspots.Count > 0)
        {
            sb.AppendLine("── Top Hotspots ─────────────────────────────────────────");
            foreach (var hs in result.Hotspots)
                sb.AppendLine($"  {hs.DayOfWeek,-10} {hs.Hour:D2}:00  count={hs.Count}  score={hs.WeightedScore:F1}  intensity={hs.Intensity:F1}");
            sb.AppendLine();
        }
        if (result.Patterns.Count > 0)
        {
            sb.AppendLine("── Detected Patterns ────────────────────────────────────");
            foreach (var p in result.Patterns)
                sb.AppendLine($"  [{p.Type}] {p.Description}");
            sb.AppendLine();
        }
        return sb.ToString();
    }

    /// <summary>Export heatmap to JSON.</summary>
    public string ToJson(HeatmapResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var export = new
        {
            result.Summary, result.Hotspots, result.Patterns,
            Grid = Enumerable.Range(0, 7).Select(d => new
            {
                Day = DayNames[d],
                Hours = Enumerable.Range(0, 24).Select(h => new
                {
                    Hour = h, result.Grid[d, h].Count,
                    result.Grid[d, h].WeightedScore, result.Grid[d, h].Intensity
                })
            })
        };
        return JsonSerializer.Serialize(export, new JsonSerializerOptions
        {
            WriteIndented = true, Converters = { new JsonStringEnumConverter() }
        });
    }

    private List<HeatmapPattern> DetectPatterns(HeatmapCell[,] grid, double maxWeight)
    {
        var patterns = new List<HeatmapPattern>();
        double offHours = 0, businessHours = 0, total = 0, weekend = 0, weekday = 0, lateNight = 0;
        double[] dayTotals = new double[7];

        for (int d = 0; d < 7; d++)
            for (int h = 0; h < 24; h++)
            {
                var w = grid[d, h].WeightedScore;
                total += w; dayTotals[d] += w;
                if (h < 9 || h >= 17) offHours += w; else businessHours += w;
                var dow = (DayOfWeek)((d + 1) % 7);
                if (dow == DayOfWeek.Saturday || dow == DayOfWeek.Sunday) weekend += w; else weekday += w;
                if (h < 5) lateNight += w;
            }

        if (offHours > businessHours * 2 && offHours > 0)
            patterns.Add(new HeatmapPattern { Type = PatternType.OffHoursActivity,
                Description = $"Off-hours activity is {(offHours / Math.Max(1, businessHours)):F1}x higher than business hours — possible automated attacks or unauthorized access." });

        double avgWeekday = weekday / 5.0, avgWeekend = weekend / 2.0;
        if (avgWeekend > avgWeekday * 1.5 && avgWeekend > 0)
            patterns.Add(new HeatmapPattern { Type = PatternType.WeekendSpike,
                Description = $"Weekend average ({avgWeekend:F1}) is {(avgWeekend / Math.Max(1, avgWeekday)):F1}x weekday average — investigate unattended-hours activity." });

        if (total > 0 && lateNight / total > 0.3)
            patterns.Add(new HeatmapPattern { Type = PatternType.LateNightConcentration,
                Description = $"{(lateNight / total * 100):F0}% of weighted findings occur between midnight and 5 AM." });

        for (int d = 0; d < 7; d++)
            if (total > 0 && dayTotals[d] / total > 0.4)
            {
                patterns.Add(new HeatmapPattern { Type = PatternType.SingleDayDominance,
                    Description = $"{DayNames[d]} accounts for {(dayTotals[d] / total * 100):F0}% of all weighted findings." });
                break;
            }

        int burstCount = 0;
        for (int d = 0; d < 7; d++)
            for (int h = 0; h < 24; h++)
                if (maxWeight > 0 && grid[d, h].WeightedScore > maxWeight * 0.8) burstCount++;
        if (burstCount == 1)
            patterns.Add(new HeatmapPattern { Type = PatternType.BurstPattern,
                Description = "Single time slot dominates the heatmap — possible targeted or scheduled attack." });

        return patterns;
    }

    private static int DayIndex(DayOfWeek dow) => dow switch
    {
        DayOfWeek.Monday => 0, DayOfWeek.Tuesday => 1, DayOfWeek.Wednesday => 2,
        DayOfWeek.Thursday => 3, DayOfWeek.Friday => 4, DayOfWeek.Saturday => 5,
        DayOfWeek.Sunday => 6, _ => 0
    };

    private static bool IsWeekday(DayOfWeek dow) => dow != DayOfWeek.Saturday && dow != DayOfWeek.Sunday;

    private static double SeverityWeight(Severity s) => s switch
    {
        Severity.Pass => 0, Severity.Info => 1, Severity.Warning => 3, Severity.Critical => 10, _ => 0
    };
}

public class HeatmapOptions
{
    public Severity? MinSeverity { get; set; }
    public string? CategoryFilter { get; set; }
    public TimeZoneInfo? TimeZone { get; set; }
    public int TopHotspots { get; set; } = 5;
}

public class HeatmapResult
{
    public HeatmapCell[,] Grid { get; set; } = new HeatmapCell[7, 24];
    public List<HeatmapCell> Cells { get; set; } = new();
    public List<Hotspot> Hotspots { get; set; } = new();
    public List<HeatmapPattern> Patterns { get; set; } = new();
    public HeatmapSummary Summary { get; set; } = new();
}

public class HeatmapCell
{
    public DayOfWeek DayOfWeek { get; set; }
    public int Hour { get; set; }
    public int Count { get; set; }
    public double WeightedScore { get; set; }
    public double Intensity { get; set; }
    public Dictionary<Severity, int> SeverityCounts { get; set; } = new();
    public List<string> Categories { get; set; } = new();
}

public class Hotspot
{
    public DayOfWeek DayOfWeek { get; set; }
    public int Hour { get; set; }
    public int Count { get; set; }
    public double WeightedScore { get; set; }
    public double Intensity { get; set; }
}

public class HeatmapPattern
{
    public PatternType Type { get; set; }
    public string Description { get; set; } = string.Empty;
}

public class HeatmapSummary
{
    public int TotalFindings { get; set; }
    public double TotalWeightedScore { get; set; }
    public DayOfWeek PeakDay { get; set; }
    public int PeakHour { get; set; }
    public double WeekdayPercent { get; set; }
    public double BusinessHoursPercent { get; set; }
    public double OffHoursPercent { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PatternType
{
    OffHoursActivity, WeekendSpike, LateNightConcentration, SingleDayDominance, BurstPattern
}
