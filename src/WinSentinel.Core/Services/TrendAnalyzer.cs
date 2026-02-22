using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes security score trends over time, providing statistics,
/// ASCII visualizations, streak tracking, and alert detection.
/// </summary>
public class TrendAnalyzer
{
    /// <summary>
    /// Analyze score trend from a list of audit run records.
    /// Records should be ordered newest-first (as returned by GetHistory).
    /// </summary>
    public TrendReport Analyze(List<AuditRunRecord> runs, TrendOptions? options = null)
    {
        options ??= new TrendOptions();
        var report = new TrendReport();

        if (runs.Count == 0)
        {
            report.HasData = false;
            return report;
        }

        report.HasData = true;

        // Chronological order for analysis
        var chronological = runs.OrderBy(r => r.Timestamp).ToList();
        var latest = chronological.Last();
        var oldest = chronological.First();

        // Basic stats
        report.TotalScans = chronological.Count;
        report.CurrentScore = latest.OverallScore;
        report.CurrentGrade = latest.Grade;
        report.FirstScanDate = oldest.Timestamp;
        report.LastScanDate = latest.Timestamp;
        report.TimeSpan = latest.Timestamp - oldest.Timestamp;

        var scores = chronological.Select(r => r.OverallScore).ToList();
        report.AverageScore = Math.Round(scores.Average(), 1);
        report.MedianScore = CalculateMedian(scores);
        report.MinScore = scores.Min();
        report.MaxScore = scores.Max();
        report.ScoreStdDev = Math.Round(CalculateStdDev(scores), 1);

        // Best/worst
        var best = chronological.OrderByDescending(r => r.OverallScore).First();
        report.BestScore = best.OverallScore;
        report.BestScoreDate = best.Timestamp;
        report.BestScoreGrade = best.Grade;

        var worst = chronological.OrderBy(r => r.OverallScore).First();
        report.WorstScore = worst.OverallScore;
        report.WorstScoreDate = worst.Timestamp;
        report.WorstScoreGrade = worst.Grade;

        // Score change vs previous
        if (chronological.Count >= 2)
        {
            var previous = chronological[^2];
            report.PreviousScore = previous.OverallScore;
            report.ScoreChange = latest.OverallScore - previous.OverallScore;
        }

        // Trend direction (linear regression slope)
        report.TrendSlope = CalculateSlope(scores);
        report.TrendDirection = report.TrendSlope > 0.5 ? TrendDirection.Improving
            : report.TrendSlope < -0.5 ? TrendDirection.Declining
            : TrendDirection.Stable;

        // Streaks
        CalculateStreaks(chronological, report);

        // Score distribution (buckets: 0-20, 20-40, 40-60, 60-80, 80-100)
        report.Distribution = CalculateDistribution(scores);

        // Alert conditions
        if (options.AlertThreshold.HasValue && latest.OverallScore < options.AlertThreshold.Value)
        {
            report.Alerts.Add(new TrendAlert
            {
                Level = AlertLevel.Critical,
                Message = $"Score {latest.OverallScore} is below threshold {options.AlertThreshold.Value}"
            });
        }

        if (report.ScoreChange < -10)
        {
            report.Alerts.Add(new TrendAlert
            {
                Level = AlertLevel.Warning,
                Message = $"Score dropped {Math.Abs(report.ScoreChange)} points since last scan"
            });
        }

        // Finding trends
        report.TotalCriticalCurrent = latest.CriticalCount;
        report.TotalWarningCurrent = latest.WarningCount;
        if (chronological.Count >= 2)
        {
            var prev = chronological[^2];
            report.CriticalChange = latest.CriticalCount - prev.CriticalCount;
            report.WarningChange = latest.WarningCount - prev.WarningCount;

            if (report.CriticalChange > 0)
            {
                report.Alerts.Add(new TrendAlert
                {
                    Level = AlertLevel.Warning,
                    Message = $"{report.CriticalChange} new critical finding(s) since last scan"
                });
            }
        }

        // Sparkline data (last N scores)
        var sparkCount = Math.Min(options.SparklineWidth, chronological.Count);
        report.SparklineScores = chronological
            .TakeLast(sparkCount)
            .Select(r => r.OverallScore)
            .ToList();

        // Module trends (from the last two runs with module data)
        report.ModuleTrends = BuildModuleTrends(chronological);

        return report;
    }

    /// <summary>
    /// Generate an ASCII sparkline from a series of scores.
    /// Uses Unicode block elements for compact visualization.
    /// </summary>
    public static string GenerateSparkline(List<int> scores, int minVal = 0, int maxVal = 100)
    {
        if (scores.Count == 0) return "";
        var blocks = new[] { '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█' };
        var range = Math.Max(maxVal - minVal, 1);
        var chars = scores.Select(s =>
        {
            var normalized = Math.Clamp((double)(s - minVal) / range, 0, 1);
            var idx = (int)(normalized * (blocks.Length - 1));
            return blocks[idx];
        });
        return new string(chars.ToArray());
    }

    /// <summary>
    /// Generate an ASCII bar chart for score history.
    /// Each line represents one scan with a horizontal bar.
    /// </summary>
    public static string GenerateBarChart(List<AuditRunRecord> runs, int barWidth = 40)
    {
        if (runs.Count == 0) return "No data";
        var lines = new List<string>();
        var chronological = runs.OrderBy(r => r.Timestamp).TakeLast(20).ToList();

        foreach (var run in chronological)
        {
            var date = run.Timestamp.LocalDateTime.ToString("MM/dd HH:mm");
            var filled = (int)Math.Round((double)run.OverallScore / 100 * barWidth);
            var bar = new string('█', filled) + new string('░', barWidth - filled);
            var color = run.OverallScore >= 80 ? "A" : run.OverallScore >= 60 ? "B" : run.OverallScore >= 40 ? "C" : "F";
            lines.Add($"  {date}  {bar} {run.OverallScore,3}/100 ({color})");
        }

        return string.Join(Environment.NewLine, lines);
    }

    // ── Private helpers ──────────────────────────────────────────────

    private static double CalculateSlope(List<int> values)
    {
        if (values.Count < 2) return 0;
        var n = values.Count;
        var xMean = (n - 1) / 2.0;
        var yMean = values.Average();
        var numerator = 0.0;
        var denominator = 0.0;
        for (int i = 0; i < n; i++)
        {
            numerator += (i - xMean) * (values[i] - yMean);
            denominator += (i - xMean) * (i - xMean);
        }
        return denominator == 0 ? 0 : numerator / denominator;
    }

    private static double CalculateStdDev(List<int> values)
    {
        if (values.Count < 2) return 0;
        var avg = values.Average();
        var variance = values.Sum(v => (v - avg) * (v - avg)) / (values.Count - 1);
        return Math.Sqrt(variance);
    }

    private static int CalculateMedian(List<int> values)
    {
        var sorted = values.OrderBy(v => v).ToList();
        var mid = sorted.Count / 2;
        return sorted.Count % 2 == 0
            ? (sorted[mid - 1] + sorted[mid]) / 2
            : sorted[mid];
    }

    private static void CalculateStreaks(List<AuditRunRecord> chronological, TrendReport report)
    {
        // Improvement streak: consecutive scans where score >= previous
        int currentStreak = 0;
        int bestStreak = 0;
        for (int i = 1; i < chronological.Count; i++)
        {
            if (chronological[i].OverallScore >= chronological[i - 1].OverallScore)
            {
                currentStreak++;
                bestStreak = Math.Max(bestStreak, currentStreak);
            }
            else
            {
                currentStreak = 0;
            }
        }
        report.CurrentImprovementStreak = currentStreak;
        report.BestImprovementStreak = bestStreak;

        // Decline streak
        currentStreak = 0;
        for (int i = 1; i < chronological.Count; i++)
        {
            if (chronological[i].OverallScore < chronological[i - 1].OverallScore)
            {
                currentStreak++;
            }
            else
            {
                currentStreak = 0;
            }
        }
        report.CurrentDeclineStreak = currentStreak;
    }

    private static Dictionary<string, int> CalculateDistribution(List<int> scores)
    {
        return new Dictionary<string, int>
        {
            ["0-19"] = scores.Count(s => s < 20),
            ["20-39"] = scores.Count(s => s >= 20 && s < 40),
            ["40-59"] = scores.Count(s => s >= 40 && s < 60),
            ["60-79"] = scores.Count(s => s >= 60 && s < 80),
            ["80-100"] = scores.Count(s => s >= 80),
        };
    }

    private static List<ModuleTrendInfo> BuildModuleTrends(List<AuditRunRecord> chronological)
    {
        // Find last two runs that have module score data
        var withModules = chronological
            .Where(r => r.ModuleScores.Count > 0)
            .TakeLast(2)
            .ToList();

        if (withModules.Count == 0) return [];

        var latest = withModules.Last();
        var previous = withModules.Count >= 2 ? withModules.First() : null;

        return latest.ModuleScores.Select(ms =>
        {
            var prevModule = previous?.ModuleScores
                .FirstOrDefault(p => p.ModuleName == ms.ModuleName);
            return new ModuleTrendInfo
            {
                ModuleName = ms.ModuleName,
                Category = ms.Category,
                CurrentScore = ms.Score,
                PreviousScore = prevModule?.Score,
            };
        }).OrderBy(m => m.ModuleName).ToList();
    }
}

// ── Models ───────────────────────────────────────────────────────────

/// <summary>
/// Complete trend analysis report.
/// </summary>
public class TrendReport
{
    public bool HasData { get; set; }

    // Current state
    public int CurrentScore { get; set; }
    public string CurrentGrade { get; set; } = "";
    public int? PreviousScore { get; set; }
    public int ScoreChange { get; set; }

    // Time range
    public DateTimeOffset FirstScanDate { get; set; }
    public DateTimeOffset LastScanDate { get; set; }
    public TimeSpan TimeSpan { get; set; }
    public int TotalScans { get; set; }

    // Statistics
    public double AverageScore { get; set; }
    public int MedianScore { get; set; }
    public int MinScore { get; set; }
    public int MaxScore { get; set; }
    public double ScoreStdDev { get; set; }

    // Best/worst
    public int BestScore { get; set; }
    public DateTimeOffset BestScoreDate { get; set; }
    public string BestScoreGrade { get; set; } = "";
    public int WorstScore { get; set; }
    public DateTimeOffset WorstScoreDate { get; set; }
    public string WorstScoreGrade { get; set; } = "";

    // Trend
    public double TrendSlope { get; set; }
    public TrendDirection TrendDirection { get; set; }

    // Streaks
    public int CurrentImprovementStreak { get; set; }
    public int BestImprovementStreak { get; set; }
    public int CurrentDeclineStreak { get; set; }

    // Distribution
    public Dictionary<string, int> Distribution { get; set; } = new();

    // Findings trend
    public int TotalCriticalCurrent { get; set; }
    public int TotalWarningCurrent { get; set; }
    public int CriticalChange { get; set; }
    public int WarningChange { get; set; }

    // Visualization data
    public List<int> SparklineScores { get; set; } = [];

    // Module trends
    public List<ModuleTrendInfo> ModuleTrends { get; set; } = [];

    // Alerts
    public List<TrendAlert> Alerts { get; set; } = [];
}

public enum TrendDirection
{
    Improving,
    Stable,
    Declining
}

public enum AlertLevel
{
    Info,
    Warning,
    Critical
}

public class TrendAlert
{
    public AlertLevel Level { get; set; }
    public string Message { get; set; } = "";
}

public class TrendOptions
{
    /// <summary>
    /// Alert if score drops below this value.
    /// </summary>
    public int? AlertThreshold { get; set; }

    /// <summary>
    /// Width of sparkline in characters.
    /// </summary>
    public int SparklineWidth { get; set; } = 30;
}
