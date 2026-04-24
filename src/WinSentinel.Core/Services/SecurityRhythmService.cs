namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Temporal rhythm analyzer: detects periodic patterns in security findings,
/// identifies active/quiet hours, weekly cycles, and recommends optimal scan windows.
/// </summary>
public sealed class SecurityRhythmService
{
    private readonly AuditHistoryService _history;
    public SecurityRhythmService(AuditHistoryService history) => _history = history;

    public RhythmReport Analyze(int historyDays = 90, string granularity = "hourly")
    {
        var runs = _history.GetHistory(historyDays);
        if (runs.Count < 3) return new RhythmReport { AnalyzedRuns = runs.Count };

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var report = new RhythmReport
        {
            AnalyzedRuns = runs.Count,
            HistoryDays = historyDays,
            Granularity = granularity,
            FirstRun = ordered.First().Timestamp.LocalDateTime,
            LastRun = ordered.Last().Timestamp.LocalDateTime
        };

        // Hourly distribution (0-23)
        var hourlyScores = new double[24];
        var hourlyCounts = new int[24];
        var hourlyFindings = new int[24];
        foreach (var run in ordered)
        {
            var hour = run.Timestamp.ToLocalTime().Hour;
            hourlyScores[hour] += run.OverallScore;
            hourlyCounts[hour]++;
            hourlyFindings[hour] += run.TotalFindings;
        }

        for (int h = 0; h < 24; h++)
        {
            if (hourlyCounts[h] > 0)
            {
                report.HourlyProfile.Add(new HourSlot
                {
                    Hour = h,
                    AvgScore = hourlyScores[h] / hourlyCounts[h],
                    AvgFindings = (double)hourlyFindings[h] / hourlyCounts[h],
                    RunCount = hourlyCounts[h]
                });
            }
        }

        // Day-of-week distribution
        var dowScores = new double[7];
        var dowCounts = new int[7];
        var dowFindings = new int[7];
        foreach (var run in ordered)
        {
            var dow = (int)run.Timestamp.ToLocalTime().DayOfWeek;
            dowScores[dow] += run.OverallScore;
            dowCounts[dow]++;
            dowFindings[dow] += run.TotalFindings;
        }

        var dayNames = new[] { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
        for (int d = 0; d < 7; d++)
        {
            if (dowCounts[d] > 0)
            {
                report.WeeklyProfile.Add(new DaySlot
                {
                    DayOfWeek = dayNames[d],
                    DayIndex = d,
                    AvgScore = dowScores[d] / dowCounts[d],
                    AvgFindings = (double)dowFindings[d] / dowCounts[d],
                    RunCount = dowCounts[d]
                });
            }
        }

        // Detect periodicity using autocorrelation on daily finding counts
        var dailyBuckets = new Dictionary<DateOnly, int>();
        foreach (var run in ordered)
        {
            var day = DateOnly.FromDateTime(run.Timestamp.LocalDateTime);
            dailyBuckets.TryGetValue(day, out var existing);
            dailyBuckets[day] = existing + run.TotalFindings;
        }

        if (dailyBuckets.Count >= 14)
        {
            var startDate = dailyBuckets.Keys.Min();
            var endDate = dailyBuckets.Keys.Max();
            var totalDays = endDate.DayNumber - startDate.DayNumber + 1;
            var series = new double[totalDays];
            for (int i = 0; i < totalDays; i++)
            {
                var d = startDate.AddDays(i);
                series[i] = dailyBuckets.TryGetValue(d, out var v) ? v : 0;
            }

            var mean = series.Average();
            var variance = series.Sum(x => (x - mean) * (x - mean));

            if (variance > 0)
            {
                for (int lag = 1; lag <= Math.Min(totalDays / 2, 30); lag++)
                {
                    double autocorr = 0;
                    for (int i = 0; i < totalDays - lag; i++)
                        autocorr += (series[i] - mean) * (series[i + lag] - mean);
                    autocorr /= variance;

                    if (autocorr > 0.3)
                    {
                        report.DetectedCycles.Add(new CycleDetection
                        {
                            PeriodDays = lag,
                            Strength = autocorr,
                            Label = lag switch
                            {
                                7 => "Weekly cycle",
                                14 => "Biweekly cycle",
                                28 or 29 or 30 or 31 => "Monthly cycle",
                                _ => $"{lag}-day cycle"
                            }
                        });
                    }
                }
            }
        }

        // Identify quiet windows (best times for maintenance)
        if (report.HourlyProfile.Count > 0)
        {
            var sorted = report.HourlyProfile.OrderBy(h => h.AvgFindings).ToList();
            report.QuietWindows = sorted.Take(Math.Min(3, sorted.Count)).Select(h => new TimeWindow
            {
                StartHour = h.Hour,
                EndHour = (h.Hour + 1) % 24,
                Reason = $"Avg {h.AvgFindings:F1} findings, score {h.AvgScore:F0}"
            }).ToList();

            var hotSorted = report.HourlyProfile.OrderByDescending(h => h.AvgFindings).ToList();
            report.HotWindows = hotSorted.Take(Math.Min(3, hotSorted.Count)).Select(h => new TimeWindow
            {
                StartHour = h.Hour,
                EndHour = (h.Hour + 1) % 24,
                Reason = $"Avg {h.AvgFindings:F1} findings, score {h.AvgScore:F0}"
            }).ToList();
        }

        // Proactive recommendations
        if (report.QuietWindows.Count > 0)
            report.Recommendations.Add($"Schedule maintenance during quiet window: {report.QuietWindows[0].StartHour:D2}:00-{report.QuietWindows[0].EndHour:D2}:00");

        if (report.HotWindows.Count > 0)
            report.Recommendations.Add($"Increase monitoring during peak threat hour: {report.HotWindows[0].StartHour:D2}:00-{report.HotWindows[0].EndHour:D2}:00");

        var weeklyBest = report.WeeklyProfile.OrderBy(d => d.AvgFindings).FirstOrDefault();
        var weeklyWorst = report.WeeklyProfile.OrderByDescending(d => d.AvgFindings).FirstOrDefault();
        if (weeklyBest != null)
            report.Recommendations.Add($"Best day for updates: {weeklyBest.DayOfWeek} (avg {weeklyBest.AvgFindings:F1} findings)");
        if (weeklyWorst != null)
            report.Recommendations.Add($"Highest risk day: {weeklyWorst.DayOfWeek} (avg {weeklyWorst.AvgFindings:F1} findings) — consider extra scans");

        var strongCycles = report.DetectedCycles.Where(c => c.Strength > 0.5).OrderByDescending(c => c.Strength).Take(2).ToList();
        foreach (var cycle in strongCycles)
            report.Recommendations.Add($"Strong {cycle.Label} detected (r={cycle.Strength:F2}) — align scan cadence to {cycle.PeriodDays}-day interval");

        report.RhythmScore = CalculateRhythmScore(report);
        report.RhythmVerdict = report.RhythmScore switch
        {
            >= 80 => "Highly Predictable",
            >= 60 => "Regular Patterns",
            >= 40 => "Some Patterns",
            >= 20 => "Mostly Random",
            _ => "Chaotic"
        };

        return report;
    }

    private static int CalculateRhythmScore(RhythmReport report)
    {
        double score = 50;
        if (report.DetectedCycles.Count > 0)
            score += report.DetectedCycles.Max(c => c.Strength) * 25;
        if (report.HourlyProfile.Count >= 6)
        {
            var cv = CoeffOfVariation(report.HourlyProfile.Select(h => h.AvgFindings));
            score += Math.Min(15, cv * 10);
        }
        if (report.WeeklyProfile.Count >= 5)
        {
            var cv = CoeffOfVariation(report.WeeklyProfile.Select(d => d.AvgFindings));
            score += Math.Min(10, cv * 8);
        }
        return Math.Clamp((int)score, 0, 100);
    }

    private static double CoeffOfVariation(IEnumerable<double> values)
    {
        var list = values.ToList();
        if (list.Count < 2) return 0;
        var mean = list.Average();
        if (mean == 0) return 0;
        var stddev = Math.Sqrt(list.Sum(x => (x - mean) * (x - mean)) / list.Count);
        return stddev / mean;
    }
}

public class RhythmReport
{
    public int AnalyzedRuns { get; set; }
    public int HistoryDays { get; set; }
    public string Granularity { get; set; } = "";
    public DateTime FirstRun { get; set; }
    public DateTime LastRun { get; set; }
    public int RhythmScore { get; set; }
    public string RhythmVerdict { get; set; } = "";
    public List<HourSlot> HourlyProfile { get; set; } = new();
    public List<DaySlot> WeeklyProfile { get; set; } = new();
    public List<CycleDetection> DetectedCycles { get; set; } = new();
    public List<TimeWindow> QuietWindows { get; set; } = new();
    public List<TimeWindow> HotWindows { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
}

public class HourSlot
{
    public int Hour { get; set; }
    public double AvgScore { get; set; }
    public double AvgFindings { get; set; }
    public int RunCount { get; set; }
}

public class DaySlot
{
    public string DayOfWeek { get; set; } = "";
    public int DayIndex { get; set; }
    public double AvgScore { get; set; }
    public double AvgFindings { get; set; }
    public int RunCount { get; set; }
}

public class CycleDetection
{
    public int PeriodDays { get; set; }
    public double Strength { get; set; }
    public string Label { get; set; } = "";
}

public class TimeWindow
{
    public int StartHour { get; set; }
    public int EndHour { get; set; }
    public string Reason { get; set; } = "";
}
