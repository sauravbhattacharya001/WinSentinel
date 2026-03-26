namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Generates a GitHub-style calendar heatmap of audit activity.
/// </summary>
public class CalendarHeatmapService
{
    /// <summary>
    /// Analyze audit runs and produce a calendar heatmap model.
    /// </summary>
    public CalendarHeatmap Analyze(List<AuditRunRecord> runs, int weeks = 26)
    {
        var heatmap = new CalendarHeatmap { Weeks = weeks };
        var endDate = DateOnly.FromDateTime(DateTime.Now);
        // Align to end-of-week (Sunday)
        var daysUntilSunday = ((int)DayOfWeek.Sunday - (int)endDate.DayOfWeek + 7) % 7;
        var endSunday = endDate.AddDays(daysUntilSunday);
        var startDate = endSunday.AddDays(-(weeks * 7) + 1);

        // Group runs by date
        var runsByDate = new Dictionary<DateOnly, List<AuditRunRecord>>();
        foreach (var run in runs)
        {
            var date = DateOnly.FromDateTime(run.Timestamp.LocalDateTime);
            if (!runsByDate.ContainsKey(date))
                runsByDate[date] = [];
            runsByDate[date].Add(run);
        }

        int totalAudits = 0;
        int activeDays = 0;
        int maxAuditsInDay = 0;
        int bestScore = 0;
        int worstScore = 100;
        int currentStreak = 0;
        int longestStreak = 0;
        bool streakActive = true;

        // Build day cells from most recent backward
        for (var d = endSunday; d >= startDate; d = d.AddDays(-1))
        {
            var cell = new HeatmapDay
            {
                Date = d,
                DayOfWeek = d.DayOfWeek
            };

            if (runsByDate.TryGetValue(d, out var dayRuns))
            {
                cell.AuditCount = dayRuns.Count;
                cell.AvgScore = (int)dayRuns.Average(r => r.OverallScore);
                cell.TotalFindings = dayRuns.Sum(r => r.TotalFindings);
                cell.CriticalCount = dayRuns.Sum(r => r.CriticalCount);
                cell.BestScore = dayRuns.Max(r => r.OverallScore);

                totalAudits += dayRuns.Count;
                activeDays++;
                if (dayRuns.Count > maxAuditsInDay) maxAuditsInDay = dayRuns.Count;
                if (cell.BestScore > bestScore) bestScore = cell.BestScore;
                var dayWorst = dayRuns.Min(r => r.OverallScore);
                if (dayWorst < worstScore) worstScore = dayWorst;

                if (streakActive) currentStreak++;
            }
            else
            {
                if (d <= endDate) // Don't break streak on future days
                    streakActive = false;
            }

            heatmap.Days.Add(cell);
        }

        // Compute longest streak
        var sortedDates = runsByDate.Keys.OrderBy(d => d).ToList();
        int tempStreak = 1;
        longestStreak = sortedDates.Count > 0 ? 1 : 0;
        for (int i = 1; i < sortedDates.Count; i++)
        {
            if (sortedDates[i].DayNumber - sortedDates[i - 1].DayNumber == 1)
            {
                tempStreak++;
                if (tempStreak > longestStreak) longestStreak = tempStreak;
            }
            else
            {
                tempStreak = 1;
            }
        }

        heatmap.TotalAudits = totalAudits;
        heatmap.ActiveDays = activeDays;
        heatmap.MaxAuditsInDay = maxAuditsInDay;
        heatmap.BestScore = runs.Count > 0 ? bestScore : 0;
        heatmap.WorstScore = runs.Count > 0 ? worstScore : 0;
        heatmap.CurrentStreak = currentStreak;
        heatmap.LongestStreak = longestStreak;

        // Reverse so days are in chronological order
        heatmap.Days.Reverse();

        return heatmap;
    }
}

/// <summary>Calendar heatmap result model.</summary>
public class CalendarHeatmap
{
    public int Weeks { get; set; }
    public int TotalAudits { get; set; }
    public int ActiveDays { get; set; }
    public int MaxAuditsInDay { get; set; }
    public int BestScore { get; set; }
    public int WorstScore { get; set; }
    public int CurrentStreak { get; set; }
    public int LongestStreak { get; set; }
    public List<HeatmapDay> Days { get; set; } = [];
}

/// <summary>Single day cell in the heatmap.</summary>
public class HeatmapDay
{
    public DateOnly Date { get; set; }
    public DayOfWeek DayOfWeek { get; set; }
    public int AuditCount { get; set; }
    public int AvgScore { get; set; }
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int BestScore { get; set; }
}
