using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a GitHub-style calendar heatmap of audit activity.
    /// </summary>
    public static void PrintCalendarHeatmap(CalendarHeatmap heatmap)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║  📅 Audit Activity Heatmap                  ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        if (heatmap.TotalAudits == 0)
        {
            WriteLineColored("  No audit history found. Run some audits to see your activity!", ConsoleColor.Yellow);
            return;
        }

        // Stats summary
        WriteColored("  Total Audits: ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.TotalAudits}", ConsoleColor.Green);

        WriteColored("  Active Days:  ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.ActiveDays}", ConsoleColor.Green);

        WriteColored("  Best Score:   ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.BestScore}/100", ScoreColor(heatmap.BestScore));

        WriteColored("  Worst Score:  ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.WorstScore}/100", ScoreColor(heatmap.WorstScore));

        WriteColored("  Current Streak: ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.CurrentStreak} day{(heatmap.CurrentStreak == 1 ? "" : "s")} 🔥", ConsoleColor.Yellow);

        WriteColored("  Longest Streak: ", ConsoleColor.Gray);
        WriteLineColored($"{heatmap.LongestStreak} day{(heatmap.LongestStreak == 1 ? "" : "s")} 🏆", ConsoleColor.Yellow);

        Console.WriteLine();

        // Render heatmap grid: 7 rows (Mon-Sun) x N weeks
        var grid = new Dictionary<(int dow, int week), HeatmapDay>();
        if (heatmap.Days.Count > 0)
        {
            var firstDate = heatmap.Days[0].Date;
            foreach (var day in heatmap.Days)
            {
                int daysSinceStart = day.Date.DayNumber - firstDate.DayNumber;
                int weekIdx = daysSinceStart / 7;
                int dow = (int)day.DayOfWeek;
                grid[(dow, weekIdx)] = day;
            }
        }

        int totalWeeks = heatmap.Weeks;

        // Month labels row
        string[] monthNames = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        int lastMonth = -1;
        Console.Write("       ");
        for (int w = 0; w < totalWeeks; w++)
        {
            if (grid.TryGetValue((0, w), out var sun))
            {
                if (sun.Date.Month != lastMonth)
                {
                    Console.Write(monthNames[sun.Date.Month - 1].PadRight(3));
                    lastMonth = sun.Date.Month;
                    w += 1;
                    continue;
                }
            }
            Console.Write("  ");
        }
        Console.WriteLine();

        // Day rows
        string[] dayLabels = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        int[] rowOrder = { 1, 2, 3, 4, 5, 6, 0 };

        foreach (var dow in rowOrder)
        {
            if (dow == 1 || dow == 3 || dow == 5)
                WriteColored($"  {dayLabels[dow]} ", ConsoleColor.DarkGray);
            else
                Console.Write("      ");

            for (int w = 0; w < totalWeeks; w++)
            {
                if (grid.TryGetValue((dow, w), out var day))
                {
                    var (symbol, color) = GetHeatmapCellDisplay(day.AuditCount, heatmap.MaxAuditsInDay, day.CriticalCount);
                    WriteColored(symbol, color);
                }
                else
                {
                    WriteColored("· ", ConsoleColor.DarkGray);
                }
            }
            Console.WriteLine();
        }

        Console.WriteLine();

        // Legend
        WriteColored("  Less ", ConsoleColor.DarkGray);
        WriteColored("· ", ConsoleColor.DarkGray);
        WriteColored("░ ", ConsoleColor.DarkGreen);
        WriteColored("▒ ", ConsoleColor.Green);
        WriteColored("▓ ", ConsoleColor.Cyan);
        WriteColored("█ ", ConsoleColor.White);
        WriteLineColored(" More", ConsoleColor.DarkGray);
        WriteColored("  ", ConsoleColor.DarkGray);
        WriteColored("✖ ", ConsoleColor.Red);
        WriteLineColored("= day with critical findings", ConsoleColor.DarkGray);

        Console.WriteLine();

        // Weekly summary (last 4 weeks)
        WriteLineColored("  Recent Weekly Summary:", ConsoleColor.Gray);
        WriteLineColored("  ─────────────────────────────────────", ConsoleColor.DarkGray);

        for (int w = Math.Max(0, totalWeeks - 4); w < totalWeeks; w++)
        {
            int weekAudits = 0;
            int weekFindings = 0;
            int weekCritical = 0;
            int weekBestScore = 0;
            DateOnly? weekStart = null;

            for (int dow = 0; dow < 7; dow++)
            {
                if (grid.TryGetValue((dow, w), out var day))
                {
                    weekAudits += day.AuditCount;
                    weekFindings += day.TotalFindings;
                    weekCritical += day.CriticalCount;
                    if (day.BestScore > weekBestScore) weekBestScore = day.BestScore;
                    weekStart ??= day.Date;
                }
            }

            if (weekStart.HasValue)
            {
                WriteColored($"  {weekStart.Value:MMM dd}: ", ConsoleColor.DarkGray);
                WriteColored($"{weekAudits} audit{(weekAudits == 1 ? "" : "s")}", ConsoleColor.White);
                WriteColored(" | ", ConsoleColor.DarkGray);
                WriteColored($"{weekFindings} findings", ConsoleColor.Yellow);
                if (weekCritical > 0)
                {
                    WriteColored(" | ", ConsoleColor.DarkGray);
                    WriteColored($"{weekCritical} critical", ConsoleColor.Red);
                }
                if (weekBestScore > 0)
                {
                    WriteColored(" | best: ", ConsoleColor.DarkGray);
                    WriteColored($"{weekBestScore}", ScoreColor(weekBestScore));
                }
                Console.WriteLine();
            }
        }

        Console.WriteLine();
    }

    private static (string symbol, ConsoleColor color) GetHeatmapCellDisplay(int auditCount, int maxAudits, int criticalCount)
    {
        if (criticalCount > 0)
            return ("✖ ", ConsoleColor.Red);

        if (auditCount == 0)
            return ("· ", ConsoleColor.DarkGray);

        if (maxAudits <= 1)
            return ("█ ", ConsoleColor.White);

        double ratio = (double)auditCount / maxAudits;
        return ratio switch
        {
            >= 0.75 => ("█ ", ConsoleColor.White),
            >= 0.50 => ("▓ ", ConsoleColor.Cyan),
            >= 0.25 => ("▒ ", ConsoleColor.Green),
            _ => ("░ ", ConsoleColor.DarkGreen)
        };
    }
}
