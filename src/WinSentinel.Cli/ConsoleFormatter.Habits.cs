using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print the security habit tracker report with streaks and consistency.
    /// </summary>
    public static void PrintHabits(HabitReport report)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║  🔄 Security Habit Tracker                  ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        if (report.TotalHabits == 0)
        {
            WriteLineColored("  No habits configured. Add one with:", ConsoleColor.Yellow);
            WriteLineColored("    winsentinel --habits add --habit-name \"Check Windows Update\"", ConsoleColor.DarkGray);
            return;
        }

        // Summary bar
        WriteColored("  Today: ", ConsoleColor.Gray);
        var todayColor = report.CompletedToday == report.TotalHabits ? ConsoleColor.Green
                       : report.CompletedToday > 0 ? ConsoleColor.Yellow : ConsoleColor.Red;
        WriteLineColored($"{report.CompletedToday}/{report.TotalHabits} completed", todayColor);

        WriteColored("  Overall consistency (last {0} days): ", ConsoleColor.Gray);
        Console.Write(report.Days);
        var pctColor = report.OverallConsistency >= 80 ? ConsoleColor.Green
                     : report.OverallConsistency >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;

        // Fix: reprint properly
        Console.SetCursorPosition(0, Console.CursorTop);
        WriteColored($"  Overall consistency ({report.Days}d): ", ConsoleColor.Gray);
        WriteLineColored($"{report.OverallConsistency}%", pctColor);
        Console.WriteLine();

        // Per-habit details
        foreach (var stat in report.HabitStats)
        {
            WriteLineColored($"  ── {stat.Name} ──", ConsoleColor.White);
            WriteColored("    Category:    ", ConsoleColor.Gray);
            WriteLineColored(stat.Category, ConsoleColor.DarkCyan);
            WriteColored("    Consistency: ", ConsoleColor.Gray);
            var c = stat.ConsistencyPercent >= 80 ? ConsoleColor.Green
                  : stat.ConsistencyPercent >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
            WriteLineColored($"{stat.ConsistencyPercent}% ({stat.CompletedDays}/{stat.TotalDays} days)", c);

            WriteColored("    Streak:      ", ConsoleColor.Gray);
            WriteColored($"🔥 {stat.CurrentStreak} current", ConsoleColor.White);
            WriteColored(" / ", ConsoleColor.DarkGray);
            WriteLineColored($"{stat.BestStreak} best", ConsoleColor.Cyan);

            // Last 7 days visual
            WriteColored("    Last 7 days: ", ConsoleColor.Gray);
            foreach (var done in stat.Last7Days)
            {
                if (done)
                    WriteColored("■ ", ConsoleColor.Green);
                else
                    WriteColored("□ ", ConsoleColor.DarkGray);
            }
            Console.WriteLine();

            WriteColored("    Today:       ", ConsoleColor.Gray);
            if (stat.CompletedToday)
                WriteLineColored("✅ Done", ConsoleColor.Green);
            else
                WriteLineColored("⬜ Pending", ConsoleColor.Yellow);

            Console.WriteLine();
        }
    }

    /// <summary>Print the list of configured habits.</summary>
    public static void PrintHabitList(List<HabitDefinition> habits)
    {
        Console.WriteLine();
        WriteLineColored("  Configured Security Habits:", ConsoleColor.Cyan);
        Console.WriteLine();
        if (habits.Count == 0)
        {
            WriteLineColored("  (none)", ConsoleColor.DarkGray);
            return;
        }
        foreach (var h in habits)
        {
            WriteColored($"  • {h.Name}", ConsoleColor.White);
            WriteColored($"  [{h.Category}]", ConsoleColor.DarkCyan);
            WriteColored($"  ({h.Frequency})", ConsoleColor.DarkGray);
            WriteLineColored($"  since {h.CreatedDate}", ConsoleColor.DarkGray);
        }
        Console.WriteLine();
    }
}
