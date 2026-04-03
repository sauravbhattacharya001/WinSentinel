namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintCalendar(
        List<CalendarEvent> events,
        int totalRuns,
        double avgInterval,
        double recommendedInterval,
        int latestScore,
        int criticalCount,
        int forecastDays)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📅  Security Calendar                 ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        // Audit cadence summary
        Console.WriteLine();
        Console.Write("  Audit History: ");
        WriteColored($"{totalRuns}", ConsoleColor.White);
        Console.Write(" runs, avg interval ");
        WriteColored($"{avgInterval:F1}", ConsoleColor.White);
        Console.WriteLine(" days");

        Console.Write("  Recommended Cadence: every ");
        WriteColored($"{recommendedInterval}", ConsoleColor.Green);
        Console.WriteLine(" days");

        Console.Write("  Latest Score: ");
        var scoreColor = latestScore >= 80 ? ConsoleColor.Green :
                         latestScore >= 60 ? ConsoleColor.Yellow : ConsoleColor.Red;
        WriteColored($"{latestScore}/100", scoreColor);
        Console.WriteLine();

        if (criticalCount > 0)
        {
            Console.Write("  Active Critical/High: ");
            WriteColored($"{criticalCount}", ConsoleColor.Red);
            Console.WriteLine(" (SLA deadlines generated)");
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ─── Upcoming {forecastDays} Days ──────────────────────────────");
        Console.ResetColor();

        if (events.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No events scheduled.");
            Console.ResetColor();
            return;
        }

        // Group by week
        var grouped = events
            .GroupBy(e => {
                var cal = System.Globalization.CultureInfo.InvariantCulture.Calendar;
                var week = cal.GetWeekOfYear(e.Start.DateTime, System.Globalization.CalendarWeekRule.FirstDay, DayOfWeek.Monday);
                return new { e.Start.Year, Week = week };
            })
            .OrderBy(g => g.First().Start);

        foreach (var weekGroup in grouped)
        {
            var weekStart = weekGroup.First().Start;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine($"  Week of {weekStart:MMM dd, yyyy}");
            Console.ResetColor();

            foreach (var evt in weekGroup.OrderBy(e => e.Start))
            {
                var icon = evt.Category switch
                {
                    "Audit" => "🔍",
                    "SLA" => "⚠️",
                    "SLA Reminder" => "🔔",
                    "Review" => "📊",
                    _ => "📌"
                };

                var catColor = evt.Category switch
                {
                    "SLA" => ConsoleColor.Red,
                    "SLA Reminder" => ConsoleColor.Yellow,
                    "Audit" => ConsoleColor.Cyan,
                    "Review" => ConsoleColor.Green,
                    _ => ConsoleColor.White
                };

                Console.Write($"    {evt.Start:ddd MMM dd HH:mm}  ");
                Console.ForegroundColor = catColor;
                Console.Write($"{icon} {evt.Title}");
                Console.ResetColor();

                if (evt.Priority == "High")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(" [HIGH]");
                    Console.ResetColor();
                }

                Console.WriteLine();

                // Show duration
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"                        {evt.Duration.TotalMinutes}min · {evt.Category}");
                Console.ResetColor();
            }
        }

        // Legend
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ─────────────────────────────────────────────");
        Console.ResetColor();
        Console.WriteLine("  Legend: 🔍 Audit  ⚠️ SLA Deadline  🔔 SLA Reminder  📊 Review");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Export as .ics: winsentinel --calendar --calendar-format ics");
        Console.WriteLine("  JSON output:    winsentinel --calendar --json");
        Console.ResetColor();
        Console.WriteLine();
    }
}
