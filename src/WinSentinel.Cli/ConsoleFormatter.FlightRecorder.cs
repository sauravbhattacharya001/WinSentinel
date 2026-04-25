namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintFlightRecorder(FlightRecorderResult result, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  +====================================================+");
        Console.WriteLine("  |    SECURITY FLIGHT RECORDER                        |");
        Console.WriteLine("  +====================================================+");
        Console.ResetColor();
        Console.WriteLine();

        // Summary
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Period: {result.DaysAnalyzed} days | Capacity: {result.Capacity} | Recorded: {result.TotalEventsRecorded} events | Volatility: {result.OverallVolatility}/day");
        if (result.OldestEvent.HasValue && result.NewestEvent.HasValue)
            Console.WriteLine($"  Range: {result.OldestEvent:yyyy-MM-dd HH:mm} -> {result.NewestEvent:yyyy-MM-dd HH:mm}");
        Console.ResetColor();
        Console.WriteLine();

        // Event type summary box
        if (result.EventTypeCounts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  +-- Event Summary -------------------------------------------+");
            Console.ResetColor();
            foreach (var (type, count) in result.EventTypeCounts.OrderByDescending(x => x.Value))
            {
                var icon = type switch
                {
                    "ScoreDrop" => "[-]",
                    "ScoreGain" => "[+]",
                    "NewCritical" => "[!]",
                    "FindingResolved" => "[v]",
                    "ModuleRegression" => "[v]",
                    "CriticalSpike" => "[!]",
                    "Milestone" => "[*]",
                    _ => "[ ]"
                };
                Console.WriteLine($"  |  {icon} {type,-24} {count,4} events                   |");
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  +-----------------------------------------------------------+");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Severity breakdown
        if (result.SeverityCounts.Count > 0)
        {
            Console.Write("  Severity: ");
            foreach (var (sev, count) in result.SeverityCounts.OrderByDescending(x => x.Value))
            {
                Console.ForegroundColor = sev switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };
                Console.Write($"{sev}: {count}  ");
            }
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine();
        }

        // Event timeline
        if (result.Events.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  =================== EVENT TIMELINE ===================");
            Console.ResetColor();
            Console.WriteLine();

            foreach (var evt in result.Events)
            {
                Console.ForegroundColor = evt.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                var icon = evt.EventType switch
                {
                    "ScoreDrop" => "v",
                    "ScoreGain" => "^",
                    "NewCritical" => "!",
                    "FindingResolved" => "*",
                    "ModuleRegression" => "v",
                    "CriticalSpike" => "!",
                    "Milestone" => "*",
                    _ => "-"
                };

                var modStr = string.IsNullOrEmpty(evt.Module) ? "" : $" [{evt.Module}]";
                Console.WriteLine($"  {evt.Timestamp:yyyy-MM-dd HH:mm}  {icon} [{evt.Severity[0]}] {evt.Description}{modStr}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  No events recorded in this period.");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Proactive insights
        if (result.ProactiveInsights.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  -- Proactive Insights --------------------------------------");
            Console.ResetColor();
            foreach (var insight in result.ProactiveInsights)
            {
                Console.WriteLine($"    > {insight}");
            }
            Console.WriteLine();
        }
    }
}
