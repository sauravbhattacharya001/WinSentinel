namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintShadowIt(ShadowItResult result, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  +====================================================+");
        Console.WriteLine("  |    SHADOW IT DETECTOR                              |");
        Console.WriteLine("  +====================================================+");
        Console.ResetColor();
        Console.WriteLine();

        // Risk score gauge
        var scoreColor = result.OverallRiskScore >= 60 ? ConsoleColor.Red
            : result.OverallRiskScore >= 30 ? ConsoleColor.Yellow
            : ConsoleColor.Green;
        Console.Write("  Risk Score: ");
        Console.ForegroundColor = scoreColor;
        int filled = result.OverallRiskScore / 5;
        Console.Write($"[{new string('#', filled)}{new string('.', 20 - filled)}] {result.OverallRiskScore}/100");
        Console.ResetColor();
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Scanned: {result.ScanTimestamp:yyyy-MM-dd HH:mm} UTC | Findings: {result.TotalFindings} | High: {result.HighRiskCount} | Medium: {result.MediumRiskCount} | Low: {result.LowRiskCount}");
        Console.ResetColor();
        Console.WriteLine();

        // Category breakdown
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  +-- Category Breakdown ------------------------------------+");
        Console.ResetColor();
        foreach (var (cat, count) in result.CategoryBreakdown)
        {
            var bar = new string('=', Math.Min(count * 4, 30));
            Console.WriteLine($"  |  {cat,-24} {count,3}  {bar}");
        }
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  +---------------------------------------------------------+");
        Console.ResetColor();
        Console.WriteLine();

        // Unknown Services
        if (result.UnknownServices.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  >> Unknown Services");
            Console.ResetColor();
            foreach (var svc in result.UnknownServices)
            {
                Console.ForegroundColor = RiskColor(svc.RiskLevel);
                Console.Write($"  [{svc.RiskLevel,6}] ");
                Console.ResetColor();
                Console.WriteLine($"{svc.Name} ({svc.DisplayName}) - {svc.Status}, {svc.StartType}");
            }
            Console.WriteLine();
        }

        // Suspicious Ports
        if (result.SuspiciousListeningPorts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  >> Suspicious Listening Ports");
            Console.ResetColor();
            foreach (var p in result.SuspiciousListeningPorts)
            {
                Console.ForegroundColor = RiskColor(p.RiskLevel);
                Console.Write($"  [{p.RiskLevel,6}] ");
                Console.ResetColor();
                Console.WriteLine($":{p.Port}/{p.Protocol} <- {p.ProcessName} (PID {p.Pid})");
            }
            Console.WriteLine();
        }

        // Startup Programs
        if (result.UnauthorizedStartupPrograms.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  >> Unauthorized Startup Programs");
            Console.ResetColor();
            foreach (var s in result.UnauthorizedStartupPrograms)
            {
                Console.ForegroundColor = RiskColor(s.RiskLevel);
                Console.Write($"  [{s.RiskLevel,6}] ");
                Console.ResetColor();
                Console.WriteLine($"{s.Name}: {s.Command}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"           Location: {s.Location}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // Shadow Tasks
        if (result.ShadowScheduledTasks.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  >> Shadow Scheduled Tasks");
            Console.ResetColor();
            foreach (var t in result.ShadowScheduledTasks)
            {
                Console.ForegroundColor = RiskColor(t.RiskLevel);
                Console.Write($"  [{t.RiskLevel,6}] ");
                Console.ResetColor();
                Console.Write($"{t.Name}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" (by {t.Author})");
                if (t.NextRunTime.HasValue)
                    Console.Write($" next: {t.NextRunTime:yyyy-MM-dd HH:mm}");
                Console.ResetColor();
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Recommendations
        if (result.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  +-- Recommendations ---------------------------------------+");
            Console.ResetColor();
            foreach (var rec in result.Recommendations)
            {
                Console.WriteLine($"  |  -> {rec}");
            }
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  +---------------------------------------------------------+");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private static ConsoleColor RiskColor(string riskLevel) => riskLevel switch
    {
        "High" => ConsoleColor.Red,
        "Medium" => ConsoleColor.Yellow,
        "Low" => ConsoleColor.Green,
        _ => ConsoleColor.Gray
    };
}
