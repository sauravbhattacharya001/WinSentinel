namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintCanary(SecurityCanaryResult result, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  +====================================================+");
        Console.WriteLine("  |    🐤 SECURITY CANARY NETWORK                      |");
        Console.WriteLine("  +====================================================+");
        Console.ResetColor();
        Console.WriteLine();

        // Network health score gauge
        var scoreColor = result.NetworkHealthScore >= 70 ? ConsoleColor.Green
            : result.NetworkHealthScore >= 40 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.Write("  Network Health: ");
        Console.ForegroundColor = scoreColor;
        int filled = result.NetworkHealthScore / 5;
        Console.Write($"[{new string('#', filled)}{new string('.', 20 - filled)}] {result.NetworkHealthScore}/100");
        Console.ResetColor();
        Console.WriteLine();

        // Threat level
        var threatColor = result.ThreatLevel.StartsWith("CRITICAL") ? ConsoleColor.Red
            : result.ThreatLevel.StartsWith("HIGH") ? ConsoleColor.Red
            : result.ThreatLevel.StartsWith("ELEVATED") ? ConsoleColor.Yellow
            : result.ThreatLevel.StartsWith("MODERATE") ? ConsoleColor.Yellow
            : ConsoleColor.Green;
        Console.Write("  Threat Level:   ");
        Console.ForegroundColor = threatColor;
        Console.Write(result.ThreatLevel);
        Console.ResetColor();
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Scanned: {result.ScanTimestamp:yyyy-MM-dd HH:mm} UTC | Total: {result.TotalCanaries} | Healthy: {result.HealthyCount} | Tripped: {result.TrippedCount} | Expired: {result.ExpiredCount}");
        Console.ResetColor();
        Console.WriteLine();

        // Category breakdown
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  +-- Canary Coverage ----------------------------------------+");
        Console.ResetColor();
        foreach (var (cat, count) in result.CategoryBreakdown)
        {
            var bar = new string('=', Math.Min(count * 4, 30));
            Console.WriteLine($"  |  {cat,-24} {count,3}  {bar}");
        }
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  +----------------------------------------------------------+");
        Console.ResetColor();
        Console.WriteLine();

        // Deployments table (skip if trips-only)
        if (!options.CanaryTripsOnly)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Canary Deployments:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"ID",-10} {"Name",-28} {"Type",-12} {"Status",-10} {"Location"}");
            Console.WriteLine($"  {new string('-', 10)} {new string('-', 28)} {new string('-', 12)} {new string('-', 10)} {new string('-', 30)}");
            Console.ResetColor();

            foreach (var d in result.Deployments)
            {
                Console.Write($"  {d.Id,-10} {d.Name,-28} {d.Type,-12} ");
                Console.ForegroundColor = d.Status switch
                {
                    "Healthy" => ConsoleColor.Green,
                    "Tripped" => ConsoleColor.Red,
                    "Expired" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"{d.Status,-10} ");
                Console.ResetColor();

                // Truncate long locations
                string loc = d.Location.Length > 35 ? d.Location[..32] + "..." : d.Location;
                Console.WriteLine(loc);
            }
            Console.WriteLine();
        }

        // Trip alerts
        if (result.TripAlerts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ⚠ CANARY TRIP ALERTS:");
            Console.ResetColor();
            Console.WriteLine();

            foreach (var alert in result.TripAlerts)
            {
                var sevColor = alert.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write("  [");
                Console.ForegroundColor = sevColor;
                Console.Write(alert.Severity.ToUpperInvariant());
                Console.ResetColor();
                Console.Write($"] {alert.CanaryId} — ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(alert.CanaryName);
                Console.ResetColor();
                Console.WriteLine($" ({alert.TripType})");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    Process: {alert.ProcessName} (PID {alert.ProcessId}) | User: {alert.UserAccount}");
                Console.WriteLine($"    Time:    {alert.TrippedAt:yyyy-MM-dd HH:mm} UTC");
                Console.ResetColor();
                Console.Write("    MITRE:   ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(alert.MitreAttackTechnique);
                Console.ResetColor();
                Console.Write("    ");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine(alert.Assessment);
                Console.ResetColor();
                Console.WriteLine();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No canary trips detected — all tripwires intact");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Recommendations
        if (result.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  +-- Recommendations ---------------------------------------+");
            Console.ResetColor();
            int idx = 1;
            foreach (var rec in result.Recommendations)
            {
                var recColor = rec.StartsWith("URGENT") ? ConsoleColor.Red : ConsoleColor.Gray;
                Console.ForegroundColor = recColor;
                Console.WriteLine($"  {idx}. {rec}");
                Console.ResetColor();
                idx++;
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  +----------------------------------------------------------+");
            Console.ResetColor();
        }

        Console.WriteLine();
    }
}
