using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintNerveCenter(SecurityNerveCenter.NerveCenterReport report, CliOptions options)
    {
        Console.WriteLine();

        // ── Header ───────────────────────────────────────────────────
        var headerColor = report.ThreatLevel switch
        {
            1 => ConsoleColor.Red,
            2 => ConsoleColor.Yellow,
            3 => ConsoleColor.Cyan,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = headerColor;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║              S E C U R I T Y   N E R V E   C E N T E R     ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.ResetColor();
        Console.WriteLine();

        // ── Threat Level ─────────────────────────────────────────────
        PrintDefconIndicator(report.ThreatLevel, report.ThreatLabel);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {report.ThreatRationale}");
        Console.ResetColor();
        Console.WriteLine();

        // ── Active Incidents ─────────────────────────────────────────
        if (report.Incidents.Count > 0)
        {
            PrintSectionHeader("ACTIVE INCIDENTS");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Module",-25} {"Severity",-10} {"Count",5} {"Age",6}  Top Finding");
            Console.WriteLine($"  {"─────────────────────────",-25} {"──────────",-10} {"─────",5} {"──────",6}  ───────────────────────────────");
            Console.ResetColor();

            foreach (var inc in report.Incidents)
            {
                Console.ForegroundColor = inc.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"  {Truncate(inc.Module, 25),-25} {inc.Severity,-10} {inc.Count,5} {inc.OldestDays + "d",6}  ");
                Console.ResetColor();
                Console.WriteLine(Truncate(inc.TopFinding, 40));
            }
            Console.WriteLine();
        }

        // ── Module Vitals ────────────────────────────────────────────
        if (report.Vitals.Count > 0)
        {
            PrintSectionHeader("MODULE VITALS");
            foreach (var vital in report.Vitals)
            {
                var statusColor = vital.Status switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Degraded" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };
                var dot = vital.Status switch
                {
                    "Critical" => "●",
                    "Degraded" => "◐",
                    _ => "○"
                };

                Console.ForegroundColor = statusColor;
                Console.Write($"  {dot} ");
                Console.ResetColor();
                Console.Write($"{Truncate(vital.Module, 28),-28} ");

                Console.ForegroundColor = statusColor;
                Console.Write($"{vital.Score,5:F0}/100 ");
                Console.ResetColor();

                Console.ForegroundColor = vital.Trend == "↓" ? ConsoleColor.Red
                    : vital.Trend == "↑" ? ConsoleColor.Green
                    : ConsoleColor.DarkGray;
                Console.Write(vital.Trend);
                Console.ResetColor();

                if (vital.PrevScore.HasValue)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($" (prev: {vital.PrevScore.Value:F0})");
                    Console.ResetColor();
                }
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // ── Signal Feed ──────────────────────────────────────────────
        if (report.Signals.Count > 0)
        {
            PrintSectionHeader("SIGNAL FEED");
            foreach (var sig in report.Signals)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {sig.Timestamp:MM-dd HH:mm} ");
                Console.ResetColor();
                Console.WriteLine($"{sig.Icon} {sig.Message}");
            }
            Console.WriteLine();
        }

        // ── Proactive Actions ────────────────────────────────────────
        if (report.Actions.Count > 0)
        {
            PrintSectionHeader("PROACTIVE ACTIONS");
            foreach (var action in report.Actions)
            {
                var tagColor = action.Tag switch
                {
                    "URGENT" => ConsoleColor.Red,
                    "HIGH" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Cyan
                };
                Console.ForegroundColor = tagColor;
                Console.Write($"  [{action.Tag}] ");
                Console.ResetColor();
                Console.WriteLine(action.Action);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"         {action.Rationale}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // ── Autonomous Alerts ────────────────────────────────────────
        if (report.Alerts.Count > 0)
        {
            PrintSectionHeader("AUTONOMOUS ALERTS");
            foreach (var alert in report.Alerts)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ┌─ ⚠ {alert.Title} [{alert.Type}]");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  │  {alert.Description}");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"  │  → {alert.Recommendation}");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  └─");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        if (report.Incidents.Count == 0 && report.Alerts.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ All quiet — no active incidents or autonomous alerts.");
            Console.ResetColor();
            Console.WriteLine();
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static void PrintDefconIndicator(int level, string label)
    {
        var color = level switch
        {
            1 => ConsoleColor.Red,
            2 => ConsoleColor.Yellow,
            3 => ConsoleColor.Cyan,
            4 => ConsoleColor.Green,
            _ => ConsoleColor.Green
        };

        Console.ForegroundColor = color;
        Console.WriteLine($"  ╔═══════════════════╗");
        Console.WriteLine($"  ║   DEFCON   {level}       ║");
        Console.WriteLine($"  ╚═══════════════════╝");
        Console.ResetColor();
        Console.ForegroundColor = color;
        Console.Write($"  {label}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintSectionHeader(string title)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  ── {title} ──────────────────────────────────────────");
        Console.ResetColor();
    }
}
