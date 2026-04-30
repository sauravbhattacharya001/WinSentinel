namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintLateralMovement(LateralMovementReport report, CliOptions options)
    {
        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            return;
        }

        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║   🕸️  LATERAL MOVEMENT DETECTOR — Pivot Analysis        ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Threat Score Gauge
        Console.Write("  Threat Score: ");
        var scoreColor = report.ThreatScore switch
        {
            >= 80 => ConsoleColor.DarkRed,
            >= 60 => ConsoleColor.Red,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = scoreColor;
        var filled = (int)(report.ThreatScore / 5);
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.ThreatScore:F0}/100 ({report.ThreatLevel})");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Summary Stats
        Console.Write("  Events Processed: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.EventsProcessed}");
        Console.ForegroundColor = original;

        Console.Write("  │  Movements: ");
        Console.ForegroundColor = report.MovementsDetected > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.MovementsDetected}");
        Console.ForegroundColor = original;

        Console.Write("  │  Paths: ");
        Console.ForegroundColor = report.Paths.Count > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.Paths.Count}");
        Console.ForegroundColor = original;

        Console.Write("  │  Hosts: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.Graph.NodeCount}");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Severity Breakdown
        if (report.MovementsDetected > 0)
        {
            Console.Write("  Severity: ");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write($"■ Critical/High: {report.HighSeverityMovements}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"  ■ Medium: {report.MediumSeverityMovements}");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write($"  ■ Low: {report.LowSeverityMovements}");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine();
        }

        // Movement Table
        if (report.Movements.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Detected Lateral Movements ──────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var top = report.Movements.OrderByDescending(m => m.Severity).ThenByDescending(m => m.Confidence).Take(options.LateralMovementTop);
            Console.WriteLine("  {0,-18} {1,-18} {2,-14} {3,-12} {4,-8} {5,-6}",
                "Source", "Target", "Technique", "MITRE", "Sev", "Conf");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  " + new string('─', 78));
            Console.ForegroundColor = original;

            foreach (var m in top)
            {
                var sevColor = m.Severity switch
                {
                    LateralMovementSeverity.Critical => ConsoleColor.DarkRed,
                    LateralMovementSeverity.High => ConsoleColor.Red,
                    LateralMovementSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.Write("  {0,-18} {1,-18} {2,-14} {3,-12} ",
                    Truncate(m.SourceHost, 17),
                    Truncate(m.TargetHost, 17),
                    Truncate(m.Technique, 13),
                    m.MitreTechnique);

                Console.ForegroundColor = sevColor;
                Console.Write($"{m.Severity,-8}");
                Console.ForegroundColor = original;
                Console.Write($" {m.Confidence:P0}");
                Console.WriteLine();

                if (m.AccountUsed != null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"    Account: ");
                    Console.ForegroundColor = m.IsServiceAccount ? ConsoleColor.Red : ConsoleColor.Gray;
                    Console.Write(m.AccountUsed);
                    if (m.IsServiceAccount) Console.Write(" [SVC]");
                    Console.ForegroundColor = original;
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
        }

        // Movement Paths
        if (report.Paths.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Multi-Hop Movement Paths ────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var path in report.Paths.Take(10))
            {
                Console.ForegroundColor = path.ReachesCriticalAsset ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write("  ");
                for (var i = 0; i < path.Hops.Count; i++)
                {
                    Console.Write(path.Hops[i]);
                    if (i < path.Hops.Count - 1)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write($" ─[{path.Techniques[i]}]→ ");
                        Console.ForegroundColor = path.ReachesCriticalAsset ? ConsoleColor.Red : ConsoleColor.Yellow;
                    }
                }
                Console.ForegroundColor = original;
                Console.Write($"  (risk: {path.PathRisk:F0}");
                if (path.ReachesCriticalAsset)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(" ⚠ CRITICAL ASSET");
                    Console.ForegroundColor = original;
                }
                Console.Write(")");
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Graph Summary
        if (report.Graph.NodeCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Movement Graph ──────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  Nodes: {report.Graph.NodeCount}  │  Edges: {report.Graph.EdgeCount}  │  Most Connected: {report.Graph.MostConnectedNode ?? "N/A"}  │  Max Path: {report.Graph.MaxPathLength} hops");
            Console.WriteLine();
        }

        // Stats
        if (report.MovementsDetected > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Statistics ──────────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  Unique Sources: {report.Stats.UniqueSourceHosts}  │  Unique Targets: {report.Stats.UniqueTargetHosts}  │  Techniques: {report.Stats.UniqueTechniques}");
            Console.WriteLine($"  Service Acct Moves: {report.Stats.ServiceAccountMovements}  │  Off-Hours: {report.Stats.OffHoursMovements}  │  Accounts: {report.Stats.UniqueAccounts}");
            Console.WriteLine($"  Most Used: {report.Stats.MostUsedTechnique}  │  Most Targeted: {report.Stats.MostTargetedHost}");
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Containment Recommendations ────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in report.Recommendations)
            {
                var prioColor = rec.Priority switch
                {
                    "Critical" => ConsoleColor.DarkRed,
                    "High" => ConsoleColor.Red,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };

                Console.Write("  ");
                Console.ForegroundColor = prioColor;
                Console.Write($"[{rec.Priority}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {rec.Title}");
                Console.ForegroundColor = original;
                Console.WriteLine();
                Console.WriteLine($"    {rec.Description}");
                if (rec.MitreMitigation != null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"    MITRE: {rec.MitreMitigation}");
                    Console.ForegroundColor = original;
                }
                Console.WriteLine();
            }
        }

        Console.ForegroundColor = original;
    }
}
