namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintExfiltration(DataExfiltrationReport report, CliOptions options)
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
        Console.WriteLine("  ║   📤  DATA EXFILTRATION DETECTOR — Leak Analysis        ║");
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
        Console.Write("  |  Exfiltrations Detected: ");
        Console.ForegroundColor = report.ExfiltrationsDetected > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.ExfiltrationsDetected}");
        Console.ForegroundColor = original;
        Console.Write("  |  Days Analyzed: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{report.DaysAnalyzed}");
        Console.WriteLine();

        // Severity Breakdown
        Console.WriteLine("  Severity Breakdown:");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"    High/Critical: {report.HighSeverityCount}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"  Medium: {report.MediumSeverityCount}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  Low: {report.LowSeverityCount}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Top Exfiltration Events
        if (report.Events.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Exfiltration Events ──────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var top = report.Events.OrderByDescending(e => e.Confidence).Take(options.ExfilTop);
            foreach (var ev in top)
            {
                var sevColor = ev.Severity switch
                {
                    "Critical" => ConsoleColor.DarkRed,
                    "High" => ConsoleColor.Red,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.Write("    ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{ev.Severity,-8}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {ev.Technique}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" ({ev.TechniqueId})");
                Console.ForegroundColor = original;
                Console.Write($"  Conf: ");
                Console.ForegroundColor = ev.Confidence >= 0.8 ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"{ev.Confidence:P0}");
                Console.ForegroundColor = original;
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"           {ev.Description}");
                if (ev.DestinationAddress != "Unknown")
                    Console.WriteLine($"           → {ev.DestinationAddress}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Channel Breakdown
        if (report.Channels.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Exfiltration Channels ────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var ch in report.Channels)
            {
                Console.Write("    ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{ch.ChannelType,-35}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" [{ch.TechniqueId}]");
                Console.ForegroundColor = original;
                Console.Write($"  Events: {ch.EventCount}");
                if (ch.TotalVolumeEstimate > 0)
                    Console.Write($"  Volume: {FormatBytes(ch.TotalVolumeEstimate)}");
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── Statistics ───────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine($"    Channels Detected:      {report.Stats.TotalChannelsDetected}");
        Console.WriteLine($"    Unique Destinations:    {report.Stats.UniqueDestinations}");
        Console.WriteLine($"    Off-Hours Activity:     {report.Stats.OffHoursExfiltrations}");
        Console.WriteLine($"    High Volume Transfers:  {report.Stats.HighVolumeTransfers}");
        Console.WriteLine($"    Encrypted Channels:     {report.Stats.EncryptedChannelCount}");
        Console.WriteLine($"    Unusual Protocols:      {report.Stats.UnusualProtocolCount}");
        Console.WriteLine();

        // Graph (ASCII)
        if (report.Graph.Nodes.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Exfiltration Graph ───────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var processes = report.Graph.Nodes.Where(n => n.Type == "process").Take(5);
            foreach (var proc in processes)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"    [{proc.Label}]");
                Console.ForegroundColor = original;

                var edges = report.Graph.Edges.Where(e => e.Source == proc.Id).Take(3);
                foreach (var edge in edges)
                {
                    var target = report.Graph.Nodes.FirstOrDefault(n => n.Id == edge.Target);
                    if (target != null)
                    {
                        Console.Write(" ──► ");
                        Console.ForegroundColor = target.Type == "channel" ? ConsoleColor.Yellow : ConsoleColor.Red;
                        Console.Write($"[{target.Label}]");
                        Console.ForegroundColor = original;
                    }
                }
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Recommendations ─────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in report.Recommendations.OrderBy(r => r.Priority))
            {
                Console.Write($"    {rec.Priority}. ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"[{rec.Category}] {rec.Title}");
                Console.ForegroundColor = original;
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"       {rec.Description}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        Console.ForegroundColor = original;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1_099_511_627_776) return $"{bytes / 1_099_511_627_776.0:F1} TB";
        if (bytes >= 1_073_741_824) return $"{bytes / 1_073_741_824.0:F1} GB";
        if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:F1} MB";
        if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }
}
