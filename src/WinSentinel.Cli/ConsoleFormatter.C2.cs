namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintC2Report(CommandControlReport report, string format = "text")
    {
        if (format == "json")
        {
            Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            return;
        }

        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║   📡  C2 DETECTOR — MITRE ATT&CK TA0011                     ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
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
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.ThreatScore}/100 ({report.ThreatLevel})");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Summary
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Summary ───────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Days Analyzed:        {report.DaysAnalyzed}");
        Console.WriteLine($"  Events Processed:     {report.EventsProcessed}");
        Console.WriteLine($"  C2 Channels Detected: {report.C2DetectionsCount}");
        Console.WriteLine($"    Critical/High:      {report.HighSeverityC2}");
        Console.WriteLine($"    Medium:             {report.MediumSeverityC2}");
        Console.WriteLine($"    Low:                {report.LowSeverityC2}");
        Console.WriteLine();

        // Detections Table
        if (report.Detections.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── C2 Channels ──────────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var evt in report.Detections)
            {
                var sevColor = evt.Severity switch
                {
                    C2Severity.Critical => ConsoleColor.DarkRed,
                    C2Severity.High => ConsoleColor.Red,
                    C2Severity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.ForegroundColor = sevColor;
                Console.Write($"  [{evt.Severity}]");
                Console.ForegroundColor = original;
                Console.Write($" {evt.Technique}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" ({evt.MitreTechnique})");
                Console.ForegroundColor = original;
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"         Protocol: {evt.Protocol ?? "n/a"}");
                if (evt.KnownFramework != null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"  Framework: {evt.KnownFramework}");
                }
                Console.ForegroundColor = original;
                Console.WriteLine($"  Confidence: {evt.Confidence:P0}");

                if (evt.IsEncrypted)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("         🔒 Encrypted channel");
                    Console.ForegroundColor = original;
                }

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"         Evidence: {evt.Evidence}");
                Console.ForegroundColor = original;

                foreach (var indicator in evt.Indicators)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine($"         ⚠ {indicator}");
                    Console.ForegroundColor = original;
                }

                Console.WriteLine();
            }
        }

        // Campaigns
        if (report.Campaigns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── C2 Campaigns ─────────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            for (var i = 0; i < report.Campaigns.Count; i++)
            {
                var camp = report.Campaigns[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Campaign #{i + 1}:");
                Console.ForegroundColor = original;
                Console.WriteLine($"    Primary Protocol:   {camp.PrimaryProtocol}");
                Console.WriteLine($"    Channel Types:      {camp.ChannelCount}");
                Console.WriteLine($"    Target:             {camp.TargetSummary}");
                Console.WriteLine($"    Compound Conf.:     {camp.CompoundConfidence:P1}");
                Console.WriteLine($"    Duration:           {camp.Duration.TotalHours:F1}h");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"    Verdict:            {camp.Verdict}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Techniques Used:      {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Unique Protocols:     {report.Stats.UniqueProtocols}");
        Console.WriteLine($"  Most Common:          {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:       {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Encrypted Channels:   {report.Stats.EncryptedChannels}");
        Console.WriteLine($"  Clear-Text Channels:  {report.Stats.ClearTextChannels}");
        Console.WriteLine($"  C2 Velocity:          {report.Stats.C2Velocity:F2}/day");
        Console.WriteLine($"  Frameworks Detected:  {report.Stats.FrameworksDetected}");
        Console.WriteLine();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations ──────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            for (var i = 0; i < report.Recommendations.Count; i++)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"  {i + 1}. ");
                Console.ForegroundColor = original;
                Console.WriteLine(report.Recommendations[i]);
            }
            Console.WriteLine();
        }

        Console.ForegroundColor = original;
    }
}
