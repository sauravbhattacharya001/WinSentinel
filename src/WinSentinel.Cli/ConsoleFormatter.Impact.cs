namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintImpactReport(ImpactReport report, string format = "text")
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
        Console.WriteLine("  ║   💥  IMPACT DETECTOR — MITRE ATT&CK TA0040                 ║");
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
        Console.WriteLine($"  Impact Detections:    {report.ImpactDetectionsCount}");
        Console.Write("  High/Critical:        ");
        Console.ForegroundColor = report.HighSeverityImpact > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.WriteLine(report.HighSeverityImpact);
        Console.ForegroundColor = original;
        Console.Write("  Medium:               ");
        Console.ForegroundColor = report.MediumSeverityImpact > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.WriteLine(report.MediumSeverityImpact);
        Console.ForegroundColor = original;
        Console.WriteLine($"  Low:                  {report.LowSeverityImpact}");
        Console.WriteLine();

        // Detections
        if (report.Detections.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detections ────────────────────────────────────────────────");
            Console.ForegroundColor = original;

            foreach (var evt in report.Detections.OrderByDescending(e => e.Severity).Take(20))
            {
                var sevColor = evt.Severity switch
                {
                    ImpactSeverity.Critical => ConsoleColor.DarkRed,
                    ImpactSeverity.High => ConsoleColor.Red,
                    ImpactSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.Write("  ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{evt.Severity,-8}]");
                Console.ForegroundColor = original;
                Console.Write($" {evt.MitreTechnique,-10} {evt.Technique}");
                if (evt.KnownTool != null)
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write($" ({evt.KnownTool})");
                    Console.ForegroundColor = original;
                }
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"             Evidence: {evt.Evidence}");
                Console.WriteLine($"             Confidence: {evt.Confidence:P0}  Destructive: {(evt.IsDestructive ? "YES" : "No")}");
                Console.ForegroundColor = original;

                foreach (var indicator in evt.Indicators.Take(3))
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine($"             ⚠ {indicator}");
                    Console.ForegroundColor = original;
                }
                Console.WriteLine();
            }
        }

        // Campaigns
        if (report.Campaigns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Campaigns ─────────────────────────────────────────────────");
            Console.ForegroundColor = original;

            for (var i = 0; i < report.Campaigns.Count; i++)
            {
                var campaign = report.Campaigns[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Campaign #{i + 1}:");
                Console.ForegroundColor = original;
                Console.WriteLine($"    Primary Type:    {campaign.PrimaryType}");
                Console.WriteLine($"    Techniques:      {campaign.TechniqueCount}");
                Console.WriteLine($"    Targets:         {campaign.TargetSummary}");
                Console.WriteLine($"    Confidence:      {campaign.CompoundConfidence:P1}");
                Console.WriteLine($"    Duration:        {campaign.Duration}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"    Verdict:         {campaign.Verdict}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Techniques Used:      {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Most Common:          {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:       {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Destructive Events:   {report.Stats.DestructiveEvents}");
        Console.WriteLine($"  Non-Destructive:      {report.Stats.NonDestructiveEvents}");
        Console.WriteLine($"  Attack Velocity:      {report.Stats.AttackVelocity} events/day");
        Console.WriteLine($"  Tools Detected:       {report.Stats.ToolsDetected}");
        Console.WriteLine();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations ───────────────────────────────────────────");
            Console.ForegroundColor = original;

            for (var i = 0; i < report.Recommendations.Count; i++)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"  {i + 1}. ");
                Console.ForegroundColor = original;
                Console.WriteLine(report.Recommendations[i]);
            }
            Console.WriteLine();
        }

        Console.ForegroundColor = original;
    }
}
