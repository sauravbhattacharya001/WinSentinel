namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintCollection(CollectionReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║   📋  COLLECTION DETECTOR — Data Harvesting Analysis    ║");
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
        Console.Write("  |  Collection Activities: ");
        Console.ForegroundColor = report.CollectionActivitiesDetected > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.CollectionActivitiesDetected}");
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

        // Top Collection Events
        if (report.Events.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Collection Events ────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var topCount = options.CollectionTop > 0 ? options.CollectionTop : 20;
            var events = report.Events.AsEnumerable();

            if (!string.IsNullOrEmpty(options.CollectionSeverityFilter))
            {
                events = events.Where(e =>
                    e.Severity.Equals(options.CollectionSeverityFilter, StringComparison.OrdinalIgnoreCase));
            }

            var top = events.OrderByDescending(e => e.Confidence).Take(topCount);
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
                if (!string.IsNullOrEmpty(ev.TargetData))
                    Console.WriteLine($"           → Target: {ev.TargetData}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Technique Breakdown
        if (report.Techniques.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Techniques Detected ──────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var tech in report.Techniques)
            {
                Console.Write("    ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{tech.TechniqueName,-30}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" [{tech.TechniqueId}]");
                Console.ForegroundColor = original;
                Console.WriteLine($"  Events: {tech.EventCount}  Severity: {tech.Severity}");
            }
            Console.WriteLine();
        }

        // Campaigns
        if (report.Campaigns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Collection Campaigns ─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var camp in report.Campaigns)
            {
                Console.Write("    ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"⚠ {camp.CampaignId}");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  Source: {camp.SourceProcess}");
                Console.ForegroundColor = original;
                Console.WriteLine($"  Techniques: {camp.TechniquesUsed.Count}  Events: {camp.EventCount}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"      Techniques: {string.Join(", ", camp.TechniquesUsed)}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── Statistics ───────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine($"    Techniques Detected:     {report.Stats.TotalTechniquesDetected}");
        Console.WriteLine($"    Unique Processes:        {report.Stats.UniqueProcesses}");
        Console.WriteLine($"    Off-Hours Activity:      {report.Stats.OffHoursActivities}");
        Console.WriteLine($"    High Volume Collections: {report.Stats.HighVolumeCollections}");
        Console.WriteLine($"    Automated Collection:    {report.Stats.AutomatedCollectionCount}");
        Console.WriteLine($"    Sensitive Data Targets:  {report.Stats.SensitiveDataTargets}");
        Console.WriteLine();

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
}
