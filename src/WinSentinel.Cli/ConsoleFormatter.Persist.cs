namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintPersistMechReport(PersistMechReport report, string format = "text")
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
        Console.WriteLine("  ║   🔗 PERSISTENCE MECHANISM SCANNER — MITRE ATT&CK TA0003    ║");
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
        Console.WriteLine($"  Days Analyzed:         {report.DaysAnalyzed}");
        Console.WriteLine($"  Events Processed:      {report.EventsProcessed}");
        Console.WriteLine($"  Mechanisms Detected:   {report.MechanismsDetected}");
        Console.WriteLine($"  Active:                {report.ActiveMechanisms}");
        Console.WriteLine($"  Dormant:               {report.DormantMechanisms}");
        Console.WriteLine($"  Technique Diversity:   {report.Stats.TechniqueDiversity:P0}");
        Console.WriteLine();

        // Severity Breakdown
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Severity Breakdown ────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.Write($"  Critical: {report.CriticalMechanisms}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"   High: {report.HighMechanisms}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"   Medium: {report.MediumMechanisms}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"   Low: {report.LowMechanisms}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Top Mechanisms
        if (report.Entries.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Mechanisms ───────────────────────────────────────");
            Console.ForegroundColor = original;

            var top = report.Entries
                .OrderByDescending(e => e.Severity)
                .ThenByDescending(e => e.Confidence)
                .Take(15);

            foreach (var entry in top)
            {
                var sevColor = entry.Severity switch
                {
                    PersistMechSeverity.Critical => ConsoleColor.DarkRed,
                    PersistMechSeverity.High => ConsoleColor.Red,
                    PersistMechSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                var status = entry.IsActive ? "🟢 ACTIVE" : entry.IsDormant ? "💤 DORMANT" : "⚪ UNKNOWN";

                Console.ForegroundColor = sevColor;
                Console.Write($"  [{entry.Severity,-8}] ");
                Console.ForegroundColor = original;
                Console.Write($"{entry.Technique,-35} ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"({entry.MitreTechnique}) ");
                Console.ForegroundColor = original;
                Console.WriteLine($" {status}  conf:{entry.Confidence:F2}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"           Evidence: {entry.Evidence}");
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // Chains
        if (report.Chains.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Persistence Chains ────────────────────────────────────────");
            Console.ForegroundColor = original;

            for (var i = 0; i < report.Chains.Count; i++)
            {
                var chain = report.Chains[i];
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"  Chain #{i + 1}: {chain.PrimaryTechnique} (depth={chain.Depth}, " +
                    $"defense-in-depth={chain.DefenseInDepthLevel})");
                Console.ForegroundColor = original;
                Console.WriteLine($"    Verdict: {chain.Verdict}");
                Console.Write("    Techniques: ");
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine(string.Join(" → ", chain.Mechanisms.Select(m => m.Technique)));
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Statistics
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:     {report.Stats.UniqueTechniquesUsed}");
        Console.WriteLine($"  Unique Locations:      {report.Stats.UniqueLocations}");
        Console.WriteLine($"  Most Common:           {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:        {report.Stats.AverageConfidence:F3}");
        Console.WriteLine($"  Dormancy Ratio:        {report.Stats.DormancyRatio:P1}");
        Console.WriteLine();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations ──────────────────────────────────────────");
            Console.ForegroundColor = original;

            foreach (var rec in report.Recommendations)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.Write("  → ");
                Console.ForegroundColor = original;
                Console.WriteLine(rec);
            }
            Console.WriteLine();
        }
    }
}
