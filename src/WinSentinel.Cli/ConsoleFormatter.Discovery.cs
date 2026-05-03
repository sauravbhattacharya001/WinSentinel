namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintDiscoveryReport(DiscoveryReport report, string format = "text")
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
        Console.WriteLine("  ║   🔍  DISCOVERY DETECTOR — MITRE ATT&CK TA0007               ║");
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
        Console.WriteLine($"  Activities Detected:  {report.ActivitiesDetected}");
        Console.WriteLine($"    Critical/High:      {report.HighSeverityActivities}");
        Console.WriteLine($"    Medium:             {report.MediumSeverityActivities}");
        Console.WriteLine($"    Low:                {report.LowSeverityActivities}");
        Console.WriteLine();

        // Activities Table
        if (report.Activities.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Discovery Activities ─────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  {"#",-3} {"Technique",-35} {"MITRE",-12} {"Severity",-10} {"Conf",-6} {"Category",-12} {"Evidence"}");
            Console.WriteLine($"  {"─",-3} {"─",-35} {"─",-12} {"─",-10} {"─",-6} {"─",-12} {"─"}");

            for (var i = 0; i < report.Activities.Count; i++)
            {
                var act = report.Activities[i];
                var sevColor = act.Severity switch
                {
                    DiscoverySeverity.Critical => ConsoleColor.DarkRed,
                    DiscoverySeverity.High => ConsoleColor.Red,
                    DiscoverySeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,-3} ");
                Console.Write($"{TruncateDisc(act.Technique, 35),-35} ");
                Console.Write($"{act.MitreTechnique,-12} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"{act.Severity,-10} ");
                Console.ForegroundColor = original;
                Console.Write($"{act.Confidence:P0,-6} ");
                Console.Write($"{TruncateDisc(act.DiscoveryCategory ?? "–", 12),-12} ");
                Console.WriteLine(TruncateDisc(act.Evidence, 35));

                if (act.SourceTool != null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"      🔧 Tool: {act.SourceTool}");
                    Console.ForegroundColor = original;
                }

                foreach (var ind in act.Indicators)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine($"      ⚠ {ind}");
                    Console.ForegroundColor = original;
                }
            }
            Console.WriteLine();
        }

        // Campaigns
        if (report.Campaigns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Discovery Campaigns ───────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Campaigns.Count; i++)
            {
                var campaign = report.Campaigns[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Campaign #{i + 1}: ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{campaign.PrimaryCategory} → {campaign.TargetSummary} ({campaign.CategoryCount} categories)");
                Console.WriteLine($"    Confidence: {campaign.CompoundConfidence:P1} | Duration: {campaign.Duration.TotalMinutes:F0}min");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    Verdict: {campaign.Verdict}");
                Console.ForegroundColor = original;
                foreach (var step in campaign.Steps)
                    Console.WriteLine($"      → [{step.MitreTechnique}] {step.Technique} ({step.DiscoveryCategory})");
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:    {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Assets Targeted:      {report.Stats.UniqueAssetsTargeted}");
        Console.WriteLine($"  Discovery Categories: {report.Stats.DiscoveryCategoriesUsed}");
        Console.WriteLine($"  Most Common:          {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:       {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Automated Activities: {report.Stats.AutomatedActivities}");
        Console.WriteLine($"  Manual Activities:    {report.Stats.ManualActivities}");
        Console.WriteLine($"  Activity Velocity:    {report.Stats.ActivityVelocity:F1}/day");
        Console.WriteLine();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations ──────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Recommendations.Count; i++)
                Console.WriteLine($"  {i + 1}. {report.Recommendations[i]}");
            Console.WriteLine();
        }
    }

    private static string TruncateDisc(string text, int max) =>
        text.Length <= max ? text : text[..(max - 3)] + "...";
}
