namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintInitialAccessReport(InitialAccessReport report, string format = "text")
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
        Console.WriteLine("  ║   🚪  INITIAL ACCESS DETECTOR — MITRE ATT&CK TA0001          ║");
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
        Console.WriteLine($"  Attempts Detected:    {report.AttemptsDetected}");
        Console.WriteLine($"    Critical/High:      {report.HighSeverityAttempts}");
        Console.WriteLine($"    Medium:             {report.MediumSeverityAttempts}");
        Console.WriteLine($"    Low:                {report.LowSeverityAttempts}");
        Console.WriteLine();

        // Attempts Table
        if (report.Attempts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Initial Access Attempts ──────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  {"#",-3} {"Technique",-30} {"MITRE",-12} {"Severity",-10} {"Conf",-6} {"Vector",-15} {"Evidence"}");
            Console.WriteLine($"  {"─",-3} {"─",-30} {"─",-12} {"─",-10} {"─",-6} {"─",-15} {"─"}");

            for (var i = 0; i < report.Attempts.Count; i++)
            {
                var att = report.Attempts[i];
                var sevColor = att.Severity switch
                {
                    InitialAccessSeverity.Critical => ConsoleColor.DarkRed,
                    InitialAccessSeverity.High => ConsoleColor.Red,
                    InitialAccessSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,-3} ");
                Console.Write($"{TruncateIA(att.Technique, 30),-30} ");
                Console.Write($"{att.MitreTechnique,-12} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"{att.Severity,-10} ");
                Console.ForegroundColor = original;
                Console.Write($"{att.Confidence:P0,-6} ");
                Console.Write($"{TruncateIA(att.AccessVector ?? "–", 15),-15} ");
                Console.WriteLine(TruncateIA(att.Evidence, 35));

                if (att.SourceTool != null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"      🔧 Tool: {att.SourceTool}");
                    Console.ForegroundColor = original;
                }

                foreach (var ind in att.Indicators)
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
            Console.WriteLine("  ── Initial Access Campaigns ──────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Campaigns.Count; i++)
            {
                var campaign = report.Campaigns[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Campaign #{i + 1}: ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{campaign.PrimaryVector} → {campaign.TargetSummary} ({campaign.VectorCount} vectors)");
                Console.WriteLine($"    Confidence: {campaign.CompoundConfidence:P1} | Duration: {campaign.Duration.TotalMinutes:F0}min");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    Verdict: {campaign.Verdict}");
                Console.ForegroundColor = original;
                foreach (var step in campaign.Steps)
                    Console.WriteLine($"      → [{step.MitreTechnique}] {step.Technique} ({step.AccessVector})");
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:    {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Assets Targeted:      {report.Stats.UniqueAssetsTargeted}");
        Console.WriteLine($"  Access Vectors:       {report.Stats.AccessVectorsUsed}");
        Console.WriteLine($"  Most Common:          {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:       {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Automated Attempts:   {report.Stats.AutomatedAttempts}");
        Console.WriteLine($"  Manual Attempts:      {report.Stats.ManualAttempts}");
        Console.WriteLine($"  Attack Velocity:      {report.Stats.AttackVelocity:F1}/day");
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

    private static string TruncateIA(string text, int max) =>
        text.Length <= max ? text : text[..(max - 3)] + "...";
}
