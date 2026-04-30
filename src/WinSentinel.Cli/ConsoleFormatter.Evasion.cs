namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintEvasionReport(DefenseEvasionReport report, string format = "text")
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
        Console.WriteLine("  ║   🛡️  DEFENSE EVASION DETECTOR — MITRE ATT&CK TA0005        ║");
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
        Console.WriteLine($"  Days Analyzed:       {report.DaysAnalyzed}");
        Console.WriteLine($"  Events Processed:    {report.EventsProcessed}");
        Console.WriteLine($"  Evasions Detected:   {report.EvasionsDetected}");
        Console.Write("  Severity:            ");
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.Write($"{report.CriticalEvasions} critical");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($" | {report.HighSeverityEvasions} high");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($" | {report.MediumSeverityEvasions} medium");
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($" | {report.LowSeverityEvasions} low");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Evasions Table
        if (report.Evasions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Evasion Techniques ───────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var top = report.Evasions.OrderByDescending(e => e.Severity).ThenByDescending(e => e.Confidence).Take(20);
            foreach (var evasion in top)
            {
                var sevIcon = evasion.Severity switch
                {
                    EvasionSeverity.Critical => "🔴",
                    EvasionSeverity.High => "🟠",
                    EvasionSeverity.Medium => "🟡",
                    _ => "🟢"
                };
                Console.WriteLine($"  {sevIcon} [{evasion.MitreTechnique}] {evasion.Technique}");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine($"     Target: {evasion.TargetDefense} | Confidence: {evasion.Confidence:P0} | {(evasion.IsAutomated ? "⚡ Automated" : "Manual")}");
                Console.WriteLine($"     Evidence: {evasion.Evidence}");
                if (evasion.Indicators.Count > 0)
                    Console.WriteLine($"     Indicators: {string.Join("; ", evasion.Indicators)}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Campaigns
        if (report.Campaigns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Evasion Campaigns ─────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var campaign in report.Campaigns)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ⚠️  {campaign.CampaignType}");
                Console.ForegroundColor = original;
                Console.WriteLine($"     Techniques: {campaign.TechniqueCount} | Duration: {campaign.Duration.TotalHours:F1}h | Confidence: {campaign.CompoundConfidence:P0}");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine($"     Verdict: {campaign.Verdict}");
                Console.ForegroundColor = original;

                foreach (var step in campaign.Steps)
                {
                    Console.WriteLine($"       → [{step.MitreTechnique}] {step.Technique}");
                }
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:     {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Defenses Targeted:     {report.Stats.UniqueDefensesTargeted}");
        Console.WriteLine($"  Most Targeted:         {report.Stats.MostTargetedDefense}");
        Console.WriteLine($"  Most Common Technique: {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:        {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Automated/Manual:      {report.Stats.AutomatedAttempts}/{report.Stats.ManualAttempts}");
        Console.WriteLine($"  Evasion Velocity:      {report.Stats.EvasionVelocity:F2}/day");
        Console.WriteLine();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations ───────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (int i = 0; i < report.Recommendations.Count; i++)
            {
                Console.WriteLine($"  {i + 1}. {report.Recommendations[i]}");
            }
            Console.WriteLine();
        }
    }
}
