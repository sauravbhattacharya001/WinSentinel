namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintExecutionReport(ExecutionReport report, string format = "text")
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
        Console.WriteLine("  ║   ⚡  EXECUTION DETECTOR — MITRE ATT&CK TA0002               ║");
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
        Console.WriteLine($"  Executions Detected:  {report.ExecutionsDetected}");
        Console.WriteLine($"    Critical/High:      {report.HighSeverityExecutions}");
        Console.WriteLine($"    Medium:             {report.MediumSeverityExecutions}");
        Console.WriteLine($"    Low:                {report.LowSeverityExecutions}");
        Console.WriteLine();

        // Executions Table
        if (report.Executions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Execution Events ─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  {"#",-3} {"Technique",-38} {"MITRE",-12} {"Severity",-10} {"Conf",-6} {"Method",-14} {"Evidence"}");
            Console.WriteLine($"  {"─",-3} {"─",-38} {"─",-12} {"─",-10} {"─",-6} {"─",-14} {"─"}");

            for (var i = 0; i < report.Executions.Count; i++)
            {
                var evt = report.Executions[i];
                var sevColor = evt.Severity switch
                {
                    ExecutionSeverity.Critical => ConsoleColor.DarkRed,
                    ExecutionSeverity.High => ConsoleColor.Red,
                    ExecutionSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,-3} ");
                Console.Write($"{TruncateExec(evt.Technique, 38),-38} ");
                Console.Write($"{evt.MitreTechnique,-12} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"{evt.Severity,-10} ");
                Console.ForegroundColor = original;
                Console.Write($"{evt.Confidence:P0,-6} ");
                Console.Write($"{TruncateExec(evt.ExecutionMethod ?? "–", 14),-14} ");
                Console.WriteLine(TruncateExec(evt.Evidence, 35));

                if (evt.SourceTool != null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"      🔧 Tool: {evt.SourceTool}");
                    Console.ForegroundColor = original;
                }

                foreach (var ind in evt.Indicators)
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
            Console.WriteLine("  ── Execution Campaigns ───────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Campaigns.Count; i++)
            {
                var campaign = report.Campaigns[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Campaign #{i + 1}: ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{campaign.PrimaryMethod} → {campaign.TargetSummary} ({campaign.MethodCount} methods)");
                Console.WriteLine($"    Confidence: {campaign.CompoundConfidence:P1} | Duration: {campaign.Duration.TotalMinutes:F0}min");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    Verdict: {campaign.Verdict}");
                Console.ForegroundColor = original;
                foreach (var step in campaign.Steps)
                    Console.WriteLine($"      → [{step.MitreTechnique}] {step.Technique} ({step.ExecutionMethod})");
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:    {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Assets Targeted:      {report.Stats.UniqueAssetsTargeted}");
        Console.WriteLine($"  Execution Methods:    {report.Stats.ExecutionMethodsUsed}");
        Console.WriteLine($"  Most Common:          {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:       {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Automated Executions: {report.Stats.AutomatedExecutions}");
        Console.WriteLine($"  Manual Executions:    {report.Stats.ManualExecutions}");
        Console.WriteLine($"  Execution Velocity:   {report.Stats.ExecutionVelocity:F1}/day");
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

    private static string TruncateExec(string text, int max) =>
        text.Length <= max ? text : text[..(max - 3)] + "...";
}
