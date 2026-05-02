namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintCredentialAccessReport(CredentialAccessReport report, string format = "text")
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
        Console.WriteLine("  ║   🔑  CREDENTIAL ACCESS DETECTOR — MITRE ATT&CK TA0006      ║");
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
            Console.WriteLine("  ── Detected Credential Access Attempts ───────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  {"#",-3} {"Technique",-30} {"MITRE",-12} {"Severity",-10} {"Conf",-6} {"Cred Type",-25} {"Evidence"}");
            Console.WriteLine($"  {"─",-3} {"─",-30} {"─",-12} {"─",-10} {"─",-6} {"─",-25} {"─"}");

            for (var i = 0; i < report.Attempts.Count; i++)
            {
                var att = report.Attempts[i];
                var sevColor = att.Severity switch
                {
                    CredAccessSeverity.Critical => ConsoleColor.DarkRed,
                    CredAccessSeverity.High => ConsoleColor.Red,
                    CredAccessSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,-3} ");
                Console.Write($"{TruncateCredAccess(att.Technique, 30),-30} ");
                Console.Write($"{att.MitreTechnique,-12} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"{att.Severity,-10} ");
                Console.ForegroundColor = original;
                Console.Write($"{att.Confidence:P0,-6} ");
                Console.Write($"{TruncateCredAccess(att.CredentialType ?? "–", 25),-25} ");
                Console.WriteLine(TruncateCredAccess(att.Evidence, 35));

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

        // Chains
        if (report.Chains.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Credential Harvest Chains ─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Chains.Count; i++)
            {
                var chain = report.Chains[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Chain #{i + 1}: ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{chain.InitialVector} → {chain.FinalAccess} ({chain.StepCount} steps)");
                Console.WriteLine($"    Confidence: {chain.CompoundConfidence:P1} | Duration: {chain.Duration.TotalMinutes:F0}min");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    Verdict: {chain.Verdict}");
                Console.ForegroundColor = original;
                foreach (var step in chain.Steps)
                    Console.WriteLine($"      → [{step.MitreTechnique}] {step.Technique} ({step.CredentialType})");
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:    {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Accounts Targeted:    {report.Stats.UniqueAccountsTargeted}");
        Console.WriteLine($"  Credential Types:     {report.Stats.CredentialTypesTargeted}");
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

    private static string TruncateCredAccess(string text, int max) =>
        text.Length <= max ? text : text[..(max - 3)] + "...";
}
