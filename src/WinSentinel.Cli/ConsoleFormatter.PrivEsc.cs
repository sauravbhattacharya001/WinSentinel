namespace WinSentinel.Cli;

using System.Text.Json;
using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintPrivEscReport(PrivilegeEscalationReport report, string format = "text")
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
        Console.WriteLine("  ║   🛡️  PRIVILEGE ESCALATION DETECTOR — MITRE ATT&CK TA0004   ║");
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
        Console.WriteLine($"  Escalations Found:   {report.EscalationsDetected}");
        Console.WriteLine($"    Critical/High:     {report.HighSeverityEscalations}");
        Console.WriteLine($"    Medium:            {report.MediumSeverityEscalations}");
        Console.WriteLine($"    Low:               {report.LowSeverityEscalations}");
        Console.WriteLine();

        // Escalations Table
        if (report.Escalations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Detected Escalations ──────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  {"#",-3} {"Technique",-35} {"MITRE",-12} {"Severity",-10} {"Conf",-6} {"Evidence"}");
            Console.WriteLine($"  {"─",-3} {"─",-35} {"─",-12} {"─",-10} {"─",-6} {"─"}");

            for (var i = 0; i < report.Escalations.Count; i++)
            {
                var esc = report.Escalations[i];
                var sevColor = esc.Severity switch
                {
                    PrivEscSeverity.Critical => ConsoleColor.DarkRed,
                    PrivEscSeverity.High => ConsoleColor.Red,
                    PrivEscSeverity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,-3} ");
                Console.Write($"{TruncatePrivEsc(esc.Technique, 35),-35} ");
                Console.Write($"{esc.MitreTechnique,-12} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"{esc.Severity,-10} ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{esc.Confidence:P0,-6} {TruncatePrivEsc(esc.Evidence, 40)}");

                foreach (var ind in esc.Indicators)
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
            Console.WriteLine("  ── Escalation Chains ─────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Chains.Count; i++)
            {
                var chain = report.Chains[i];
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Chain #{i + 1}: ");
                Console.ForegroundColor = original;
                Console.WriteLine($"{chain.StartPrivilege} → {chain.EndPrivilege} ({chain.HopCount} hops)");
                Console.WriteLine($"    Confidence: {chain.CompoundConfidence:P1} | Duration: {chain.Duration.TotalMinutes:F0}min");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"    Verdict: {chain.Verdict}");
                Console.ForegroundColor = original;
                foreach (var step in chain.Steps)
                    Console.WriteLine($"      → [{step.MitreTechnique}] {step.Technique}");
                Console.WriteLine();
            }
        }

        // Stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Statistics ────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Unique Techniques:   {report.Stats.TotalTechniquesUsed}");
        Console.WriteLine($"  Accounts Involved:   {report.Stats.UniqueAccountsInvolved}");
        Console.WriteLine($"  Most Common:         {report.Stats.MostCommonTechnique}");
        Console.WriteLine($"  Avg Confidence:      {report.Stats.AverageConfidence:P1}");
        Console.WriteLine($"  Automated Attempts:  {report.Stats.AutomatedAttempts}");
        Console.WriteLine($"  Manual Attempts:     {report.Stats.ManualAttempts}");
        Console.WriteLine($"  Escalation Velocity: {report.Stats.EscalationVelocity:F1}/day");
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

    private static string TruncatePrivEsc(string text, int max) =>
        text.Length <= max ? text : text[..(max - 3)] + "...";
}
