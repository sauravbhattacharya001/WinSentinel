using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a prioritized triage queue of findings grouped by urgency tier.
    /// </summary>
    public static void PrintTriage(
        List<(string Module, Finding Finding, int PriorityScore, bool Fixable, string Tier)> items,
        int totalFindings,
        TimeSpan elapsed)
    {
        Console.WriteLine();
        WriteLineColored("  🎯 Security Finding Triage Queue", ConsoleColor.Cyan);
        Console.WriteLine($"  {items.Count} items triaged (of {totalFindings} actionable findings) in {elapsed.TotalSeconds:F1}s");
        Console.WriteLine();

        if (items.Count == 0)
        {
            WriteLineColored("  ✅ No actionable findings to triage. System looks clean!", ConsoleColor.Green);
            Console.WriteLine();
            return;
        }

        // Group by tier
        var tiers = new[] { "IMMEDIATE", "SOON", "LATER", "MONITOR" };
        foreach (var tier in tiers)
        {
            var tierItems = items.Where(i => i.Tier == tier).ToList();
            if (tierItems.Count == 0) continue;

            var (tierEmoji, tierColor) = tier switch
            {
                "IMMEDIATE" => ("🔴", ConsoleColor.Red),
                "SOON" => ("🟠", ConsoleColor.Yellow),
                "LATER" => ("🔵", ConsoleColor.Cyan),
                "MONITOR" => ("⚪", ConsoleColor.DarkGray),
                _ => ("⚪", ConsoleColor.Gray)
            };

            WriteLineColored($"  {tierEmoji} {tier} ({tierItems.Count})", tierColor);
            Console.WriteLine($"  {"─",1}{new string('─', 70)}");

            int rank = 1;
            foreach (var (module, finding, score, isFixable, _) in tierItems)
            {
                var sevColor = finding.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.Warning => ConsoleColor.Yellow,
                    Severity.Info => ConsoleColor.Cyan,
                    _ => ConsoleColor.Gray
                };

                Console.Write($"  {rank,3}. ");
                WriteColored($"[{finding.Severity}]", sevColor);
                Console.Write($" {TriageTruncate(finding.Title ?? "(untitled)", 50)}");
                if (isFixable)
                {
                    WriteColored(" ⚡", ConsoleColor.Green);
                }
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"       Module: {module}  │  Priority: {score}");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("       Fix: ");
                    Console.ResetColor();
                    Console.WriteLine(TriageTruncate(finding.Remediation.Replace('\n', ' ').Replace('\r', ' '), 60));
                }

                rank++;
            }

            Console.WriteLine();
        }

        // Summary bar
        var immediate = items.Count(i => i.Tier == "IMMEDIATE");
        var soon = items.Count(i => i.Tier == "SOON");
        var later = items.Count(i => i.Tier == "LATER");
        var monitor = items.Count(i => i.Tier == "MONITOR");
        var fixable = items.Count(i => i.Fixable);

        Console.Write("  Summary: ");
        if (immediate > 0) { WriteColored($"{immediate} immediate", ConsoleColor.Red); Console.Write("  "); }
        if (soon > 0) { WriteColored($"{soon} soon", ConsoleColor.Yellow); Console.Write("  "); }
        if (later > 0) { WriteColored($"{later} later", ConsoleColor.Cyan); Console.Write("  "); }
        if (monitor > 0) { WriteColored($"{monitor} monitor", ConsoleColor.DarkGray); Console.Write("  "); }
        Console.WriteLine();

        if (fixable > 0)
        {
            Console.Write("  ");
            WriteColored($"⚡ {fixable} finding{(fixable == 1 ? "" : "s")} auto-fixable", ConsoleColor.Green);
            Console.WriteLine(" (run with 'fix' command)");
        }

        Console.WriteLine();
    }

    private static string TriageTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return text.Length <= maxLen ? text : text[..(maxLen - 3)] + "...";
    }
}
