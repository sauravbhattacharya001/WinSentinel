namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintNegotiation(WinSentinel.Core.Services.NegotiationResult result, CliOptions options)
    {
        var orig = Console.ForegroundColor;
        Console.WriteLine();

        // Banner
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║              🤝  SECURITY NEGOTIATION TABLE  🤝              ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Strategy indicator
        var stratIcon = result.Strategy switch
        {
            "aggressive" => "⚔️  Aggressive",
            "conservative" => "🕊️  Conservative",
            _ => "🏛️  Balanced"
        };
        Console.Write("  Strategy: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(stratIcon);
        Console.ForegroundColor = orig;

        Console.Write("  Findings: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(result.TotalFindings);
        Console.ForegroundColor = orig;
        Console.Write("   Score: ");
        Console.ForegroundColor = result.SecurityScore >= 70 ? ConsoleColor.Green : result.SecurityScore >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
        Console.Write($"{result.SecurityScore}");
        Console.ForegroundColor = orig;
        Console.Write(" → ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"{result.ProjectedScore} (projected)");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Deal Terms
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── DEAL TERMS ──────────────────────────────────────────────");
        Console.ForegroundColor = orig;
        for (int i = 0; i < result.DealTerms.Count; i++)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {i + 1}. ");
            Console.ForegroundColor = orig;
            Console.WriteLine(result.DealTerms[i]);
        }
        Console.WriteLine();

        // Phases
        foreach (var phase in result.Phases)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  ── PHASE {phase.PhaseNumber}: {phase.Name.ToUpper()} ({phase.Timeline}) ──");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {phase.Description}");
            Console.ForegroundColor = orig;
            Console.WriteLine($"  Effort: {phase.EffortScore:F1}  |  Impact: {phase.ImpactScore:F1}  |  Score after: +{phase.ProjectedScoreAfter:F1}");
            Console.WriteLine();

            // Items table
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Module              Finding                          Sev   Eff  Imp  Pri");
            Console.WriteLine("  ────────────────── ──────────────────────────────── ──── ──── ──── ────");
            Console.ForegroundColor = orig;

            foreach (var item in phase.Items.Take(15))
            {
                var modName = TruncateNeg(item.Module, 18).PadRight(18);
                var findName = TruncateNeg(item.Finding, 32).PadRight(32);
                var sevColor = item.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                Console.Write("  ");
                Console.Write(modName);
                Console.Write(" ");
                Console.Write(findName);
                Console.Write(" ");
                Console.ForegroundColor = sevColor;
                Console.Write(TruncateNeg(item.Severity, 4).PadRight(4));
                Console.ForegroundColor = orig;
                Console.Write($" {item.EffortScore,4:F1} {item.ImpactScore,4:F1} {item.Priority,4:F1}");
                Console.WriteLine();
            }

            if (phase.Items.Count > 15)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ... and {phase.Items.Count - 15} more items");
                Console.ForegroundColor = orig;
            }
            Console.WriteLine();
        }

        // Compromises
        if (result.Compromises.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── COMPROMISES ─────────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            foreach (var c in result.Compromises)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"  [{c.Area}]");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("    Security wants: ");
                Console.ForegroundColor = orig;
                Console.WriteLine(c.SecurityWants);
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("    Ops wants:      ");
                Console.ForegroundColor = orig;
                Console.WriteLine(c.OperationsWants);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("    Deal:           ");
                Console.ForegroundColor = orig;
                Console.WriteLine(c.Deal);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    Rationale:      ");
                Console.ForegroundColor = orig;
                Console.WriteLine(c.Rationale);
                Console.WriteLine();
            }
        }

        // Summary
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── SUMMARY ─────────────────────────────────────────────────");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        var s = result.Summary;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ⚡ Quick Wins: {s.QuickWins}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"   📋 Deferred: {s.DeferredItems}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"   ✓ Accepted Risk: {s.AcceptedRisks}");
        Console.ForegroundColor = orig;
        Console.Write($"   ⏱️ Est. Effort: {s.EstimatedEffort:F0}h");
        Console.WriteLine();
        Console.WriteLine();
        Console.Write("  Verdict: ");
        Console.WriteLine(s.Verdict);
        Console.WriteLine();

        // Proactive recommendations
        if (s.ProactiveRecommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  💡 Proactive Recommendations:");
            Console.ForegroundColor = orig;
            foreach (var rec in s.ProactiveRecommendations)
            {
                Console.Write("    → ");
                Console.WriteLine(rec);
            }
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Tip: Use --negotiate-strategy aggressive|conservative to shift priorities");
        Console.WriteLine("  Tip: Use --negotiate-phases N to change the number of implementation phases");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    private static string TruncateNeg(string s, int maxLen)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= maxLen ? s : s[..(maxLen - 1)] + "…";
    }
}
