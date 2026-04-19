using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintCorrelate(
        List<CorrelationResult> correlations,
        int totalFindings,
        int modulesAnalyzed,
        TimeSpan elapsed)
    {
        var original = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║         🔗  Security Correlation Engine             ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Summary
        var compoundCritical = correlations.Count(c => c.CompoundRisk == "Critical");
        var compoundHigh = correlations.Count(c => c.CompoundRisk == "High");
        var compoundElevated = correlations.Count(c => c.CompoundRisk == "Elevated");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Findings: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(totalFindings);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Modules: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(modulesAnalyzed);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Correlations: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(correlations.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Time: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{elapsed.TotalSeconds:F1}s");
        Console.ForegroundColor = original;
        Console.WriteLine();

        if (compoundCritical > 0 || compoundHigh > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Compound Risks: ");
            if (compoundCritical > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{compoundCritical} Critical");
            }
            if (compoundHigh > 0)
            {
                if (compoundCritical > 0) { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write(" │ "); }
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"{compoundHigh} High");
            }
            if (compoundElevated > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" │ ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{compoundElevated} Elevated");
            }
            Console.WriteLine();
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        if (correlations.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No cross-module correlations detected — findings are isolated.");
            Console.ForegroundColor = original;
            Console.WriteLine();
            return;
        }

        // Each correlation
        for (int i = 0; i < correlations.Count; i++)
        {
            var corr = correlations[i];
            var riskColor = corr.CompoundRisk switch
            {
                "Critical" => ConsoleColor.Red,
                "High" => ConsoleColor.Yellow,
                "Elevated" => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  ┌─ [{i + 1}] ");
            Console.ForegroundColor = riskColor;
            Console.Write(corr.Name);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  ({corr.CompoundRisk})");

            // Modules involved
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │  Modules: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(string.Join(", ", corr.ModulesInvolved));

            // Contributing findings
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  │  Contributing findings:");
            foreach (var finding in corr.ContributingFindings.Take(5))
            {
                var fSevColor = finding.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.Warning => ConsoleColor.Yellow,
                    Severity.Info => ConsoleColor.Cyan,
                    _ => ConsoleColor.Gray
                };
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  │    • ");
                Console.ForegroundColor = fSevColor;
                Console.Write($"[{finding.Severity}] ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(finding.Title.Length > 60 ? finding.Title[..57] + "..." : finding.Title);
            }
            if (corr.ContributingFindings.Count > 5)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  │    ... and {corr.ContributingFindings.Count - 5} more");
            }

            // Narrative
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │  Risk: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(corr.Narrative);

            // Recommended action
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │  Action: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(corr.RecommendedAction);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └──────────────────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Proactive Recommendations
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ┌─ 🎯 Proactive Recommendations (Priority Order)");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  │");

        var prioritized = correlations
            .OrderByDescending(c => c.CompoundRisk == "Critical" ? 3 : c.CompoundRisk == "High" ? 2 : 1)
            .Take(5)
            .ToList();

        for (int i = 0; i < prioritized.Count; i++)
        {
            var p = prioritized[i];
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  │  {i + 1}. ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"{p.RecommendedAction} (resolves: {p.Name})");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └──────────────────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}

/// <summary>
/// Represents a cross-module security correlation result.
/// </summary>
public class CorrelationResult
{
    public string Name { get; set; } = "";
    public string CompoundRisk { get; set; } = "Elevated";
    public List<string> ModulesInvolved { get; set; } = new();
    public List<Finding> ContributingFindings { get; set; } = new();
    public string Narrative { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
}
