namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintThreatDna(ThreatDnaReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║   🧬 THREAT DNA PROFILER — Vulnerability Fingerprint    ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // DNA Hash (fingerprint)
        Console.Write("  DNA Fingerprint: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"[{report.DnaHash}]");
        Console.ForegroundColor = original;
        Console.Write("  │  System: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(report.SystemId);
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Resilience Score Gauge
        Console.Write("  Resilience: ");
        var scoreColor = report.OverallResilienceScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.DarkYellow,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };
        Console.ForegroundColor = scoreColor;
        var filled = (int)(report.OverallResilienceScore / 5);
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.OverallResilienceScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Evolution Phase
        Console.Write("  Phase: ");
        var phaseColor = report.EvolutionPhase switch
        {
            "Resilient" => ConsoleColor.Green,
            "Hardening" => ConsoleColor.DarkYellow,
            "Stabilizing" => ConsoleColor.Yellow,
            _ => ConsoleColor.Red
        };
        Console.ForegroundColor = phaseColor;
        Console.Write($"● {report.EvolutionPhase}");
        Console.ForegroundColor = original;
        Console.Write($"  │  Genes: {report.GeneCount}");
        Console.Write($"  │  Dominant: {report.DominantCategory}");
        Console.WriteLine();
        Console.WriteLine();

        // Gene Table
        if (report.Genes.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Threat Genes ───────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  {0,-14} {1,-12} {2,-10} {3,4} {4,-10} {5}",
                "Gene ID", "Category", "Severity", "Freq", "Persist.", "MITRE Technique");
            Console.ForegroundColor = original;
            Console.WriteLine("  {0}", new string('─', 76));

            foreach (var gene in report.Genes)
            {
                Console.Write("  ");
                Console.ForegroundColor = gene.IsActive ? ConsoleColor.White : ConsoleColor.DarkGray;
                Console.Write($"{gene.GeneId,-14} ");

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{DnaTruncate(gene.Category, 11),-12} ");

                Console.ForegroundColor = gene.Severity.ToLowerInvariant() switch
                {
                    "critical" => ConsoleColor.DarkRed,
                    "warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"{gene.Severity,-10} ");

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{gene.Frequency,4} ");

                // Persistence bar (5-char)
                var pFilled = (int)(gene.Persistence * 5);
                Console.ForegroundColor = gene.Persistence > 0.7 ? ConsoleColor.Red : ConsoleColor.DarkYellow;
                Console.Write($"{new string('█', pFilled)}{new string('░', 5 - pFilled),-10} ");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{DnaTruncate(gene.MitreTechnique, 30)}");

                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Category Breakdown
        if (report.CategoryBreakdown.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Category Exposure ──────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var cat in report.CategoryBreakdown)
            {
                Console.Write("  ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{cat.Category,-16} ");

                var expColor = cat.ExposureScore switch
                {
                    >= 60 => ConsoleColor.DarkRed,
                    >= 30 => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };
                Console.ForegroundColor = expColor;
                var eFilled = (int)(cat.ExposureScore / 5);
                Console.Write($"[{new string('█', Math.Min(eFilled, 20))}{new string('░', Math.Max(0, 20 - eFilled))}] ");
                Console.Write($"{cat.ExposureScore,5:F1}  ");

                Console.ForegroundColor = original;
                Console.Write($"Genes: {cat.GeneCount} ({cat.ActiveGenes} active)  ");

                var trendColor = cat.TrendDirection switch
                {
                    "Worsening" => ConsoleColor.Red,
                    "Improving" => ConsoleColor.Green,
                    _ => ConsoleColor.DarkGray
                };
                Console.ForegroundColor = trendColor;
                var arrow = cat.TrendDirection switch
                {
                    "Worsening" => "▲",
                    "Improving" => "▼",
                    _ => "►"
                };
                Console.Write($"{arrow} {cat.TrendDirection}");

                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Mutation Alerts
        if (report.MutationAlerts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Mutation Alerts ────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var mutation in report.MutationAlerts)
            {
                var icon = mutation.MutationType switch
                {
                    DnaMutationType.NewGene => "🆕",
                    DnaMutationType.GeneEliminated => "✅",
                    DnaMutationType.Resurgence => "🔄",
                    DnaMutationType.SeverityEscalation => "⚠️",
                    DnaMutationType.CategoryShift => "🔀",
                    _ => "•"
                };

                Console.ForegroundColor = mutation.Impact switch
                {
                    "Critical" => ConsoleColor.DarkRed,
                    "High" => ConsoleColor.Red,
                    "Positive" => ConsoleColor.Green,
                    _ => ConsoleColor.Yellow
                };
                Console.WriteLine($"  {icon} [{mutation.Impact}] {mutation.Description}");
            }

            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Hardening Plan
        if (report.HardeningPlan.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Hardening Plan ─────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var action in report.HardeningPlan)
            {
                Console.ForegroundColor = action.Priority <= 2 ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"  {action.Priority}. ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(action.Action);
                Console.ForegroundColor = original;
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"     Effort: {action.Effort}");
                Console.Write($"  │  Resilience Gain: +{action.ResilienceGain}");
                Console.Write($"  │  Genes: {action.TargetGenes.Count}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Recommendations ───────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in report.Recommendations)
            {
                Console.ForegroundColor = rec.StartsWith("URGENT", StringComparison.OrdinalIgnoreCase)
                    ? ConsoleColor.Red
                    : ConsoleColor.Gray;
                Console.WriteLine($"  • {rec}");
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Footer
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    private static string DnaTruncate(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
    }
}
