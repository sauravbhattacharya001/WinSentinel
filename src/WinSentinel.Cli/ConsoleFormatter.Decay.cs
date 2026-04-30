namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintDecay(DecayPredictionReport report)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║      ☢️ DECAY — Security Finding Escalation Predictor        ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        if (report.TotalFindings == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✅ No active findings to analyze.");
            Console.ForegroundColor = original;
            Console.WriteLine();
            return;
        }

        // ── Health Score Gauge ───────────────────────────────────
        var scoreColor = report.HealthScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.Cyan,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        Console.Write("  Decay Health: ");
        Console.ForegroundColor = scoreColor;
        Console.Write($"{report.HealthScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine($"  │  Findings: {report.TotalFindings}");
        Console.WriteLine();

        // ── Escalation Summary ───────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌─ Escalation Forecast ─────────────────────────────────┐");
        Console.ForegroundColor = original;

        if (report.OverdueCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  │  🚨 Overdue:        {report.OverdueCount} finding(s) past expected escalation");
            Console.ForegroundColor = original;
        }
        if (report.EscalatingWithin7Days > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"  │  ⚡ Within 7 days:  {report.EscalatingWithin7Days} finding(s) approaching escalation");
            Console.ForegroundColor = original;
        }
        if (report.EscalatingWithin30Days > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  │  📈 Within 30 days: {report.EscalatingWithin30Days} finding(s) on decay trajectory");
            Console.ForegroundColor = original;
        }

        var stableCount = report.Predictions.Count(p => p.Trajectory == DecayTrajectory.Stable);
        if (stableCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  │  ✅ Stable:         {stableCount} finding(s) with no escalation predicted");
            Console.ForegroundColor = original;
        }

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Top Urgent Findings ──────────────────────────────────
        var urgent = report.Predictions.Where(p => p.Urgency >= DecayUrgency.Medium).Take(15).ToList();
        if (urgent.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Most Urgent (by time-to-escalation) ─────────────────┐");
            Console.ForegroundColor = original;

            foreach (var p in urgent)
            {
                var urgencyIcon = p.Urgency switch
                {
                    DecayUrgency.Critical => "🔴",
                    DecayUrgency.High => "🟠",
                    DecayUrgency.Medium => "🟡",
                    _ => "⚪"
                };

                var urgencyColor = p.Urgency switch
                {
                    DecayUrgency.Critical => ConsoleColor.Red,
                    DecayUrgency.High => ConsoleColor.DarkYellow,
                    DecayUrgency.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                var title = p.FindingTitle.Length > 40 ? p.FindingTitle[..37] + "..." : p.FindingTitle;
                var escalation = p.DaysToEscalation < 0
                    ? "N/A"
                    : p.DaysToEscalation == 0 ? "OVERDUE" : $"{p.DaysToEscalation:F0}d";

                Console.Write($"  │  {urgencyIcon} ");
                Console.ForegroundColor = urgencyColor;
                Console.Write($"{title,-40}");
                Console.ForegroundColor = original;
                Console.Write($"  {p.CurrentSeverity,-8} → {p.PredictedNextSeverity,-8}");
                Console.ForegroundColor = urgencyColor;
                Console.Write($"  {escalation,7}");
                Console.ForegroundColor = original;
                Console.WriteLine($"  ({p.Confidence}%)");
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Category Breakdown ───────────────────────────────────
        if (report.CategorySummaries.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Category Decay Health ───────────────────────────────┐");
            Console.ForegroundColor = original;

            foreach (var cat in report.CategorySummaries.Take(10))
            {
                var catColor = cat.HealthScore switch
                {
                    >= 80 => ConsoleColor.Green,
                    >= 50 => ConsoleColor.Yellow,
                    _ => ConsoleColor.Red
                };

                var avgDays = cat.AvgDaysToEscalation < 0 ? "stable" : $"~{cat.AvgDaysToEscalation:F0}d";
                Console.Write($"  │  ");
                Console.ForegroundColor = catColor;
                Console.Write($"{cat.Category,-18}");
                Console.ForegroundColor = original;
                Console.WriteLine($"  Health: {cat.HealthScore,3}/100  │  Findings: {cat.FindingCount,2}  │  Avg escalation: {avgDays}");
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Recommendations ──────────────────────────────────────
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Autonomous Recommendations ─────────────────────────┐");
            Console.ForegroundColor = original;

            foreach (var rec in report.Recommendations)
            {
                Console.WriteLine($"  │  {rec}");
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Summary ──────────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {report.Summary}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
