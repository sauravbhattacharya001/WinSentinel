using static WinSentinel.Core.Services.AttackSurfaceAnalyzer;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintAttackSurface(AttackSurfaceReport report, int topActions = 10)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║         ATTACK SURFACE ANALYSIS             ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Overall score
        Console.Write("  Overall Exposure Score: ");
        Console.ForegroundColor = GradeColor(report.OverallGrade);
        Console.Write($"{report.OverallScore:F1}/100");
        Console.ForegroundColor = orig;
        Console.Write("  Grade: ");
        Console.ForegroundColor = GradeColor(report.OverallGrade);
        Console.WriteLine(report.OverallGrade);
        Console.ForegroundColor = orig;

        Console.WriteLine($"  Total Findings: {report.TotalFindings} ({report.TotalCritical} critical, {report.TotalWarnings} warnings)");

        if (report.MostExposedVector.HasValue)
        {
            Console.Write("  Most Exposed:  ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(report.MostExposedVector.Value);
            Console.ForegroundColor = orig;
        }

        if (report.LeastExposedVector.HasValue)
        {
            Console.Write("  Least Exposed: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(report.LeastExposedVector.Value);
            Console.ForegroundColor = orig;
        }

        // Vector breakdown
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Vector Breakdown ──────────────────────────");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Vector",-18} {"Score",7} {"Grade",6} {"Crit",5} {"Warn",5} {"Info",5} {"Pass",5}");
        Console.WriteLine($"  {"──────────────────",-18} {"─────",7} {"─────",6} {"────",5} {"────",5} {"────",5} {"────",5}");
        Console.ForegroundColor = orig;

        foreach (var v in report.Vectors.OrderByDescending(x => x.ExposureScore))
        {
            if (v.TotalFindings == 0) continue;

            Console.Write($"  {v.DisplayName,-18} ");
            Console.ForegroundColor = GradeColor(v.Grade);
            Console.Write($"{v.ExposureScore,6:F1} ");
            Console.Write($"{v.Grade,5} ");
            Console.ForegroundColor = orig;

            Console.ForegroundColor = v.CriticalCount > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            Console.Write($"{v.CriticalCount,5} ");
            Console.ForegroundColor = v.WarningCount > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            Console.Write($"{v.WarningCount,5} ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{v.InfoCount,5} ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{v.PassCount,5}");
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        // Exposure bar chart
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Exposure Visualization ────────────────────");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        foreach (var v in report.Vectors.OrderByDescending(x => x.ExposureScore))
        {
            if (v.TotalFindings == 0) continue;

            Console.Write($"  {v.DisplayName,-16} ");
            int barLen = (int)(v.ExposureScore / 100.0 * 30);
            Console.ForegroundColor = GradeColor(v.Grade);
            Console.Write(new string('█', barLen));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(new string('░', 30 - barLen));
            Console.ForegroundColor = orig;
            Console.WriteLine($" {v.ExposureScore:F1}");
        }

        // Top reduction actions
        if (report.TopActions.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Top Reduction Actions ─────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            var actionsToShow = report.TopActions.Take(topActions).ToList();
            for (int i = 0; i < actionsToShow.Count; i++)
            {
                var a = actionsToShow[i];
                Console.Write($"  {i + 1,2}. ");
                Console.ForegroundColor = a.Priority switch
                {
                    ActionPriority.Critical => ConsoleColor.Red,
                    ActionPriority.High => ConsoleColor.Yellow,
                    ActionPriority.Medium => ConsoleColor.DarkYellow,
                    _ => ConsoleColor.DarkGray
                };
                Console.Write($"[{a.Priority}] ");
                Console.ForegroundColor = orig;
                Console.Write(a.Action);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  (~{a.EstimatedReduction:F0}pts on {a.Vector})");
                Console.ForegroundColor = orig;
            }
        }

        // Vector recommendations
        var vectorsWithRecs = report.Vectors
            .Where(v => v.Recommendations.Count > 0)
            .OrderByDescending(v => v.ExposureScore)
            .Take(3)
            .ToList();

        if (vectorsWithRecs.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Recommendations (Top 3 Vectors) ──────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            foreach (var v in vectorsWithRecs)
            {
                Console.ForegroundColor = GradeColor(v.Grade);
                Console.Write($"  {v.DisplayName}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" (Score: {v.ExposureScore:F1})");
                Console.ForegroundColor = orig;

                foreach (var rec in v.Recommendations.Take(3))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    → ");
                    Console.ForegroundColor = orig;
                    Console.WriteLine(rec);
                }
                Console.WriteLine();
            }
        }

        // Comparison section (if available)
        if (report.Comparison != null)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Comparison ────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            Console.Write("  Score Change: ");
            Console.ForegroundColor = report.Comparison.ScoreDelta > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.WriteLine($"{report.Comparison.ScoreDelta:+0.0;-0.0;0.0}");
            Console.ForegroundColor = orig;

            Console.WriteLine($"  New Findings: {report.Comparison.NewFindings}  |  Resolved: {report.Comparison.ResolvedFindings}");
            Console.Write("  Direction: ");
            Console.ForegroundColor = report.Comparison.Direction == "Improved" ? ConsoleColor.Green :
                report.Comparison.Direction == "Worsened" ? ConsoleColor.Red : ConsoleColor.DarkGray;
            Console.WriteLine(report.Comparison.Direction);
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        Console.WriteLine();
    }

    private static ConsoleColor GradeColor(string grade) => grade switch
    {
        "A" => ConsoleColor.Green,
        "B" => ConsoleColor.DarkGreen,
        "C" => ConsoleColor.Yellow,
        "D" => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };
}
