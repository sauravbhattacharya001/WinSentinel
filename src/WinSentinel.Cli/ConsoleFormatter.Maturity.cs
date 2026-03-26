using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a security maturity assessment report to the console.
    /// </summary>
    public static void PrintMaturity(MaturityAssessment assessment, bool gapsOnly = false)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🏛️  SECURITY MATURITY ASSESSMENT          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        // Overall summary
        var gradeColor = assessment.Grade switch
        {
            "A" => ConsoleColor.Green,
            "B" => ConsoleColor.DarkGreen,
            "C" => ConsoleColor.Yellow,
            "D" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red,
        };

        Console.Write("  Overall Grade: ");
        Console.ForegroundColor = gradeColor;
        Console.Write(assessment.Grade);
        Console.ResetColor();
        Console.Write($"  (Level {(int)assessment.OverallLevel} – {assessment.OverallLevel})");
        Console.WriteLine($"  Score: {assessment.OverallScore:F1}/5.0");
        Console.WriteLine($"  Findings: {assessment.TotalFindings} total, {assessment.CriticalFindings} critical, {assessment.WarningFindings} warnings");
        Console.WriteLine();

        // Domain breakdown
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Domain Maturity ──────────────────────────────────");
        Console.ResetColor();
        Console.WriteLine();

        foreach (var domain in assessment.Domains.OrderBy(d => (int)d.Level))
        {
            var levelColor = domain.Level switch
            {
                MaturityLevel.Optimizing => ConsoleColor.Green,
                MaturityLevel.Managed => ConsoleColor.DarkGreen,
                MaturityLevel.Defined => ConsoleColor.Yellow,
                MaturityLevel.Repeatable => ConsoleColor.DarkYellow,
                _ => ConsoleColor.Red,
            };

            // Domain header with bar
            Console.Write("  ");
            Console.ForegroundColor = levelColor;
            Console.Write($"[L{(int)domain.Level}]");
            Console.ResetColor();
            Console.Write($" {domain.Name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" — {domain.Description}");
            Console.ResetColor();

            // Progress bar
            Console.Write("       ");
            var barWidth = 30;
            var filled = (int)(domain.Percentage / 100.0 * barWidth);
            Console.ForegroundColor = levelColor;
            Console.Write(new string('█', filled));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(new string('░', barWidth - filled));
            Console.ResetColor();
            Console.WriteLine($" {domain.Percentage:F0}% ({domain.Score}/{domain.MaxScore})");

            if (!gapsOnly && domain.Strengths.Length > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                foreach (var s in domain.Strengths)
                    Console.WriteLine($"       ✓ {s}");
                Console.ResetColor();
            }

            if (domain.Gaps.Length > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach (var g in domain.Gaps)
                    Console.WriteLine($"       ✗ {g}");
                Console.ResetColor();
            }

            if (domain.Recommendations.Length > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                foreach (var r in domain.Recommendations)
                    Console.WriteLine($"       → {r}");
                Console.ResetColor();
            }

            Console.WriteLine();
        }

        // Top priorities
        if (assessment.TopPriorities.Length > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Top Priorities ───────────────────────────────────");
            Console.ResetColor();
            Console.WriteLine();
            for (var i = 0; i < assessment.TopPriorities.Length; i++)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"  {i + 1}. ");
                Console.ResetColor();
                Console.WriteLine(assessment.TopPriorities[i]);
            }
            Console.WriteLine();
        }

        // Maturity scale legend
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Scale: L1=Initial  L2=Repeatable  L3=Defined  L4=Managed  L5=Optimizing");
        Console.ResetColor();
        Console.WriteLine();
    }
}
