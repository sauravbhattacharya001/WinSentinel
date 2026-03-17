using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a per-module score breakdown with horizontal bar charts,
    /// sorted worst-to-best so the weakest areas stand out immediately.
    /// </summary>
    public static void PrintBreakdown(SecurityReport report, bool quiet = false)
    {
        var results = report.Results.OrderBy(r => r.Score).ToList();

        if (results.Count == 0)
        {
            WriteLineColored("  No module results to display.", ConsoleColor.Yellow);
            Console.WriteLine();
            return;
        }

        if (!quiet)
        {
            Console.WriteLine();
            WriteLineColored("  MODULE SCORE BREAKDOWN", ConsoleColor.White);
            WriteLineColored("  ──────────────────────────────────────────────────────────────", ConsoleColor.DarkGray);
            Console.WriteLine();
        }

        // Find the longest module name for alignment
        var maxNameLen = results.Max(r => r.Category.Length);
        if (maxNameLen > 22) maxNameLen = 22; // cap it

        const int barWidth = 30;

        foreach (var result in results)
        {
            var name = result.Category.Length > maxNameLen
                ? result.Category[..maxNameLen]
                : result.Category;

            var score = result.Score;
            var grade = SecurityScorer.GetGrade(score);
            var filledWidth = (int)Math.Round(score / 100.0 * barWidth);
            var emptyWidth = barWidth - filledWidth;

            var barColor = score switch
            {
                >= 80 => ConsoleColor.Green,
                >= 60 => ConsoleColor.Yellow,
                _ => ConsoleColor.Red
            };

            // Module name (right-padded)
            WriteColored($"  {name.PadRight(maxNameLen)} ", ConsoleColor.White);

            // Score number
            WriteColored($"{score,3}", barColor);
            WriteColored("/100 ", ConsoleColor.DarkGray);

            // Bar chart
            WriteColored(new string('█', filledWidth), barColor);
            WriteColored(new string('░', emptyWidth), ConsoleColor.DarkGray);

            // Grade + finding counts
            WriteColored($" {grade}", barColor);

            if (result.CriticalCount > 0)
            {
                WriteColored($"  {result.CriticalCount}C", ConsoleColor.Red);
            }
            if (result.WarningCount > 0)
            {
                WriteColored($"  {result.WarningCount}W", ConsoleColor.Yellow);
            }

            Console.WriteLine();
        }

        if (!quiet)
        {
            Console.WriteLine();
            WriteLineColored("  ──────────────────────────────────────────────────────────────", ConsoleColor.DarkGray);

            // Summary line
            var overallScore = report.SecurityScore;
            var overallGrade = SecurityScorer.GetGrade(overallScore);
            var overallColor = overallScore switch
            {
                >= 80 => ConsoleColor.Green,
                >= 60 => ConsoleColor.Yellow,
                _ => ConsoleColor.Red
            };

            WriteColored($"  {"OVERALL".PadRight(maxNameLen)} ", ConsoleColor.White);
            WriteColored($"{overallScore,3}", overallColor);
            WriteColored("/100 ", ConsoleColor.DarkGray);

            var overallFilled = (int)Math.Round(overallScore / 100.0 * barWidth);
            WriteColored(new string('█', overallFilled), overallColor);
            WriteColored(new string('░', barWidth - overallFilled), ConsoleColor.DarkGray);
            WriteColored($" {overallGrade}", overallColor);
            Console.WriteLine();
            Console.WriteLine();

            // Legend
            WriteColored("  Legend: ", ConsoleColor.DarkGray);
            WriteColored("█", ConsoleColor.Green);
            WriteColored(" ≥80  ", ConsoleColor.DarkGray);
            WriteColored("█", ConsoleColor.Yellow);
            WriteColored(" ≥60  ", ConsoleColor.DarkGray);
            WriteColored("█", ConsoleColor.Red);
            WriteColored(" <60  ", ConsoleColor.DarkGray);
            WriteColored("C", ConsoleColor.Red);
            WriteColored("=Critical  ", ConsoleColor.DarkGray);
            WriteColored("W", ConsoleColor.Yellow);
            WriteColored("=Warning", ConsoleColor.DarkGray);
            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
