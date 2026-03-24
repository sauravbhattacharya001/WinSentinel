using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a 3×3 likelihood × impact risk heat-map to the console.
    /// Impact (columns):   Low  |  Medium  |  High
    /// Likelihood (rows):  High |  Medium  |  Low
    /// Each cell shows the count of findings that fall into that bucket.
    /// </summary>
    public static void PrintRiskMatrix(SecurityReport report, bool showCounts = false)
    {
        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass)
            .ToList();

        if (allFindings.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No actionable findings — risk matrix is empty!");
            Console.ResetColor();
            Console.WriteLine();
            return;
        }

        // Classify each finding into likelihood (by category frequency) and impact (by severity)
        var categoryGroups = allFindings.GroupBy(f => f.Category).ToList();
        var maxCount = categoryGroups.Max(g => g.Count());

        string GetLikelihood(int count) =>
            maxCount <= 1 ? "Low"
            : count >= maxCount * 0.66 ? "High"
            : count >= maxCount * 0.33 ? "Medium"
            : "Low";

        string GetImpact(Severity sev) => sev switch
        {
            Severity.Critical => "High",
            Severity.Warning => "Medium",
            _ => "Low"
        };

        // Build matrix cells: [likelihood, impact] → list of findings
        var matrix = new Dictionary<(string likelihood, string impact), List<Finding>>();
        var levels = new[] { "High", "Medium", "Low" };

        foreach (var l in levels)
            foreach (var i in levels)
                matrix[(l, i)] = new List<Finding>();

        foreach (var group in categoryGroups)
        {
            var likelihood = GetLikelihood(group.Count());
            foreach (var finding in group)
            {
                var impact = GetImpact(finding.Severity);
                matrix[(likelihood, impact)].Add(finding);
            }
        }

        // Render header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║              RISK MATRIX  (Likelihood × Impact)         ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        // Column widths
        const int labelWidth = 14;
        const int cellWidth = 16;

        // Header row
        Console.Write(new string(' ', labelWidth + 4));
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Impact".PadLeft(cellWidth + cellWidth / 2));
        Console.ResetColor();
        Console.WriteLine();

        Console.Write(new string(' ', labelWidth + 2));
        foreach (var impact in levels)
        {
            var header = $"  {impact}  ";
            Console.Write(header.PadLeft(cellWidth).PadRight(cellWidth));
        }
        Console.WriteLine();

        // Separator
        Console.Write(new string(' ', labelWidth));
        Console.WriteLine("┌" + new string('─', cellWidth) + "┬" + new string('─', cellWidth) + "┬" + new string('─', cellWidth) + "┐");

        // Rows (High likelihood at top, Low at bottom)
        for (int li = 0; li < levels.Length; li++)
        {
            var likelihood = levels[li];

            // Row label
            if (li == 1)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(" Likelihood   ");
                Console.ResetColor();
            }
            else
            {
                Console.Write(new string(' ', labelWidth));
            }

            Console.Write("│");

            foreach (var impact in levels)
            {
                var findings = matrix[(likelihood, impact)];
                var count = findings.Count;
                var riskLevel = GetCellRisk(likelihood, impact);
                var color = riskLevel switch
                {
                    "Critical" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkYellow,
                    "Medium" => ConsoleColor.Yellow,
                    "Low" => ConsoleColor.Green,
                    _ => ConsoleColor.DarkGray
                };

                Console.ForegroundColor = color;
                var label = count == 0
                    ? "·"
                    : showCounts
                        ? $"{count} ({riskLevel[0]})"
                        : $"{count}";
                Console.Write(label.PadLeft(cellWidth / 2 + label.Length / 2).PadRight(cellWidth));
                Console.ResetColor();
                Console.Write("│");
            }

            // Row label on right side
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {likelihood}");
            Console.ResetColor();
            Console.WriteLine();

            if (li < levels.Length - 1)
            {
                Console.Write(new string(' ', labelWidth));
                Console.WriteLine("├" + new string('─', cellWidth) + "┼" + new string('─', cellWidth) + "┼" + new string('─', cellWidth) + "┤");
            }
        }

        // Bottom border
        Console.Write(new string(' ', labelWidth));
        Console.WriteLine("└" + new string('─', cellWidth) + "┴" + new string('─', cellWidth) + "┴" + new string('─', cellWidth) + "┘");

        Console.WriteLine();

        // Legend
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Legend: ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  ■ Critical");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.Write("  ■ High");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  ■ Medium");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("  ■ Low");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine();

        // Summary: top-risk categories
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  Top Risk Categories:");
        Console.ResetColor();

        var criticalCell = matrix[("High", "High")];
        var highCells = matrix[("High", "Medium")].Concat(matrix[("Medium", "High")]).ToList();

        if (criticalCell.Any())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"    🔴 Critical Risk ({criticalCell.Count} findings):");
            Console.ResetColor();
            foreach (var cat in criticalCell.GroupBy(f => f.Category).OrderByDescending(g => g.Count()).Take(5))
            {
                Console.WriteLine($"       • {cat.Key} ({cat.Count()})");
            }
        }

        if (highCells.Any())
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"    🟠 High Risk ({highCells.Count} findings):");
            Console.ResetColor();
            foreach (var cat in highCells.GroupBy(f => f.Category).OrderByDescending(g => g.Count()).Take(5))
            {
                Console.WriteLine($"       • {cat.Key} ({cat.Count()})");
            }
        }

        if (!criticalCell.Any() && !highCells.Any())
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("    ✓ No critical or high-risk findings");
            Console.ResetColor();
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Total actionable findings: {allFindings.Count}");
        Console.WriteLine($"  Likelihood = category frequency relative to max | Impact = finding severity");
        Console.ResetColor();
        Console.WriteLine();
    }

    /// <summary>
    /// Determine the combined risk level from a likelihood × impact cell.
    /// </summary>
    private static string GetCellRisk(string likelihood, string impact) =>
        (likelihood, impact) switch
        {
            ("High", "High") => "Critical",
            ("High", "Medium") or ("Medium", "High") => "High",
            ("High", "Low") or ("Medium", "Medium") or ("Low", "High") => "Medium",
            _ => "Low"
        };
}
