using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a scan comparison matrix showing per-module scores across multiple scans.
    /// </summary>
    public static void PrintScanMatrix(ScanMatrixService.MatrixReport report)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🛡️  Scan Comparison Matrix            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        var summary = report.Summary;
        WriteColored("  Scans: ", ConsoleColor.DarkGray);
        WriteLineColored($"{summary.TotalScans} ({summary.OldestScan.LocalDateTime:g} → {summary.NewestScan.LocalDateTime:g})", ConsoleColor.White);
        WriteColored("  Modules: ", ConsoleColor.DarkGray);
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{summary.TotalModules}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  (");
        if (summary.ImprovingModules > 0)
        {
            WriteColored($"↑{summary.ImprovingModules}", ConsoleColor.Green);
            Console.Write(" ");
        }
        if (summary.StableModules > 0)
        {
            WriteColored($"→{summary.StableModules}", ConsoleColor.DarkGray);
            Console.Write(" ");
        }
        if (summary.DecliningModules > 0)
        {
            WriteColored($"↓{summary.DecliningModules}", ConsoleColor.Red);
        }
        Console.WriteLine(")");
        Console.WriteLine();

        // Determine column width for module names
        var maxModuleLen = report.Rows.Count > 0
            ? Math.Min(22, report.Rows.Max(r => r.Category.Length))
            : 10;
        maxModuleLen = Math.Max(maxModuleLen, 10);

        // Header row
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  " + "Module".PadRight(maxModuleLen));
        foreach (var col in report.Columns)
        {
            var label = col.Timestamp.LocalDateTime.ToString("MM/dd");
            Console.Write($"  {label,6}");
        }
        Console.Write("    Δ  Trend");
        Console.WriteLine();

        // Separator
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  " + new string('─', maxModuleLen));
        foreach (var _ in report.Columns)
            Console.Write("──" + new string('─', 6));
        Console.Write("──" + new string('─', 4) + "──" + new string('─', 9));
        Console.WriteLine();
        Console.ForegroundColor = orig;

        // Data rows
        foreach (var row in report.Rows)
        {
            // Module name
            var displayName = row.Category.Length > maxModuleLen
                ? row.Category[..(maxModuleLen - 1)] + "…"
                : row.Category;
            Console.Write("  " + displayName.PadRight(maxModuleLen));

            // Score cells
            foreach (var cell in row.Cells)
            {
                if (cell == null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("       —");
                }
                else
                {
                    Console.ForegroundColor = GetScoreColor(cell.Score);
                    var marker = cell.CriticalCount > 0 ? "!" : cell.WarningCount > 0 ? "~" : " ";
                    Console.Write($"  {cell.Score,5}{marker}");
                }
            }

            // Net change
            Console.Write("  ");
            if (row.NetChange > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{("+" + row.NetChange),4}");
            }
            else if (row.NetChange < 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{row.NetChange,4}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{"  0",4}");
            }

            // Trend
            Console.Write("  ");
            switch (row.Trend)
            {
                case "Improving":
                    WriteColored("↑ Better ", ConsoleColor.Green);
                    break;
                case "Declining":
                    WriteColored("↓ Worse  ", ConsoleColor.Red);
                    break;
                case "Stable":
                    WriteColored("→ Stable ", ConsoleColor.DarkGray);
                    break;
                default:
                    WriteColored("? N/A    ", ConsoleColor.DarkGray);
                    break;
            }

            Console.WriteLine();
        }

        // Overall score row
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  " + new string('─', maxModuleLen));
        foreach (var _ in report.Columns)
            Console.Write("──" + new string('─', 6));
        Console.Write("──" + new string('─', 4) + "──" + new string('─', 9));
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  " + "OVERALL".PadRight(maxModuleLen));
        foreach (var col in report.Columns)
        {
            Console.ForegroundColor = GetScoreColor(col.OverallScore);
            Console.Write($"  {col.OverallScore,5} ");
        }

        // Overall change
        if (report.Columns.Count >= 2)
        {
            var overallDelta = report.Columns[^1].OverallScore - report.Columns[0].OverallScore;
            Console.Write("  ");
            Console.ForegroundColor = overallDelta > 0 ? ConsoleColor.Green
                : overallDelta < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            var prefix = overallDelta > 0 ? "+" : "";
            Console.Write($"{prefix + overallDelta,4}");
        }

        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Legend
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Legend: ! = has critical findings  ~ = has warnings  Δ = oldest→newest change");
        Console.WriteLine("  Options: --matrix-scans N  --matrix-module <filter>  --matrix-sort-name  --json  --csv");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        return;

        static ConsoleColor GetScoreColor(int score) => score switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.Yellow,
            _ => ConsoleColor.Red,
        };
    }
}
