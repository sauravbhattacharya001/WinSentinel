using static WinSentinel.Core.Services.HotspotAnalyzer;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a colorful security hotspot analysis to the console.
    /// </summary>
    public static void PrintHotspotResult(HotspotResult result, bool quiet = false, int top = 10)
    {
        if (quiet) return;

        var prev = Console.ForegroundColor;

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  🔥 SECURITY HOTSPOT ANALYSIS                               ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = prev;
        Console.WriteLine();

        if (result.RunsAnalyzed == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit history found. Run some audits first!");
            Console.ForegroundColor = prev;
            return;
        }

        // Summary
        Console.Write("  Runs analyzed:     ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{result.RunsAnalyzed} (over {result.DaysSpan} days)");
        Console.ForegroundColor = prev;

        Console.Write("  Overall heat:      ");
        PrintHeatBadge(result.OverallHeatLevel);
        Console.WriteLine($"  ({result.OverallHeat:F1})");

        Console.Write("  Hottest category:  ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(result.HottestCategory);
        Console.ForegroundColor = prev;

        Console.Write("  Hottest module:    ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(result.HottestModule);
        Console.ForegroundColor = prev;
        Console.WriteLine();

        // Category hotspots
        if (result.CategoryHotspots.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── Category Hotspots ─────────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            PrintHotspotTable(result.CategoryHotspots.Take(top).ToList());
            Console.WriteLine();
        }

        // Module hotspots
        if (result.ModuleHotspots.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── Module Hotspots ───────────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            PrintHotspotTable(result.ModuleHotspots.Take(top).ToList());
            Console.WriteLine();
        }

        // Heat map bar chart
        if (result.CategoryHotspots.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── Heat Map ──────────────────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            var maxHeat = result.CategoryHotspots.Max(h => h.HeatScore);
            foreach (var h in result.CategoryHotspots.Take(top))
            {
                var nameCol = h.Name.Length > 20 ? h.Name[..17] + "..." : h.Name;
                Console.Write($"  {nameCol,-20} ");
                var barLen = maxHeat > 0 ? (int)(h.HeatScore / maxHeat * 30) : 0;
                Console.ForegroundColor = HeatColor(h.HeatLevel);
                Console.Write(new string('█', Math.Max(1, barLen)));
                Console.ForegroundColor = prev;
                Console.WriteLine($" {h.HeatScore:F1}");
            }
            Console.WriteLine();
        }

        // Tips
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  💡 Focus remediation on 🔴 Critical and 🟠 High hotspots first.");
        Console.WriteLine("  💡 Use --hotspots-top N to show more/fewer entries.");
        Console.ForegroundColor = prev;
        Console.WriteLine();
    }

    private static void PrintHotspotTable(List<Hotspot> hotspots)
    {
        var prev = Console.ForegroundColor;

        // Table header
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"#",-3} {"Name",-22} {"Heat",8} {"Level",-12} {"Rate",6} {"C",4} {"W",4} {"I",4} {"Avg",5} {"Trend",-14}");
        Console.WriteLine($"  {"─",3} {"─",22} {"─",8} {"─",12} {"─",6} {"─",4} {"─",4} {"─",4} {"─",5} {"─",14}");
        Console.ForegroundColor = prev;

        for (int i = 0; i < hotspots.Count; i++)
        {
            var h = hotspots[i];
            var name = h.Name.Length > 22 ? h.Name[..19] + "..." : h.Name;

            Console.Write($"  {i + 1,-3} {name,-22} ");

            Console.ForegroundColor = HeatColor(h.HeatLevel);
            Console.Write($"{h.HeatScore,8:F1}");
            Console.ForegroundColor = prev;

            Console.Write(" ");
            PrintHeatBadge(h.HeatLevel, pad: 12);

            Console.Write($" {h.AppearanceRate,5:F0}%");

            Console.ForegroundColor = h.CriticalFindings > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            Console.Write($" {h.CriticalFindings,4}");
            Console.ForegroundColor = h.WarningFindings > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            Console.Write($" {h.WarningFindings,4}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {h.InfoFindings,4}");
            Console.ForegroundColor = prev;

            Console.Write($" {h.AvgFindingsPerRun,5:F1}");

            Console.Write(" ");
            Console.ForegroundColor = h.Trend.Contains("Worsening") ? ConsoleColor.Red
                : h.Trend.Contains("Improving") ? ConsoleColor.Green
                : ConsoleColor.DarkGray;
            Console.Write($"{h.Trend,-14}");
            Console.ForegroundColor = prev;

            Console.WriteLine();
        }
    }

    private static void PrintHeatBadge(string heatLevel, int pad = 0)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = HeatColor(heatLevel);
        if (pad > 0)
        {
            var text = heatLevel.Length > pad ? heatLevel[..pad] : heatLevel;
            Console.Write(text.PadRight(pad));
        }
        else
        {
            Console.Write(heatLevel);
        }
        Console.ForegroundColor = prev;
    }

    private static ConsoleColor HeatColor(string heatLevel)
    {
        if (heatLevel.Contains("Critical")) return ConsoleColor.Red;
        if (heatLevel.Contains("High")) return ConsoleColor.DarkYellow;
        if (heatLevel.Contains("Medium")) return ConsoleColor.Yellow;
        if (heatLevel.Contains("Low")) return ConsoleColor.Blue;
        return ConsoleColor.DarkGray;
    }
}
