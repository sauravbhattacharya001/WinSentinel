using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a colorful noise analysis report to the console.
    /// </summary>
    public static void PrintNoise(NoiseAnalysisResult result, CliOptions options)
    {
        if (options.Quiet) return;

        var prev = Console.ForegroundColor;

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  🔊 NOISE ANALYSIS                                          ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = prev;
        Console.WriteLine();

        // Overview
        var noiseColor = result.Stats.NoiseLevelRating switch
        {
            "Low" => ConsoleColor.Green,
            "Moderate" => ConsoleColor.Yellow,
            "High" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        Console.Write("  Noise Level: ");
        Console.ForegroundColor = noiseColor;
        Console.WriteLine(result.Stats.NoiseLevelRating);
        Console.ForegroundColor = prev;

        Console.WriteLine($"  Scans Analyzed:      {result.RunsAnalyzed} ({result.DaysSpan} days)");
        Console.WriteLine($"  Total Occurrences:   {result.TotalFindingOccurrences}");
        Console.WriteLine($"  Unique Findings:     {result.UniqueFindingTitles}");
        Console.WriteLine($"  Avg Findings/Scan:   {result.Stats.AvgFindingsPerScan}");
        Console.WriteLine();

        // Top Noisy Findings
        if (result.TopNoisyFindings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Noisiest Findings ─────────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            for (int i = 0; i < result.TopNoisyFindings.Count; i++)
            {
                var f = result.TopNoisyFindings[i];
                var sevColor = f.Severity.ToUpperInvariant() switch
                {
                    "CRITICAL" => ConsoleColor.Red,
                    "WARNING" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                var perennial = f.IsPerennial ? " 🔁" : "";

                Console.Write($"  {i + 1,2}. ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{f.Severity}]");
                Console.ForegroundColor = prev;
                Console.Write($" {Truncate(f.Title, 45)}{perennial}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ({f.ModuleName})");
                Console.ForegroundColor = prev;

                Console.Write($"      {f.Occurrences} hits");
                Console.ForegroundColor = f.OccurrenceRate >= 80 ? ConsoleColor.Red : f.OccurrenceRate >= 50 ? ConsoleColor.Yellow : ConsoleColor.Gray;
                Console.Write($" · {f.OccurrenceRate}% of scans");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  → {f.SuggestedAction}");
                Console.ForegroundColor = prev;
            }
            Console.WriteLine();
        }

        // Top Noisy Modules
        if (result.TopNoisyModules.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Noisiest Modules ──────────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Module",-25} {"Category",-15} {"Total",7} {"Avg/Scan",10} {"Unique",8} {"Share",7}");
            Console.WriteLine($"  {new string('─', 25)} {new string('─', 15)} {new string('─', 7)} {new string('─', 10)} {new string('─', 8)} {new string('─', 7)}");
            Console.ForegroundColor = prev;

            foreach (var m in result.TopNoisyModules)
            {
                Console.Write($"  {Truncate(m.ModuleName, 25),-25} {Truncate(m.Category, 15),-15}");
                Console.Write($" {m.TotalFindings,7}");
                Console.Write($" {m.AvgFindingsPerScan,10:F1}");
                Console.Write($" {m.UniqueFindingTitles,8}");
                Console.ForegroundColor = m.NoiseShare >= 30 ? ConsoleColor.Red : m.NoiseShare >= 15 ? ConsoleColor.Yellow : ConsoleColor.Gray;
                Console.WriteLine($" {m.NoiseShare,6:F1}%");
                Console.ForegroundColor = prev;
            }
            Console.WriteLine();
        }

        // Stats summary
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Quick Stats ───────────────────────────────────────────");
        Console.ForegroundColor = prev;
        Console.WriteLine();
        Console.WriteLine($"  Perennial (100% of scans):   {result.Stats.PerennialFindings}");
        Console.WriteLine($"  High-frequency (>80%):       {result.Stats.HighFrequencyFindings}");
        Console.WriteLine($"  Low-frequency (<20%):        {result.Stats.LowFrequencyFindings}");

        if (result.Stats.EstimatedSuppressibleFindings > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  Estimated suppressible:      {result.Stats.EstimatedSuppressibleFindings}");
            Console.ForegroundColor = prev;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  💡 Use --ignore to suppress perennial/informational findings and reduce noise.");
            Console.ForegroundColor = prev;
        }

        Console.WriteLine();
    }

}
