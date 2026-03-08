using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PeerBenchmarkService;

namespace WinSentinel.Cli;

/// <summary>
/// Console formatting methods for peer benchmark comparison reports.
/// </summary>
public static partial class ConsoleFormatter
{
    /// <summary>Print a single peer group benchmark result.</summary>
    public static void PrintBenchmarkResult(BenchmarkResult result, bool quiet = false)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║     📊  Peer Benchmark Comparison           ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Header: group and overall comparison
        Console.Write("  Peer Group:   ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(result.Group);
        Console.ForegroundColor = orig;

        Console.Write("  Your Score:   ");
        var scoreColor = result.SystemOverallScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.Yellow,
            >= 40 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };
        Console.ForegroundColor = scoreColor;
        Console.Write($"{result.SystemOverallScore}/100");
        Console.ForegroundColor = orig;
        Console.Write("  |  Peer Median: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{result.PeerOverallMedian}/100");
        Console.ForegroundColor = orig;

        Console.Write("  Percentile:   ");
        var percColor = result.OverallPercentile switch
        {
            >= 75 => ConsoleColor.Green,
            >= 50 => ConsoleColor.Yellow,
            >= 25 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };
        Console.ForegroundColor = percColor;
        Console.Write($"{result.OverallPercentile:F0}th");
        Console.ForegroundColor = orig;
        Console.Write("  (");
        Console.ForegroundColor = percColor;
        Console.Write(result.OverallRating);
        Console.ForegroundColor = orig;
        Console.WriteLine(")");

        Console.Write("  Categories:   ");
        if (result.CategoriesAbovePeer > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{result.CategoriesAbovePeer} above");
        }
        Console.ForegroundColor = orig;
        Console.Write("  |  ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{result.CategoriesAtPeer} at");
        Console.ForegroundColor = orig;
        Console.Write("  |  ");
        if (result.CategoriesBelowPeer > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"{result.CategoriesBelowPeer} below");
        }
        else
        {
            Console.Write("0 below");
        }
        Console.ForegroundColor = orig;
        Console.WriteLine(" peer");
        Console.WriteLine();

        if (!quiet)
        {
            // Strengths
            if (result.TopStrengths.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  STRENGTHS (above peers)");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  ──────────────────────────────────────────");
                Console.ForegroundColor = orig;

                foreach (var s in result.TopStrengths)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"  + {s.Category,-20}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"{s.SystemScore,4}");
                    Console.ForegroundColor = orig;
                    Console.Write($" vs {s.PeerMedian,3} median  ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"(+{s.Delta})");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  {s.Percentile:F0}th pctl");
                    Console.ForegroundColor = orig;
                }
                Console.WriteLine();
            }

            // Weaknesses
            if (result.TopWeaknesses.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  WEAKNESSES (below peers)");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  ──────────────────────────────────────────");
                Console.ForegroundColor = orig;

                foreach (var w in result.TopWeaknesses)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"  - {w.Category,-20}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"{w.SystemScore,4}");
                    Console.ForegroundColor = orig;
                    Console.Write($" vs {w.PeerMedian,3} median  ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"({w.Delta})");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  {w.Percentile:F0}th pctl");
                    Console.ForegroundColor = orig;
                }
                Console.WriteLine();
            }

            // Category table
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ALL CATEGORIES");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Category",-20} {"Score",5} {"Median",7} {"P25",5} {"P75",5} {"Delta",6} {"Pctl",5}  Rating");
            Console.ForegroundColor = orig;

            foreach (var c in result.Categories)
            {
                var ratingColor = c.Rating switch
                {
                    ComparisonRating.WellAbovePeer => ConsoleColor.Green,
                    ComparisonRating.AbovePeer => ConsoleColor.Green,
                    ComparisonRating.AtPeer => ConsoleColor.White,
                    ComparisonRating.BelowPeer => ConsoleColor.Yellow,
                    ComparisonRating.WellBelowPeer => ConsoleColor.Red,
                    _ => orig
                };

                Console.Write($"  {c.Category,-20}");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{c.SystemScore,5}");
                Console.ForegroundColor = orig;
                Console.Write($"{c.PeerMedian,7}{c.PeerP25,5}{c.PeerP75,5}");

                Console.ForegroundColor = ratingColor;
                var deltaStr = c.Delta >= 0 ? $"+{c.Delta}" : c.Delta.ToString();
                Console.Write($"{deltaStr,6}");
                Console.ForegroundColor = orig;
                Console.Write($"{c.Percentile,5:F0}");
                Console.Write("  ");
                Console.ForegroundColor = ratingColor;
                Console.WriteLine(FormatRating(c.Rating));
                Console.ForegroundColor = orig;
            }
            Console.WriteLine();

            // Suggestions
            if (result.Suggestions.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  IMPROVEMENT SUGGESTIONS");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  ──────────────────────────────────────────");
                Console.ForegroundColor = orig;

                foreach (var sug in result.Suggestions.Take(10))
                {
                    var prioColor = sug.Priority switch
                    {
                        ImprovementPriority.Critical => ConsoleColor.Red,
                        ImprovementPriority.High => ConsoleColor.DarkYellow,
                        ImprovementPriority.Medium => ConsoleColor.Yellow,
                        _ => ConsoleColor.Gray
                    };

                    Console.ForegroundColor = prioColor;
                    Console.Write($"  [{sug.Priority}] ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"{sug.Category}");
                    Console.ForegroundColor = orig;
                    Console.WriteLine($" (gap: {sug.Gap} pts)");
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"    → {sug.Recommendation}");
                    Console.ForegroundColor = orig;
                }
                Console.WriteLine();
            }
        }
    }

    /// <summary>Print a summary comparison across all peer groups.</summary>
    public static void PrintBenchmarkAllResults(Dictionary<PeerGroup, BenchmarkResult> results, bool quiet = false)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║     📊  Peer Benchmark — All Groups         ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Peer Group",-14} {"Score",5} {"Median",7} {"Pctl",6}  {"Above",6} {"At",4} {"Below",6}  Rating");
        Console.WriteLine($"  {"──────────────",-14} {"─────",5} {"───────",7} {"──────",6}  {"──────",6} {"────",4} {"──────",6}  ────────────────────────");
        Console.ForegroundColor = orig;

        foreach (var (group, result) in results.OrderBy(kv => kv.Key))
        {
            var percColor = result.OverallPercentile switch
            {
                >= 75 => ConsoleColor.Green,
                >= 50 => ConsoleColor.Yellow,
                >= 25 => ConsoleColor.DarkYellow,
                _ => ConsoleColor.Red
            };

            Console.Write($"  {group,-14}");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{result.SystemOverallScore,5}");
            Console.ForegroundColor = orig;
            Console.Write($"{result.PeerOverallMedian,7}");
            Console.ForegroundColor = percColor;
            Console.Write($"{result.OverallPercentile,5:F0}th");
            Console.ForegroundColor = orig;
            Console.Write($"  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{result.CategoriesAbovePeer,6}");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{result.CategoriesAtPeer,4}");
            Console.ForegroundColor = result.CategoriesBelowPeer > 0 ? ConsoleColor.Red : orig;
            Console.Write($"{result.CategoriesBelowPeer,6}");
            Console.ForegroundColor = orig;
            Console.Write("  ");
            Console.ForegroundColor = percColor;
            Console.WriteLine(result.OverallRating);
            Console.ForegroundColor = orig;
        }

        Console.WriteLine();

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Tip: Run 'winsentinel --benchmark <group>' for detailed comparison.");
            Console.WriteLine("       Run 'winsentinel --benchmark suggest' to find your best-fit group.");
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }
    }

    private static string FormatRating(ComparisonRating rating) => rating switch
    {
        ComparisonRating.WellAbovePeer => "Well Above",
        ComparisonRating.AbovePeer => "Above",
        ComparisonRating.AtPeer => "At Peer",
        ComparisonRating.BelowPeer => "Below",
        ComparisonRating.WellBelowPeer => "Well Below",
        _ => rating.ToString()
    };
}
