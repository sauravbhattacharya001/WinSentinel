using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PeerBenchmarkService;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a colorful peer benchmark comparison result to the console.
    /// </summary>
    public static void PrintBenchmarkResult(BenchmarkResult result)
    {
        var prev = Console.ForegroundColor;

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine($"║  PEER BENCHMARK — {result.Group.ToString().ToUpper()} GROUP{new string(' ', Math.Max(0, 40 - result.Group.ToString().Length))}║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = prev;
        Console.WriteLine();

        // Overall summary
        Console.Write("  Overall Score:  ");
        Console.ForegroundColor = ScoreColor(result.SystemOverallScore);
        Console.Write($"{result.SystemOverallScore}/100");
        Console.ForegroundColor = prev;
        Console.Write($"  (Peer median: {result.PeerOverallMedian})");
        Console.WriteLine();

        Console.Write("  Percentile:     ");
        Console.ForegroundColor = PercentileColor(result.OverallPercentile);
        Console.Write($"{result.OverallPercentile:F0}th");
        Console.ForegroundColor = prev;
        Console.Write($"  ({result.OverallRating})");
        Console.WriteLine();

        Console.Write("  Categories:     ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{result.CategoriesAbovePeer} above");
        Console.ForegroundColor = prev;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{result.CategoriesAtPeer} at");
        Console.ForegroundColor = prev;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{result.CategoriesBelowPeer} below");
        Console.ForegroundColor = prev;
        Console.WriteLine(" peer");
        Console.WriteLine();

        // Category comparison table
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌──────────────────────┬───────┬────────┬──────────┬────────────────────┐");
        Console.ForegroundColor = prev;
        Console.Write("  │ ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Category             ");
        Console.ForegroundColor = prev;
        Console.Write("│ ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Score");
        Console.ForegroundColor = prev;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Median");
        Console.ForegroundColor = prev;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Pctile   ");
        Console.ForegroundColor = prev;
        Console.Write("│ ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Rating             ");
        Console.ForegroundColor = prev;
        Console.WriteLine("│");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ├──────────────────────┼───────┼────────┼──────────┼────────────────────┤");
        Console.ForegroundColor = prev;

        foreach (var cat in result.Categories)
        {
            var catName = cat.Category.Length > 20 ? cat.Category[..20] : cat.Category.PadRight(20);
            Console.Write($"  │ {catName} │ ");

            Console.ForegroundColor = ScoreColor(cat.SystemScore);
            Console.Write($"{cat.SystemScore,3}  ");
            Console.ForegroundColor = prev;
            Console.Write($"│  {cat.PeerMedian,3}  │ ");

            Console.ForegroundColor = PercentileColor(cat.Percentile);
            Console.Write($"{cat.Percentile,5:F0}th  ");
            Console.ForegroundColor = prev;
            Console.Write("│ ");

            var (ratingText, ratingColor) = RatingDisplay(cat.Rating, cat.Delta);
            Console.ForegroundColor = ratingColor;
            Console.Write(ratingText.PadRight(19));
            Console.ForegroundColor = prev;
            Console.WriteLine("│");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └──────────────────────┴───────┴────────┴──────────┴────────────────────┘");
        Console.ForegroundColor = prev;
        Console.WriteLine();

        // Strengths
        if (result.TopStrengths.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ★ Top Strengths");
            Console.ForegroundColor = prev;
            foreach (var s in result.TopStrengths)
            {
                Console.Write("    ✓ ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(s.Category);
                Console.ForegroundColor = prev;
                Console.WriteLine($": {s.SystemScore} vs {s.PeerMedian} median (+{s.Delta})");
            }
            Console.WriteLine();
        }

        // Weaknesses
        if (result.TopWeaknesses.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ▼ Areas to Improve");
            Console.ForegroundColor = prev;
            foreach (var w in result.TopWeaknesses)
            {
                Console.Write("    ✗ ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write(w.Category);
                Console.ForegroundColor = prev;
                Console.WriteLine($": {w.SystemScore} vs {w.PeerMedian} median ({w.Delta})");
            }
            Console.WriteLine();
        }

        // Improvement suggestions
        if (result.Suggestions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  💡 Improvement Suggestions");
            Console.ForegroundColor = prev;
            foreach (var sug in result.Suggestions.Take(8))
            {
                var priorityColor = sug.Priority switch
                {
                    PeerBenchmarkService.ImprovementPriority.Critical => ConsoleColor.Red,
                    PeerBenchmarkService.ImprovementPriority.High => ConsoleColor.DarkYellow,
                    PeerBenchmarkService.ImprovementPriority.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                Console.Write("    ");
                Console.ForegroundColor = priorityColor;
                Console.Write($"[{sug.Priority}]");
                Console.ForegroundColor = prev;
                Console.WriteLine($" {sug.Category} (gap: {sug.Gap} pts)");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"          {sug.Recommendation}");
                Console.ForegroundColor = prev;
            }
        }
    }

    private static ConsoleColor ScoreColor(int score) => score switch
    {
        >= 80 => ConsoleColor.Green,
        >= 60 => ConsoleColor.Yellow,
        >= 40 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };

    private static ConsoleColor PercentileColor(double pctile) => pctile switch
    {
        >= 75 => ConsoleColor.Green,
        >= 50 => ConsoleColor.Yellow,
        >= 25 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };

    private static (string text, ConsoleColor color) RatingDisplay(ComparisonRating rating, int delta)
    {
        return rating switch
        {
            ComparisonRating.WellAbovePeer => ($"▲▲ Well Above (+{delta})", ConsoleColor.Green),
            ComparisonRating.AbovePeer => ($"▲  Above (+{delta})", ConsoleColor.Green),
            ComparisonRating.AtPeer => ($"●  At Peer ({delta:+0;-0;0})", ConsoleColor.Yellow),
            ComparisonRating.BelowPeer => ($"▼  Below ({delta})", ConsoleColor.Red),
            ComparisonRating.WellBelowPeer => ($"▼▼ Well Below ({delta})", ConsoleColor.Red),
            _ => ("?", ConsoleColor.Gray)
        };
    }
}
