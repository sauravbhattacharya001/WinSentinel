using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PeerBenchmarkService;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintBenchmarkResult(BenchmarkResult result)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored($"  ║    📊 Peer Benchmark: {result.Group,-12}            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Overall comparison
        WriteLineColored("  OVERALL", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);

        Console.Write("  Your Score:     ");
        WriteLineColored($"{result.SystemOverallScore}/100", GetBenchmarkScoreColor(result.SystemOverallScore));

        Console.Write("  Peer Median:    ");
        WriteLineColored($"{result.PeerOverallMedian}/100", ConsoleColor.White);

        var delta = result.SystemOverallScore - result.PeerOverallMedian;
        Console.Write("  Delta:          ");
        if (delta > 0)
            WriteLineColored($"+{delta} points above peers", ConsoleColor.Green);
        else if (delta < 0)
            WriteLineColored($"{delta} points below peers", ConsoleColor.Red);
        else
            WriteLineColored("At peer median", ConsoleColor.DarkGray);

        Console.Write("  Percentile:     ");
        WriteLineColored($"{result.OverallPercentile:F0}th ({result.OverallRating})", ConsoleColor.White);

        Console.Write("  Categories:     ");
        if (result.CategoriesAbovePeer > 0)
            WriteColored($"{result.CategoriesAbovePeer} above", ConsoleColor.Green);
        else
            WriteColored("0 above", ConsoleColor.DarkGray);
        Console.Write(" │ ");
        WriteColored($"{result.CategoriesAtPeer} at", ConsoleColor.White);
        Console.Write(" │ ");
        if (result.CategoriesBelowPeer > 0)
            WriteLineColored($"{result.CategoriesBelowPeer} below", ConsoleColor.Red);
        else
            WriteLineColored("0 below", ConsoleColor.DarkGray);

        Console.WriteLine();

        // Top Strengths
        if (result.TopStrengths.Count > 0)
        {
            WriteLineColored("  STRENGTHS (above peers)", ConsoleColor.Green);
            WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
            foreach (var s in result.TopStrengths)
            {
                Console.Write("  + ");
                WriteColored($"{s.Category,-20}", ConsoleColor.White);
                WriteColored($"{s.SystemScore}", GetBenchmarkScoreColor(s.SystemScore));
                Console.Write(" vs ");
                WriteColored($"{s.PeerMedian}", ConsoleColor.DarkGray);
                Console.Write(" median  ");
                WriteLineColored($"(+{s.Delta})", ConsoleColor.Green);
            }
            Console.WriteLine();
        }

        // Top Weaknesses
        if (result.TopWeaknesses.Count > 0)
        {
            WriteLineColored("  WEAKNESSES (below peers)", ConsoleColor.Red);
            WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
            foreach (var w in result.TopWeaknesses)
            {
                Console.Write("  - ");
                WriteColored($"{w.Category,-20}", ConsoleColor.White);
                WriteColored($"{w.SystemScore}", GetBenchmarkScoreColor(w.SystemScore));
                Console.Write(" vs ");
                WriteColored($"{w.PeerMedian}", ConsoleColor.DarkGray);
                Console.Write(" median  ");
                WriteLineColored($"({w.Delta})", ConsoleColor.Red);
            }
            Console.WriteLine();
        }

        // Category breakdown table
        WriteLineColored("  CATEGORY BREAKDOWN", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────────────────────────────", ConsoleColor.DarkGray);
        WriteColored("  Category             Score  Median  Delta  Pctl   Rating", ConsoleColor.DarkGray);
        Console.WriteLine();

        foreach (var c in result.Categories)
        {
            Console.Write($"  {c.Category,-20} ");
            WriteColored($"{c.SystemScore,5}", GetBenchmarkScoreColor(c.SystemScore));
            Console.Write($"  {c.PeerMedian,6}  ");

            if (c.Delta >= 0)
                WriteColored($"{("+" + c.Delta),5}", ConsoleColor.Green);
            else
                WriteColored($"{c.Delta,5}", ConsoleColor.Red);

            Console.Write($"  {c.Percentile,3:F0}%  ");

            var ratingColor = c.Rating switch
            {
                ComparisonRating.WellAbovePeer => ConsoleColor.Green,
                ComparisonRating.AbovePeer => ConsoleColor.Green,
                ComparisonRating.AtPeer => ConsoleColor.White,
                ComparisonRating.BelowPeer => ConsoleColor.Yellow,
                ComparisonRating.WellBelowPeer => ConsoleColor.Red,
                _ => ConsoleColor.Gray
            };
            var ratingText = c.Rating switch
            {
                ComparisonRating.WellAbovePeer => "★★ Well Above",
                ComparisonRating.AbovePeer => "★  Above",
                ComparisonRating.AtPeer => "•  At Peer",
                ComparisonRating.BelowPeer => "▽  Below",
                ComparisonRating.WellBelowPeer => "▼▼ Well Below",
                _ => "?"
            };
            WriteLineColored($" {ratingText}", ratingColor);
        }
        Console.WriteLine();

        // Improvement suggestions
        if (result.Suggestions.Count > 0)
        {
            WriteLineColored("  IMPROVEMENT SUGGESTIONS", ConsoleColor.White);
            WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);

            var displayed = result.Suggestions.Take(10).ToList();
            for (int i = 0; i < displayed.Count; i++)
            {
                var s = displayed[i];
                var priorityColor = s.Priority switch
                {
                    ImprovementPriority.Critical => ConsoleColor.Red,
                    ImprovementPriority.High => ConsoleColor.Yellow,
                    ImprovementPriority.Medium => ConsoleColor.Cyan,
                    ImprovementPriority.Low => ConsoleColor.DarkGray,
                    _ => ConsoleColor.Gray
                };
                Console.Write($"  {i + 1,2}. ");
                WriteColored($"[{s.Priority}]", priorityColor);
                Console.Write($" {s.Category}: ");
                WriteLineColored(s.Recommendation, ConsoleColor.White);
                WriteLineColored($"       Gap: {s.Gap} pts (you: {s.CurrentScore}, peers: {s.PeerMedian})", ConsoleColor.DarkGray);
            }

            if (result.Suggestions.Count > 10)
            {
                WriteLineColored($"  ... and {result.Suggestions.Count - 10} more", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }
    }

    public static void PrintBenchmarkAllSummary(Dictionary<PeerGroup, BenchmarkResult> results)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║    📊 Peer Benchmark: All Groups            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        WriteLineColored("  Group          Score  Median  Delta  Percentile  Rating", ConsoleColor.DarkGray);
        WriteLineColored("  ─────────────────────────────────────────────────────────────", ConsoleColor.DarkGray);

        foreach (var (group, result) in results.OrderBy(kv => kv.Key))
        {
            Console.Write($"  {group,-14} ");
            WriteColored($"{result.SystemOverallScore,5}", GetBenchmarkScoreColor(result.SystemOverallScore));
            Console.Write($"  {result.PeerOverallMedian,6}  ");

            var d = result.SystemOverallScore - result.PeerOverallMedian;
            if (d >= 0)
                WriteColored($"{("+" + d),5}", ConsoleColor.Green);
            else
                WriteColored($"{d,5}", ConsoleColor.Red);

            Console.Write($"  {result.OverallPercentile,8:F0}th  ");
            WriteLineColored(result.OverallRating, ConsoleColor.White);
        }

        Console.WriteLine();

        WriteLineColored("  Tip: Run --benchmark <group> for detailed category breakdown.", ConsoleColor.DarkGray);
        Console.WriteLine();
    }

    private static ConsoleColor GetBenchmarkScoreColor(int score) => score switch
    {
        >= 80 => ConsoleColor.Green,
        >= 60 => ConsoleColor.Yellow,
        _ => ConsoleColor.Red
    };
}
