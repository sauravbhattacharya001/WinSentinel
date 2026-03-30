using System.Diagnostics;
using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintCluster(
        List<FindingCluster> clusters,
        int totalFindings,
        double threshold,
        TimeSpan elapsed)
    {
        var original = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║           🔗  Finding Clusters Report               ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Total findings: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(totalFindings);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Clusters found: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(clusters.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Similarity threshold: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{threshold:F1}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        if (clusters.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No clusters found — all findings are unique.");
            Console.ForegroundColor = original;
            Console.WriteLine();
            return;
        }

        for (int i = 0; i < clusters.Count; i++)
        {
            var cluster = clusters[i];
            var sevColor = cluster.HighestSeverity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.Warning => ConsoleColor.Yellow,
                Severity.Info => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  ┌─ Cluster {i + 1}: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(ClusterTruncate(cluster.Label, 50));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = sevColor;
            Console.Write(cluster.HighestSeverity);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" │ {cluster.Items.Count} findings");
            Console.WriteLine();

            var modules = cluster.Modules.Distinct().ToList();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │  Modules: ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(string.Join(", ", modules));

            var hasAutoFix = cluster.Items.Any(it => !string.IsNullOrEmpty(it.Finding.FixCommand));
            if (hasAutoFix)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  │  ⚡ Some findings have auto-fix available");
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │");
            Console.WriteLine();

            foreach (var item in cluster.Items.Take(8))
            {
                var itemSevColor = item.Finding.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.Warning => ConsoleColor.Yellow,
                    Severity.Info => ConsoleColor.Cyan,
                    _ => ConsoleColor.Gray
                };

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  │  ");
                Console.ForegroundColor = itemSevColor;
                Console.Write($"[{item.Finding.Severity,-8}] ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(ClusterTruncate(item.Finding.Title, 45));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  ({item.Module})");
                Console.WriteLine();
            }

            if (cluster.Items.Count > 8)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  │  ... and {cluster.Items.Count - 8} more");
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └───────────────────────────────────────────");
            Console.WriteLine();
        }

        var clusteredCount = clusters.Sum(c => c.Items.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  💡 ");
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($"{clusteredCount} findings grouped into {clusters.Count} clusters. ");
        Console.WriteLine("Fix one, and similar findings may resolve together.");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Completed in {elapsed.TotalSeconds:F1}s");
        Console.ForegroundColor = original;
    }

    private static string ClusterTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text[..(maxLen - 1)] + "…";
    }
}
