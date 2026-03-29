using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a colorful finding dependency graph report to the console.
    /// </summary>
    public static void PrintDepGraph(FindingDependencyResult result, CliOptions options)
    {
        if (options.Quiet) return;

        var prev = Console.ForegroundColor;

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║  🔗 FINDING DEPENDENCY GRAPH                                ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = prev;
        Console.WriteLine();

        // Overview
        Console.WriteLine($"  Total Findings Analyzed:  {result.TotalFindings}");
        Console.WriteLine($"  Root Causes Found:       {result.RootFindings}");
        Console.Write($"  Cascade-Resolvable:      ");
        Console.ForegroundColor = result.EstimatedAutoResolve > 0 ? ConsoleColor.Green : ConsoleColor.Gray;
        Console.WriteLine($"{result.EstimatedAutoResolve}");
        Console.ForegroundColor = prev;
        Console.WriteLine($"  Max Cascade Depth:       {result.MaxCascadeDepth}");
        Console.WriteLine();

        // Top Cascade Impacts
        if (result.TopCascadeImpacts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Top Cascade Impacts (fix these first!) ────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            for (int i = 0; i < result.TopCascadeImpacts.Count; i++)
            {
                var impact = result.TopCascadeImpacts[i];
                var sevColor = impact.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
                var fixIcon = impact.HasAutoFix ? " 🔧" : "";

                Console.Write($"  {i + 1,2}. ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{impact.Severity}]");
                Console.ForegroundColor = prev;
                Console.Write($" {Truncate(impact.Title, 40)}{fixIcon}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ({impact.Module})");
                Console.ForegroundColor = prev;

                Console.Write($"      Fixes ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{impact.CascadeCount} dependent findings");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  · est. +{impact.ScoreImpact:F1} pts");
                Console.ForegroundColor = prev;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Dependency Clusters (detailed)
        if (result.Clusters.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Dependency Clusters ───────────────────────────────────");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            var displayClusters = result.Clusters.Take(options.DepGraphTop);

            foreach (var cluster in displayClusters)
            {
                var rootColor = cluster.RootSeverity == Severity.Critical
                    ? ConsoleColor.Red : ConsoleColor.Yellow;

                Console.Write("  ┌─ ");
                Console.ForegroundColor = rootColor;
                Console.Write($"[{cluster.RootSeverity}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {Truncate(cluster.RootTitle, 45)}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ({cluster.RootModule})");
                Console.ForegroundColor = prev;

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  │  ");
                Console.WriteLine($"Relationship: {cluster.RelationshipType}");
                Console.ForegroundColor = prev;

                for (int j = 0; j < cluster.Dependents.Count; j++)
                {
                    var dep = cluster.Dependents[j];
                    var isLast = j == cluster.Dependents.Count - 1;
                    var connector = isLast ? "└──" : "├──";

                    var depColor = dep.Severity == Severity.Critical
                        ? ConsoleColor.Red : ConsoleColor.Yellow;

                    Console.Write($"  {connector} ");
                    Console.ForegroundColor = depColor;
                    Console.Write($"[{dep.Severity}]");
                    Console.ForegroundColor = prev;
                    Console.Write($" {Truncate(dep.Title, 40)}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  ({dep.Module})");
                    Console.ForegroundColor = prev;

                    if (!string.IsNullOrEmpty(dep.Reason))
                    {
                        var indent = isLast ? "     " : "│    ";
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"  {indent}↳ {dep.Reason}");
                        Console.ForegroundColor = prev;
                    }
                }
                Console.WriteLine();
            }

            if (result.Clusters.Count > options.DepGraphTop)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ... and {result.Clusters.Count - options.DepGraphTop} more clusters. Use --depgraph-top to show more.");
                Console.ForegroundColor = prev;
                Console.WriteLine();
            }
        }

        // Summary advice
        if (result.EstimatedAutoResolve > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  💡 Fix {result.RootFindings} root causes to potentially resolve {result.EstimatedAutoResolve} additional findings.");
            Console.ForegroundColor = prev;

            var autoFixRoots = result.TopCascadeImpacts.Count(i => i.HasAutoFix);
            if (autoFixRoots > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"     {autoFixRoots} root cause(s) have auto-fix available. Use --harden to generate fix scripts.");
                Console.ForegroundColor = prev;
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  No dependency relationships found between current findings.");
            Console.ForegroundColor = prev;
        }

        Console.WriteLine();
    }
}
