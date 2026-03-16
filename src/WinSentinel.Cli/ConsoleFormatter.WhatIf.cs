using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print what-if simulation results showing before/after score projections.
    /// </summary>
    public static void PrintWhatIfResult(WhatIfSimulator.SimulationResult result, string scenario)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  ╔══════════════════════════════════════════════════╗");
        Console.WriteLine($"  ║          WHAT-IF SIMULATION RESULTS             ║");
        Console.WriteLine($"  ╚══════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Scenario: {scenario}");
        Console.ResetColor();
        Console.WriteLine();

        // Score comparison
        Console.Write("  Current Score:   ");
        PrintColoredScore(result.CurrentScore);
        Console.Write($" ({result.CurrentGrade})");
        Console.WriteLine();

        Console.Write("  Projected Score: ");
        PrintColoredScore(result.ProjectedScore);
        Console.Write($" ({result.ProjectedGrade})");
        if (result.ScoreDelta > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"  ▲ +{result.ScoreDelta}");
        }
        else if (result.ScoreDelta == 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  — no change");
        }
        Console.ResetColor();
        Console.WriteLine();

        if (result.GradeImproved)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ★ Grade upgrade: {result.CurrentGrade} → {result.ProjectedGrade}");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Summary
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Findings resolved: {result.ResolvedFindings.Count}");
        Console.ResetColor();
        if (result.CriticalResolved > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"    Critical: {result.CriticalResolved} (×20 pts each)");
            Console.ResetColor();
        }
        if (result.WarningResolved > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"    Warning:  {result.WarningResolved} (×5 pts each)");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Module impact table
        if (result.ModuleImpacts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Module Impact Breakdown:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();

            foreach (var impact in result.ModuleImpacts)
            {
                Console.Write($"    {impact.Module,-30} ");
                PrintColoredScore(impact.ScoreBefore);
                Console.Write(" → ");
                PrintColoredScore(impact.ScoreAfter);
                if (impact.Delta > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"  (+{impact.Delta})");
                }
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{impact.FindingsResolved} fixed]");
                Console.ResetColor();
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Resolved findings list
        if (result.ResolvedFindings.Count > 0 && result.ResolvedFindings.Count <= 30)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Simulated Fixes:");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();

            int n = 1;
            foreach (var f in result.ResolvedFindings.OrderByDescending(r => r.PointsRecovered))
            {
                var sevColor = f.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
                var sevLabel = f.Severity == Severity.Critical ? "CRT" : "WRN";
                Console.Write($"    {n,3}. ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{sevLabel}]");
                Console.ResetColor();
                Console.Write($" {f.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" ({f.Module}, +{f.PointsRecovered} pts)");
                Console.ResetColor();
                Console.WriteLine();
                n++;
            }
            Console.WriteLine();
        }
        else if (result.ResolvedFindings.Count > 30)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  ({result.ResolvedFindings.Count} findings resolved — showing top 20)");
            Console.ResetColor();
            int n = 1;
            foreach (var f in result.ResolvedFindings.OrderByDescending(r => r.PointsRecovered).Take(20))
            {
                var sevColor = f.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
                var sevLabel = f.Severity == Severity.Critical ? "CRT" : "WRN";
                Console.Write($"    {n,3}. ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{sevLabel}]");
                Console.ResetColor();
                Console.Write($" {f.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" ({f.Module}, +{f.PointsRecovered} pts)");
                Console.ResetColor();
                Console.WriteLine();
                n++;
            }
            Console.WriteLine();
        }
    }

    private static void PrintColoredScore(int score)
    {
        Console.ForegroundColor = score switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.Yellow,
            >= 40 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };
        Console.Write($"{score,3}");
        Console.ResetColor();
    }
}
