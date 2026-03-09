using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>Print full root cause analysis report.</summary>
    public static void PrintRootCauseReport(RootCauseAnalyzer.RootCauseReport report)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🔍  Root Cause Analysis               ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Summary strip
        WriteColored("  Root Causes: ", ConsoleColor.White);
        WriteColored($"{report.RootCausesIdentified}", ConsoleColor.Yellow);
        WriteColored("  │  Findings Covered: ", ConsoleColor.White);
        WriteColored($"{report.FindingsCovered}/{report.TotalFindings}", ConsoleColor.Yellow);
        WriteColored($" ({report.CoveragePercent}%)", ConsoleColor.DarkGray);
        WriteColored("  │  Ungrouped: ", ConsoleColor.White);
        WriteLineColored($"{report.UngroupedFindings}", ConsoleColor.DarkGray);
        Console.WriteLine();

        if (report.RootCauses.Count == 0)
        {
            WriteLineColored("  ✓ No root cause clusters found — findings appear independent.", ConsoleColor.Green);
            return;
        }

        // Root causes detail
        for (int i = 0; i < report.RootCauses.Count; i++)
        {
            var rc = report.RootCauses[i];
            var sevColor = GetSeverityColor(rc.WorstSeverity);

            WriteColored($"  {i + 1}. ", ConsoleColor.White);
            WriteColored($"[{rc.WorstSeverity}] ", sevColor);
            WriteLineColored(rc.Name, ConsoleColor.White);

            WriteColored("     ", ConsoleColor.White);
            WriteLineColored(rc.Description, ConsoleColor.DarkGray);

            WriteColored("     Impact: ", ConsoleColor.Gray);
            WriteColored($"{rc.ImpactCount} findings", ConsoleColor.Yellow);
            WriteColored(" (score: ", ConsoleColor.DarkGray);
            WriteColored($"{rc.ImpactScore}", ConsoleColor.Yellow);
            WriteLineColored(")", ConsoleColor.DarkGray);

            WriteColored("     Fix: ", ConsoleColor.Gray);
            WriteLineColored(rc.SuggestedFix, ConsoleColor.Green);

            if (rc.FixCommand != null)
            {
                WriteColored("     Command: ", ConsoleColor.Gray);
                WriteLineColored(rc.FixCommand, ConsoleColor.DarkCyan);
            }

            // List affected findings
            WriteLineColored("     Affected findings:", ConsoleColor.Gray);
            foreach (var f in rc.Findings.Take(5))
            {
                var fColor = GetSeverityColor(f.Severity);
                WriteColored("       • ", ConsoleColor.DarkGray);
                WriteColored($"[{f.Severity}] ", fColor);
                WriteLineColored(f.Title, ConsoleColor.White);
            }
            if (rc.Findings.Count > 5)
            {
                WriteLineColored($"       ... and {rc.Findings.Count - 5} more", ConsoleColor.DarkGray);
            }

            Console.WriteLine();
        }

        // Top actions
        if (report.TopActions.Count > 0)
        {
            WriteLineColored("  ── Top Actions (fix these first) ──", ConsoleColor.Cyan);
            Console.WriteLine();
            foreach (var action in report.TopActions)
            {
                WriteColored("  → ", ConsoleColor.Yellow);
                WriteLineColored(action, ConsoleColor.White);
            }
            Console.WriteLine();
        }
    }

    /// <summary>Print only root cause names and impact.</summary>
    public static void PrintRootCauseSummary(RootCauseAnalyzer.RootCauseReport report, int top)
    {
        Console.WriteLine();
        WriteLineColored($"  Top {Math.Min(top, report.RootCauses.Count)} Root Causes by Impact:", ConsoleColor.Cyan);
        Console.WriteLine();

        foreach (var rc in report.RootCauses.Take(top))
        {
            var sevColor = GetSeverityColor(rc.WorstSeverity);
            WriteColored($"  [{rc.WorstSeverity}] ", sevColor);
            WriteColored(rc.Name.PadRight(35), ConsoleColor.White);
            WriteColored($" {rc.ImpactCount} findings", ConsoleColor.Yellow);
            WriteColored($" (score: {rc.ImpactScore})", ConsoleColor.DarkGray);
            Console.WriteLine();
        }
        Console.WriteLine();
    }

    /// <summary>Print ungrouped findings that don't belong to any root cause.</summary>
    public static void PrintUngroupedFindings(RootCauseAnalyzer.RootCauseReport report)
    {
        Console.WriteLine();
        WriteLineColored($"  Ungrouped Findings ({report.UngroupedFindings}):", ConsoleColor.Cyan);
        Console.WriteLine();

        if (report.Ungrouped.Count == 0)
        {
            WriteLineColored("  ✓ All findings are covered by root causes.", ConsoleColor.Green);
            return;
        }

        foreach (var f in report.Ungrouped)
        {
            var sevColor = GetSeverityColor(f.Severity);
            WriteColored("  • ", ConsoleColor.DarkGray);
            WriteColored($"[{f.Severity}] ", sevColor);
            WriteColored(f.Title, ConsoleColor.White);
            WriteColored($" ({f.Category})", ConsoleColor.DarkGray);
            Console.WriteLine();
        }
        Console.WriteLine();
    }

    private static ConsoleColor GetSeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.Warning => ConsoleColor.Yellow,
        Severity.Info => ConsoleColor.Cyan,
        _ => ConsoleColor.Green
    };
}
