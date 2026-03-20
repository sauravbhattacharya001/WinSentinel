using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a cross-framework compliance summary table.
    /// </summary>
    public static void PrintCrossFrameworkSummary(CrossFrameworkSummary summary)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║               COMPLIANCE FRAMEWORK ANALYSIS                     ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Security Score: ");
        Console.ForegroundColor = summary.SecurityScore >= 80 ? ConsoleColor.Green
            : summary.SecurityScore >= 60 ? ConsoleColor.Yellow : ConsoleColor.Red;
        Console.WriteLine($"{summary.SecurityScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Header
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌──────────────────────────────────────┬───────────┬──────────────────────┬──────┬──────┬─────────┬─────┐");
        Console.WriteLine("  │ Framework                            │ Compliant │ Verdict              │ Pass │ Fail │ Partial │ N/A │");
        Console.WriteLine("  ├──────────────────────────────────────┼───────────┼──────────────────────┼──────┼──────┼─────────┼─────┤");
        Console.ForegroundColor = original;

        foreach (var fr in summary.FrameworkResults)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{fr.FrameworkName,-36}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");

            Console.ForegroundColor = fr.CompliancePercentage >= 80 ? ConsoleColor.Green
                : fr.CompliancePercentage >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
            Console.Write($"{fr.CompliancePercentage,7:F1}%");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");

            Console.ForegroundColor = fr.Verdict == ComplianceVerdict.Compliant ? ConsoleColor.Green
                : fr.Verdict == ComplianceVerdict.PartiallyCompliant ? ConsoleColor.Yellow : ConsoleColor.Red;
            Console.Write($"{fr.Verdict,-20}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{fr.PassCount,4}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = fr.FailCount > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.Write($"{fr.FailCount,4}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = fr.PartialCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.Write($"{fr.PartialCount,7}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{fr.NotAssessedCount,3}");
            Console.WriteLine(" │");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └──────────────────────────────────────┴───────────┴──────────────────────┴──────┴──────┴─────────┴─────┘");
        Console.ForegroundColor = original;

        // Show critical gaps
        foreach (var fr in summary.FrameworkResults.Where(f => f.CriticalGaps.Count > 0))
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"  ⚠ Critical Gaps — {fr.FrameworkName}");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var gap in fr.CriticalGaps)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    • ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(gap);
            }
        }
        Console.ForegroundColor = original;
    }

    /// <summary>
    /// Print a detailed compliance report for a single framework.
    /// </summary>
    public static void PrintComplianceReport(ComplianceReport report, bool gapsOnly = false)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"  ── {report.FrameworkName}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($" (v{report.FrameworkVersion})");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($" ── ");

        Console.ForegroundColor = report.Summary.CompliancePercentage >= 80 ? ConsoleColor.Green
            : report.Summary.CompliancePercentage >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
        Console.Write($"{report.Summary.CompliancePercentage}%");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(" compliant — ");
        Console.ForegroundColor = report.Summary.OverallVerdict == ComplianceVerdict.Compliant ? ConsoleColor.Green
            : report.Summary.OverallVerdict == ComplianceVerdict.PartiallyCompliant ? ConsoleColor.Yellow : ConsoleColor.Red;
        Console.WriteLine(report.Summary.OverallVerdict);
        Console.ForegroundColor = original;
        Console.WriteLine();

        var controls = gapsOnly
            ? report.Controls.Where(c => c.Status != ControlStatus.Pass).ToList()
            : report.Controls;

        if (gapsOnly && controls.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("    ✓ No gaps found — all assessed controls pass!");
            Console.ForegroundColor = original;
            return;
        }

        foreach (var ctrl in controls)
        {
            var (icon, color) = ctrl.Status switch
            {
                ControlStatus.Pass => ("✓", ConsoleColor.Green),
                ControlStatus.Fail => ("✗", ConsoleColor.Red),
                ControlStatus.Partial => ("◐", ConsoleColor.Yellow),
                _ => ("○", ConsoleColor.DarkGray)
            };

            Console.ForegroundColor = color;
            Console.Write($"    {icon} ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"[{ctrl.ControlId}] ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write(ctrl.ControlTitle);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  — ");
            Console.ForegroundColor = color;
            Console.WriteLine(ctrl.Status);

            if (ctrl.Remediation.Count > 0 && ctrl.Status != ControlStatus.Pass)
            {
                foreach (var rem in ctrl.Remediation.Take(2))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("      Fix: ");
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine(rem);
                }
            }
        }

        Console.ForegroundColor = original;
        Console.WriteLine();

        // Summary bar
        var total = report.Summary.TotalControls;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("    Summary: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{report.Summary.PassCount} pass");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(" · ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{report.Summary.FailCount} fail");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(" · ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{report.Summary.PartialCount} partial");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(" · ");
        Console.Write($"{report.Summary.NotAssessedCount} n/a");
        Console.Write($" (of {total} controls)");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
