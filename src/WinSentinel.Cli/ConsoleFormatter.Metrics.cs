using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Console formatting for security metrics output.
/// </summary>
public static partial class ConsoleFormatter
{
    public static void PrintMetricsReport(SecurityMetricsAggregator.MetricsReport report)
    {
        if (report.RunsAnalyzed == 0)
        {
            PrintWarning("No audit history found. Run some audits first.");
            return;
        }

        WriteLineColored("", ConsoleColor.Cyan);
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       Security Metrics Dashboard            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Health grade
        var gradeColor = report.HealthGrade switch
        {
            "A" => ConsoleColor.Green,
            "B" => ConsoleColor.Green,
            "C" => ConsoleColor.Yellow,
            "D" => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };

        WriteColored("  Health Grade: ", ConsoleColor.White);
        WriteColored(report.HealthGrade, gradeColor);
        WriteLineColored($" ({report.HealthScore:F1}/100)", ConsoleColor.Gray);
        Console.WriteLine();

        // Analysis period
        WriteLineColored($"  Analyzed {report.RunsAnalyzed} runs over {report.AnalysisPeriod.TotalDays:F0} days", ConsoleColor.Gray);
        if (report.FirstRun.HasValue)
            WriteLineColored($"  Period: {report.FirstRun.Value:yyyy-MM-dd} → {report.LastRun!.Value:yyyy-MM-dd}", ConsoleColor.Gray);
        Console.WriteLine();

        // KPIs
        WriteLineColored("  ── Key Performance Indicators ──────────────────", ConsoleColor.Cyan);
        Console.WriteLine();

        PrintKpiRow("MTTR (Mean Time to Resolve)", FormatDuration(report.MttrHours),
            report.MttrHours <= 24 ? ConsoleColor.Green : report.MttrHours <= 72 ? ConsoleColor.Yellow : ConsoleColor.Red);
        PrintKpiRow("MTTD (Mean Time to Detect)", FormatDuration(report.MttdHours),
            report.MttdHours <= 24 ? ConsoleColor.Green : report.MttdHours <= 48 ? ConsoleColor.Yellow : ConsoleColor.Red);
        PrintKpiRow("Finding Velocity", $"{report.FindingVelocityPerDay:F2}/day introduced", ConsoleColor.White);
        PrintKpiRow("Resolution Velocity", $"{report.ResolutionVelocityPerDay:F2}/day resolved", ConsoleColor.White);
        PrintKpiRow("Resolution Efficiency", $"{report.ResolutionEfficiency:P1}",
            report.ResolutionEfficiency >= 1.0 ? ConsoleColor.Green : report.ResolutionEfficiency >= 0.8 ? ConsoleColor.Yellow : ConsoleColor.Red);
        PrintKpiRow("Recurrence Rate", $"{report.RecurrenceRatePercent:F1}%",
            report.RecurrenceRatePercent <= 10 ? ConsoleColor.Green : report.RecurrenceRatePercent <= 25 ? ConsoleColor.Yellow : ConsoleColor.Red);
        Console.WriteLine();

        // Current state
        WriteLineColored("  ── Current State ──────────────────────────────", ConsoleColor.Cyan);
        Console.WriteLine();
        WriteLineColored($"  Open Findings: {report.CurrentlyOpen}  |  Unique Seen: {report.TotalUnique}  |  Resolved: {report.TotalResolved}  |  Recurrent: {report.TotalRecurrent}", ConsoleColor.White);

        if (report.CurrentSeverity.Total > 0)
        {
            Console.Write("  Severity: ");
            if (report.CurrentSeverity.Critical > 0)
                WriteColored($"■ {report.CurrentSeverity.Critical} Critical  ", ConsoleColor.Red);
            if (report.CurrentSeverity.Warning > 0)
                WriteColored($"■ {report.CurrentSeverity.Warning} Warning  ", ConsoleColor.Yellow);
            if (report.CurrentSeverity.Info > 0)
                WriteColored($"■ {report.CurrentSeverity.Info} Info", ConsoleColor.Cyan);
            Console.WriteLine();
        }
        Console.WriteLine();

        // Module health
        if (report.Modules.Count > 0)
        {
            WriteLineColored("  ── Module Health ──────────────────────────────", ConsoleColor.Cyan);
            Console.WriteLine();
            WriteLineColored("  Module                    Current  Peak  Avg   Introduced  Resolved  MTTR       Grade", ConsoleColor.Gray);
            WriteLineColored("  ─────────────────────────────────────────────────────────────────────────────────────", ConsoleColor.DarkGray);

            foreach (var m in report.Modules)
            {
                var modGradeColor = m.HealthGrade switch
                {
                    "A" => ConsoleColor.Green,
                    "B" => ConsoleColor.Green,
                    "C" => ConsoleColor.Yellow,
                    "D" => ConsoleColor.Red,
                    _ => ConsoleColor.DarkRed
                };

                Console.Write($"  {m.ModuleName,-26} {m.CurrentFindings,7}  {m.PeakFindings,4}  {m.AvgFindings,4:F1}   {m.TotalIntroduced,10}  {m.TotalResolved,8}  {FormatDuration(m.MttrHours),-9}  ");
                WriteLineColored(m.HealthGrade, modGradeColor);
            }
            Console.WriteLine();
        }

        // Top recurring
        if (report.TopRecurring.Count > 0)
        {
            WriteLineColored("  ── Top Recurring Findings ─────────────────────", ConsoleColor.Cyan);
            Console.WriteLine();

            foreach (var r in report.TopRecurring)
            {
                var sevColor = r.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? ConsoleColor.Red : ConsoleColor.Yellow;
                WriteColored($"  [{r.Severity}] ", sevColor);
                WriteLineColored($"{r.Title} ({r.ModuleName}) — {r.Recurrences} recurrence(s), avg {r.AvgDaysBeforeRecurrence:F1} days between", ConsoleColor.White);
            }
            Console.WriteLine();
        }

        // Severity trend
        if (report.SeverityTrend.Count > 0)
        {
            WriteLineColored("  ── Severity Trend ─────────────────────────────", ConsoleColor.Cyan);
            Console.WriteLine();

            foreach (var pt in report.SeverityTrend)
            {
                Console.Write($"  {pt.WindowStart:MM/dd} → {pt.WindowEnd:MM/dd}  Score:{pt.OverallScore,3}  ");
                if (pt.Severity.Critical > 0) WriteColored($"C:{pt.Severity.Critical} ", ConsoleColor.Red);
                if (pt.Severity.Warning > 0) WriteColored($"W:{pt.Severity.Warning} ", ConsoleColor.Yellow);
                if (pt.Severity.Info > 0) WriteColored($"I:{pt.Severity.Info} ", ConsoleColor.Cyan);
                Console.WriteLine();
            }
            Console.WriteLine();
        }
    }

    private static void PrintKpiRow(string label, string value, ConsoleColor valueColor)
    {
        WriteColored($"  {label,-32} ", ConsoleColor.White);
        WriteLineColored(value, valueColor);
    }

    private static string FormatDuration(double hours) => hours switch
    {
        0 => "N/A",
        < 1 => $"{hours * 60:F0}m",
        < 24 => $"{hours:F1}h",
        _ => $"{hours / 24:F1}d"
    };
}
