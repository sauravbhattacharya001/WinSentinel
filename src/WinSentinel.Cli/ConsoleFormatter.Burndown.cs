using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static class Burndown
    {
        public static void PrintReport(BurndownReport report)
        {
            Console.WriteLine();
            WriteColorLine("═══════════════════════════════════════════════════════", ConsoleColor.Cyan);
            WriteColorLine("  📉  FINDING BURNDOWN REPORT", ConsoleColor.Cyan);
            WriteColorLine("═══════════════════════════════════════════════════════", ConsoleColor.Cyan);
            Console.WriteLine();

            // Summary strip
            WriteColorLine($"  Window: {report.WindowStart:yyyy-MM-dd} → {report.WindowEnd:yyyy-MM-dd}  ({report.TotalRuns} runs)", ConsoleColor.Gray);
            WriteColorLine($"  Unique findings seen: {report.TotalUniqueFindingsSeen}  |  Resolved: {report.TotalResolved}  |  Introduced: {report.TotalIntroduced}", ConsoleColor.Gray);
            Console.WriteLine();

            // Grade
            PrintGrade(report);

            // Burndown chart (ASCII)
            if (report.DataPoints.Count >= 2)
            {
                PrintAsciiChart(report);
            }

            // Projection
            PrintProjection(report.Projection);

            // Severity breakdown
            PrintSeverityBreakdown(report.SeverityBreakdown);

            // Periods
            if (report.Periods.Count > 0)
            {
                PrintPeriods(report.Periods);
            }

            Console.WriteLine();
        }

        public static void PrintGrade(BurndownReport report)
        {
            var gradeColor = report.Grade switch
            {
                "A+" or "A" => ConsoleColor.Green,
                "B+" or "B" => ConsoleColor.DarkGreen,
                "C" => ConsoleColor.Yellow,
                "D" => ConsoleColor.DarkYellow,
                "F" => ConsoleColor.Red,
                _ => ConsoleColor.Gray
            };

            Console.Write("  Remediation Grade: ");
            WriteColorLine($"{report.Grade}", gradeColor);
            WriteColorLine($"  {report.GradeReason}", ConsoleColor.Gray);
            Console.WriteLine();
        }

        public static void PrintProjection(BurndownProjection proj)
        {
            WriteColorLine("  ── Projection ──────────────────────────────────────", ConsoleColor.DarkCyan);
            Console.WriteLine($"  Resolved/day:   {proj.AvgResolvedPerDay:F2}");
            Console.WriteLine($"  Introduced/day: {proj.AvgIntroducedPerDay:F2}");

            var velColor = proj.NetVelocityPerDay > 0 ? ConsoleColor.Green
                : proj.NetVelocityPerDay < 0 ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.Write("  Net velocity:   ");
            WriteColorLine($"{proj.NetVelocityPerDay:F2}/day", velColor);

            Console.Write("  Current open:   ");
            WriteColorLine($"{proj.CurrentOpen}", proj.CurrentOpen == 0 ? ConsoleColor.Green : ConsoleColor.White);

            if (proj.ProjectedZeroDate.HasValue)
            {
                Console.Write("  Zero date:      ");
                WriteColorLine($"{proj.ProjectedZeroDate:yyyy-MM-dd} (~{proj.DaysToZero} days)", ConsoleColor.Green);
            }

            Console.Write("  Confidence:     ");
            var confColor = proj.ConfidencePercent >= 70 ? ConsoleColor.Green
                : proj.ConfidencePercent >= 40 ? ConsoleColor.Yellow : ConsoleColor.Red;
            WriteColorLine($"{proj.ConfidencePercent}%", confColor);

            WriteColorLine($"  {proj.Summary}", ConsoleColor.Gray);
            Console.WriteLine();
        }

        public static void PrintSeverityBreakdown(List<SeverityBurndown> breakdown)
        {
            WriteColorLine("  ── Severity Breakdown ──────────────────────────────", ConsoleColor.DarkCyan);
            Console.WriteLine($"  {"Severity",-12} {"Open",6} {"Peak",6} {"Resolved",9} {"Avg Days",9}");
            Console.WriteLine($"  {"────────",-12} {"────",6} {"────",6} {"────────",9} {"────────",9}");

            foreach (var s in breakdown)
            {
                var color = s.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Cyan
                };
                Console.ForegroundColor = color;
                Console.Write($"  {s.Severity,-12}");
                Console.ResetColor();
                Console.WriteLine($" {s.CurrentOpen,6} {s.PeakOpen,6} {s.TotalResolved,9} {s.AvgDaysToResolve,9:F1}");
            }
            Console.WriteLine();
        }

        public static void PrintPeriods(List<BurndownPeriod> periods)
        {
            WriteColorLine("  ── Period Summary ──────────────────────────────────", ConsoleColor.DarkCyan);
            Console.WriteLine($"  {"Period",-12} {"Start",6} {"End",6} {"New",5} {"Fixed",6} {"Net",5} {"Vel/d",6}");
            Console.WriteLine($"  {"──────",-12} {"─────",6} {"───",6} {"───",5} {"─────",6} {"───",5} {"─────",6}");

            foreach (var p in periods)
            {
                var netColor = p.NetChange < 0 ? ConsoleColor.Green
                    : p.NetChange > 0 ? ConsoleColor.Red : ConsoleColor.Gray;
                Console.Write($"  {p.Label,-12} {p.StartCount,6} {p.EndCount,6} {p.Introduced,5} {p.Resolved,6} ");
                Console.ForegroundColor = netColor;
                Console.Write($"{p.NetChange,5}");
                Console.ResetColor();
                Console.WriteLine($" {p.VelocityPerDay,6:F1}");
            }
            Console.WriteLine();
        }

        public static void PrintAsciiChart(BurndownReport report)
        {
            WriteColorLine("  ── Burndown Chart ──────────────────────────────────", ConsoleColor.DarkCyan);

            var points = report.DataPoints;
            int maxOpen = points.Max(p => p.OpenFindings);
            if (maxOpen == 0) maxOpen = 1;
            int chartHeight = 10;
            int chartWidth = Math.Min(points.Count, 50);

            // Sample points if too many
            var sampled = points.Count <= chartWidth
                ? points
                : Enumerable.Range(0, chartWidth)
                    .Select(i => points[(int)((double)i / chartWidth * points.Count)])
                    .ToList();

            for (int row = chartHeight; row >= 0; row--)
            {
                double threshold = (double)row / chartHeight * maxOpen;
                Console.Write($"  {(row == chartHeight ? maxOpen : row == 0 ? 0 : (int)threshold),5} │");
                foreach (var p in sampled)
                {
                    if (p.OpenFindings >= threshold && threshold > 0)
                        Console.Write("█");
                    else
                        Console.Write(" ");
                }
                Console.WriteLine();
            }
            Console.Write("       └");
            Console.WriteLine(new string('─', sampled.Count));
            Console.WriteLine();
        }

        private static void WriteColorLine(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }
    }
}
