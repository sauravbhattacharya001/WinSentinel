using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintExecutiveSummary(ExecutiveSummaryService.ExecutiveSummary summary)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🛡️  EXECUTIVE SECURITY SUMMARY            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Machine + date
        Console.Write("  Machine: ");
        WriteLineColored(summary.MachineName, ConsoleColor.White);
        Console.Write("  Date:    ");
        WriteLineColored(summary.GeneratedAt.LocalDateTime.ToString("f"), ConsoleColor.White);
        Console.WriteLine();

        // Score headline
        var scoreColor = summary.Score >= 80 ? ConsoleColor.Green : summary.Score >= 60 ? ConsoleColor.Yellow : ConsoleColor.Red;
        Console.Write("  SECURITY SCORE: ");
        WriteColored($"{summary.Score}/100", scoreColor);
        Console.Write("  (");
        WriteColored(summary.Grade, scoreColor);
        Console.WriteLine(")");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {summary.Verdict}");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Finding counts
        Console.Write("  Findings: ");
        WriteColored($"{summary.TotalFindings}", ConsoleColor.White);
        Console.Write(" total  ·  ");
        if (summary.CriticalCount > 0)
        {
            WriteColored($"{summary.CriticalCount} critical", ConsoleColor.Red);
            Console.Write("  ");
        }
        if (summary.WarningCount > 0)
        {
            WriteColored($"{summary.WarningCount} warnings", ConsoleColor.Yellow);
            Console.Write("  ");
        }
        WriteColored($"{summary.InfoCount} info", ConsoleColor.Cyan);
        Console.Write("  ");
        WriteColored($"{summary.PassCount} pass", ConsoleColor.Green);
        Console.WriteLine();
        Console.Write("  Modules:  ");
        WriteLineColored($"{summary.ModulesScanned} scanned", ConsoleColor.White);
        Console.WriteLine();

        // Trend
        if (summary.Trend != null)
        {
            var arrow = summary.Trend.Direction switch
            {
                "improving" => "↑",
                "declining" => "↓",
                _ => "→"
            };
            var trendColor = summary.Trend.Direction switch
            {
                "improving" => ConsoleColor.Green,
                "declining" => ConsoleColor.Red,
                _ => ConsoleColor.DarkGray
            };
            var sign = summary.Trend.ScoreChange >= 0 ? "+" : "";
            Console.Write("  TREND: ");
            WriteColored($"{arrow} {sign}{summary.Trend.ScoreChange} pts ({summary.Trend.Direction})", trendColor);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  |  Prev: {summary.Trend.PreviousScore}  |  Avg: {summary.Trend.AverageScore}  |  Scans: {summary.Trend.TotalScans}");
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        // Module health
        WriteLineColored("  MODULE HEALTH", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-22} {"Score",5}  {"Grade",5}  Status");
        Console.ForegroundColor = orig;

        foreach (var m in summary.Modules)
        {
            Console.Write($"  {m.Category,-22} ");
            var mColor = m.Score >= 80 ? ConsoleColor.Green : m.Score >= 60 ? ConsoleColor.Yellow : ConsoleColor.Red;
            WriteColored($"{m.Score,5}", mColor);
            Console.Write("  ");
            WriteColored($"{m.Grade,5}", mColor);
            Console.Write("  ");
            var (statusIcon, statusColor) = m.Status switch
            {
                "critical" => ("🔴 critical", ConsoleColor.Red),
                "at-risk" => ("🟡 at-risk", ConsoleColor.Yellow),
                _ => ("🟢 healthy", ConsoleColor.Green)
            };
            WriteLineColored(statusIcon, statusColor);
        }
        Console.WriteLine();

        // Top risks
        if (summary.TopRisks.Count > 0)
        {
            WriteLineColored("  TOP RISKS", ConsoleColor.White);
            WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);

            foreach (var risk in summary.TopRisks)
            {
                var sevColor = risk.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"  {risk.Rank}. ");
                WriteColored($"[{risk.Severity}]", sevColor);
                Console.Write(" ");
                WriteColored(risk.Title, ConsoleColor.White);
                if (risk.HasAutoFix)
                    WriteColored(" [auto-fixable]", ConsoleColor.Green);
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"     {risk.Module}");
                if (risk.Remediation != null)
                    Console.Write($" — {risk.Remediation}");
                Console.WriteLine();
                Console.ForegroundColor = orig;
            }
            Console.WriteLine();
        }

        // Strengths
        if (summary.Strengths.Count > 0)
        {
            Console.Write("  STRENGTHS: ");
            WriteLineColored(string.Join(", ", summary.Strengths), ConsoleColor.Green);
            Console.WriteLine();
        }

        // Action items
        if (summary.ActionItems.Count > 0)
        {
            WriteLineColored("  ACTION ITEMS", ConsoleColor.White);
            WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);

            foreach (var item in summary.ActionItems)
            {
                var impactColor = item.Impact switch
                {
                    "high" => ConsoleColor.Red,
                    "medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };
                var impactIcon = item.Impact switch
                {
                    "high" => "‼️",
                    "medium" => "❗",
                    _ => "ℹ️"
                };

                Console.Write($"  {item.Priority}. {impactIcon} ");
                WriteLineColored(item.Action, ConsoleColor.White);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("     Impact: ");
                WriteColored(item.Impact, impactColor);
                Console.Write("  |  Effort: ");
                Console.WriteLine(item.Effort);
                Console.ForegroundColor = orig;
            }
            Console.WriteLine();
        }

        WriteLineColored("  ══════════════════════════════════════════════════", ConsoleColor.DarkGray);
        Console.WriteLine();
    }
}
