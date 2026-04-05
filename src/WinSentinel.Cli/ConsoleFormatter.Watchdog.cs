using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>Print Security Anomaly Watchdog report.</summary>
    public static void PrintWatchdog(WatchdogReport report)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🐕 Security Anomaly Watchdog           ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Status banner
        var statusColor = report.OverallStatus switch
        {
            "ALERT" => ConsoleColor.Red,
            "WARN" => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };
        var statusIcon = report.OverallStatus switch
        {
            "ALERT" => "🚨",
            "WARN" => "⚠️",
            _ => "✅"
        };

        WriteColored("  Status: ", ConsoleColor.White);
        WriteColored($"{statusIcon} {report.OverallStatus}", statusColor);
        WriteColored("  │  Anomalies: ", ConsoleColor.White);
        WriteColored($"{report.TotalAnomalies}", report.TotalAnomalies > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
        WriteColored("  │  Runs: ", ConsoleColor.White);
        WriteColored($"{report.RunsAnalyzed}", ConsoleColor.DarkGray);
        WriteColored("  │  Days: ", ConsoleColor.White);
        WriteLineColored($"{report.DaysAnalyzed}", ConsoleColor.DarkGray);
        Console.WriteLine();

        // Stats strip
        WriteLineColored("  ── Statistical Baseline ──", ConsoleColor.DarkGray);
        Console.WriteLine();

        WriteColored("  Score: ", ConsoleColor.White);
        WriteColored($"μ={report.Stats.MeanScore:F1}", ConsoleColor.Cyan);
        WriteColored($"  σ={report.Stats.StdDevScore:F1}", ConsoleColor.DarkCyan);
        if (report.Stats.LatestScore.HasValue)
        {
            WriteColored($"  Latest={report.Stats.LatestScore}", ConsoleColor.White);
            var zColor = Math.Abs(report.Stats.ScoreZScore) >= 2 ? ConsoleColor.Red :
                         Math.Abs(report.Stats.ScoreZScore) >= 1 ? ConsoleColor.Yellow : ConsoleColor.Green;
            WriteColored($"  z={report.Stats.ScoreZScore:F2}", zColor);
        }
        Console.WriteLine();

        WriteColored("  Findings: ", ConsoleColor.White);
        WriteColored($"μ={report.Stats.MeanFindings:F1}", ConsoleColor.Cyan);
        WriteColored($"  σ={report.Stats.StdDevFindings:F1}", ConsoleColor.DarkCyan);
        if (report.Stats.LatestFindings.HasValue)
        {
            WriteColored($"  Latest={report.Stats.LatestFindings}", ConsoleColor.White);
            var zColor = Math.Abs(report.Stats.FindingsZScore) >= 2 ? ConsoleColor.Red :
                         Math.Abs(report.Stats.FindingsZScore) >= 1 ? ConsoleColor.Yellow : ConsoleColor.Green;
            WriteColored($"  z={report.Stats.FindingsZScore:F2}", zColor);
        }
        Console.WriteLine();
        Console.WriteLine();

        // Score anomalies
        if (report.ScoreAnomalies.Count > 0)
        {
            WriteLineColored("  ── Score Anomalies ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var a in report.ScoreAnomalies)
            {
                var sevColor = a.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow;
                var icon = a.Severity == "Critical" ? "🔴" : "🟡";

                WriteColored($"  {icon} ", ConsoleColor.White);
                WriteColored($"[{a.Severity}]", sevColor);
                WriteColored($" {a.Timestamp:yyyy-MM-dd HH:mm}", ConsoleColor.DarkGray);
                WriteColored($"  Score: {a.PreviousScore} → {a.Score}", ConsoleColor.White);
                WriteColored($"  (↓{a.Drop})", ConsoleColor.Red);
                WriteColored($"  z={a.ZScore:F2}", ConsoleColor.DarkCyan);
                WriteLineColored($"  {a.Reason}", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }

        // Finding spikes
        if (report.FindingSpikes.Count > 0)
        {
            WriteLineColored("  ── Finding Spikes ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var f in report.FindingSpikes)
            {
                var sevColor = f.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow;
                var icon = f.Severity == "Critical" ? "🔴" : "🟡";

                WriteColored($"  {icon} ", ConsoleColor.White);
                WriteColored($"[{f.Severity}]", sevColor);
                WriteColored($" {f.Timestamp:yyyy-MM-dd HH:mm}", ConsoleColor.DarkGray);
                WriteColored($"  Findings: {f.PreviousFindings} → {f.TotalFindings}", ConsoleColor.White);
                WriteColored($"  (↑{f.Increase})", ConsoleColor.Red);
                WriteColored($"  z={f.ZScore:F2}", ConsoleColor.DarkCyan);
                if (f.CriticalCount > 0)
                    WriteColored($"  ({f.CriticalCount} critical)", ConsoleColor.Red);
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Module regressions
        if (report.ModuleRegressions.Count > 0)
        {
            WriteLineColored("  ── Module Regressions ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var m in report.ModuleRegressions)
            {
                var trendColor = m.Trend switch
                {
                    "Collapsed" => ConsoleColor.Red,
                    "Declining" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkYellow
                };
                var trendIcon = m.Trend switch
                {
                    "Collapsed" => "💀",
                    "Declining" => "📉",
                    _ => "〰️"
                };

                WriteColored($"  {trendIcon} {m.ModuleName,-25}", ConsoleColor.White);
                WriteColored($" {m.PreviousScore} → {m.CurrentScore}", ConsoleColor.White);
                WriteColored($"  (↓{m.ScoreDrop})", ConsoleColor.Red);
                WriteColored($"  [{m.Trend}]", trendColor);
                if (m.ConsecutiveDrops > 0)
                    WriteColored($"  {m.ConsecutiveDrops} consecutive drops", ConsoleColor.DarkGray);
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            WriteLineColored("  ── Recommendations ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var rec in report.Recommendations)
            {
                WriteLineColored($"  {rec}", ConsoleColor.White);
            }
            Console.WriteLine();
        }
    }
}
