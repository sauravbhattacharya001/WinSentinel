using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Console formatting methods for audit history, comparison, diff, and trend reports.
/// </summary>
public static partial class ConsoleFormatter
{

    /// <summary>
    /// Print the history banner with total run count.
    /// </summary>
    public static void PrintHistoryBanner(int totalRuns, int days)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📊 WinSentinel Audit History          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {totalRuns} audit run(s) found in the last {days} days");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print a table of audit history runs.
    /// </summary>
    public static void PrintHistoryTable(List<AuditRunRecord> runs, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            // Header
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"#",-5} {"Date",-20} {"Score",6} {"Grade",6} {"Crit",6} {"Warn",6} {"Total",6}  {"Type",-10}");
            Console.WriteLine($"  {new string('─', 5)} {new string('─', 20)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)}  {new string('─', 10)}");
            Console.ForegroundColor = original;
        }

        for (int i = 0; i < runs.Count; i++)
        {
            var run = runs[i];
            var color = GetScoreConsoleColor(run.OverallScore);
            var type = run.IsScheduled ? "Scheduled" : "Manual";
            var dateStr = run.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

            if (quiet)
            {
                Console.ForegroundColor = color;
                Console.WriteLine($"{run.Id}\t{dateStr}\t{run.OverallScore}\t{run.Grade}\t{run.CriticalCount}\t{run.WarningCount}\t{run.TotalFindings}");
                Console.ForegroundColor = original;
                continue;
            }

            Console.Write($"  {run.Id,-5} {dateStr,-20} ");
            Console.ForegroundColor = color;
            Console.Write($"{run.OverallScore,6} {run.Grade,6}");
            Console.ForegroundColor = run.CriticalCount > 0 ? ConsoleColor.Red : original;
            Console.Write($" {run.CriticalCount,6}");
            Console.ForegroundColor = run.WarningCount > 0 ? ConsoleColor.Yellow : original;
            Console.Write($" {run.WarningCount,6}");
            Console.ForegroundColor = original;
            Console.Write($" {run.TotalFindings,6}  ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(type);
            Console.ForegroundColor = original;

            // Show change indicator for non-first entries
            if (i < runs.Count - 1)
            {
                var nextRun = runs[i + 1]; // next is older since runs are DESC
                var change = run.OverallScore - nextRun.OverallScore;
                if (change != 0)
                {
                    Console.ForegroundColor = change > 0 ? ConsoleColor.Green : ConsoleColor.Red;
                    var arrow = change > 0 ? "↑" : "↓";
                    Console.Write($"  {"",5} {"",20} {arrow,6}{Math.Abs(change)}");
                    Console.ForegroundColor = original;
                    Console.WriteLine();
                }
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print a trend summary below the history table.
    /// </summary>
    public static void PrintHistoryTrend(ScoreTrendSummary trend)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ── Trend Summary ─────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Score change
        if (trend.PreviousScore.HasValue)
        {
            var change = trend.ScoreChange;
            var changeColor = change > 0 ? ConsoleColor.Green : change < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            Console.Write("  Latest change: ");
            Console.ForegroundColor = changeColor;
            Console.Write($"{trend.ChangeDirection} {Math.Abs(change)} points");
            Console.ForegroundColor = original;
            Console.WriteLine($"  ({trend.PreviousScore} → {trend.CurrentScore})");
        }

        // Best/Worst/Average
        if (trend.BestScore.HasValue)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"  🏆 Best:    {trend.BestScore} ({trend.BestScoreGrade})");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" on {trend.BestScoreDate?.ToLocalTime():MMM dd, yyyy}");
        }
        if (trend.WorstScore.HasValue)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"  📉 Worst:   {trend.WorstScore} ({trend.WorstScoreGrade})");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" on {trend.WorstScoreDate?.ToLocalTime():MMM dd, yyyy}");
        }
        Console.ForegroundColor = original;
        Console.WriteLine($"  📊 Average: {trend.AverageScore:F0} over {trend.TotalScans} scans");

        // Mini sparkline
        if (trend.Points.Count >= 2)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Trend: ");
            var points = trend.Points.TakeLast(15).ToList();
            foreach (var point in points)
            {
                Console.ForegroundColor = GetScoreConsoleColor(point.Score);
                var barChar = point.Score >= 90 ? '▇' : point.Score >= 80 ? '▆' : point.Score >= 70 ? '▅' : point.Score >= 60 ? '▃' : '▁';
                Console.Write(barChar);
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print a side-by-side comparison report of two audit runs.
    /// </summary>
    public static void PrintComparisonReport(AuditRunRecord previousRun, AuditRunRecord currentRun, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       🔍 WinSentinel Run Comparison         ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Overview card
        var scoreChange = currentRun.OverallScore - previousRun.OverallScore;
        var changeColor = scoreChange > 0 ? ConsoleColor.Green : scoreChange < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
        var changeArrow = scoreChange > 0 ? "↑" : scoreChange < 0 ? "↓" : "→";

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Previous: ");
        Console.ForegroundColor = GetScoreConsoleColor(previousRun.OverallScore);
        Console.Write($"{previousRun.OverallScore}/100 ({previousRun.Grade})");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  — {previousRun.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm}");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Current:  ");
        Console.ForegroundColor = GetScoreConsoleColor(currentRun.OverallScore);
        Console.Write($"{currentRun.OverallScore}/100 ({currentRun.Grade})");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  — {currentRun.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm}");

        Console.Write("  Change:   ");
        Console.ForegroundColor = changeColor;
        Console.WriteLine($"{changeArrow} {Math.Abs(scoreChange)} points");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Module comparison table
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-22} {"Previous",10} {"Current",10} {"Change",8}  Status");
        Console.WriteLine($"  {new string('─', 22)} {new string('─', 10)} {new string('─', 10)} {new string('─', 8)}  {new string('─', 8)}");
        Console.ForegroundColor = original;

        var prevModules = previousRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m);
        var currModules = currentRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m);
        var allModuleNames = prevModules.Keys.Union(currModules.Keys).OrderBy(n => n);

        foreach (var name in allModuleNames)
        {
            prevModules.TryGetValue(name, out var prev);
            currModules.TryGetValue(name, out var curr);

            var category = curr?.Category ?? prev?.Category ?? name;
            var prevScore = prev?.Score;
            var currScore = curr?.Score;
            var change = (currScore ?? 0) - (prevScore ?? 0);
            var modChangeColor = change > 0 ? ConsoleColor.Green : change < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            var modArrow = change > 0 ? "↑" : change < 0 ? "↓" : "→";
            var statusEmoji = change > 0 ? "✅" : change < 0 ? "⚠️" : "➖";

            Console.Write($"  {category,-22}");

            if (prevScore.HasValue)
            {
                Console.ForegroundColor = GetScoreConsoleColor(prevScore.Value);
                Console.Write($" {prevScore,10}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" {"  N/A",10}");
            }

            if (currScore.HasValue)
            {
                Console.ForegroundColor = GetScoreConsoleColor(currScore.Value);
                Console.Write($" {currScore,10}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" {"  N/A",10}");
            }

            Console.ForegroundColor = modChangeColor;
            Console.Write($" {modArrow}{Math.Abs(change),6}");
            Console.ForegroundColor = original;
            Console.WriteLine($"  {statusEmoji}");
        }

        Console.WriteLine();

        // Findings summary comparison
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ── Findings Comparison ────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();

        PrintFindingsComparisonRow("Critical", previousRun.CriticalCount, currentRun.CriticalCount, ConsoleColor.Red);
        PrintFindingsComparisonRow("Warnings", previousRun.WarningCount, currentRun.WarningCount, ConsoleColor.Yellow);
        PrintFindingsComparisonRow("Info", previousRun.InfoCount, currentRun.InfoCount, ConsoleColor.Cyan);
        PrintFindingsComparisonRow("Pass", previousRun.PassCount, currentRun.PassCount, ConsoleColor.Green);
        PrintFindingsComparisonRow("Total", previousRun.TotalFindings, currentRun.TotalFindings, Console.ForegroundColor);

        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    private static void PrintFindingsComparisonRow(string label, int previous, int current, ConsoleColor labelColor)
    {
        var original = Console.ForegroundColor;
        var change = current - previous;
        // For findings, decrease is good (except for Pass where increase is good)
        var isPass = label == "Pass";
        var isGood = isPass ? change >= 0 : change <= 0;
        var changeColor = change == 0 ? ConsoleColor.DarkGray : isGood ? ConsoleColor.Green : ConsoleColor.Red;
        var arrow = change > 0 ? "↑" : change < 0 ? "↓" : "→";

        Console.Write("  ");
        Console.ForegroundColor = labelColor;
        Console.Write($"  {label,-12}");
        Console.ForegroundColor = original;
        Console.Write($" {previous,5} → {current,5}  ");
        Console.ForegroundColor = changeColor;
        Console.WriteLine($"{arrow} {Math.Abs(change)}");
        Console.ForegroundColor = original;
    }

    /// <summary>
    /// Print a diff report showing new and resolved findings between two runs.
    /// </summary>
    public static void PrintDiffReport(
        AuditRunRecord previousRun,
        AuditRunRecord currentRun,
        List<FindingRecord> newFindings,
        List<FindingRecord> resolvedFindings,
        List<FindingRecord> persistentFindings,
        bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       📋 WinSentinel Findings Diff          ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();

            // Score summary
            var scoreChange = currentRun.OverallScore - previousRun.OverallScore;
            var changeColor = scoreChange > 0 ? ConsoleColor.Green : scoreChange < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            var changeArrow = scoreChange > 0 ? "↑" : scoreChange < 0 ? "↓" : "→";

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Score: ");
            Console.ForegroundColor = GetScoreConsoleColor(previousRun.OverallScore);
            Console.Write($"{previousRun.OverallScore}");
            Console.ForegroundColor = original;
            Console.Write(" → ");
            Console.ForegroundColor = GetScoreConsoleColor(currentRun.OverallScore);
            Console.Write($"{currentRun.OverallScore}");
            Console.ForegroundColor = changeColor;
            Console.WriteLine($"  ({changeArrow} {Math.Abs(scoreChange)})");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  Between: {previousRun.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm} → {currentRun.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm}");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Diff summary
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"+{newFindings.Count} new");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"-{resolvedFindings.Count} resolved");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"={persistentFindings.Count} unchanged");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // New findings (bad — things got worse)
        if (newFindings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ┌─ New Findings ({newFindings.Count})");
            Console.ForegroundColor = original;

            foreach (var finding in newFindings.OrderByDescending(f => f.Severity).ThenBy(f => f.Title))
            {
                var severityColor = finding.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    "Info" => ConsoleColor.Cyan,
                    _ => ConsoleColor.Green
                };

                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("  │  + ");
                Console.ForegroundColor = severityColor;
                Console.Write($"[{finding.Severity,-8}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {finding.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ({finding.ModuleName})");

                if (!quiet && !string.IsNullOrEmpty(finding.Description))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  │    {finding.Description}");
                }

                if (!quiet && !string.IsNullOrEmpty(finding.Remediation))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  │    → {finding.Remediation}");
                }

                Console.ForegroundColor = original;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  └─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Resolved findings (good — things improved)
        if (resolvedFindings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ┌─ Resolved Findings ({resolvedFindings.Count})");
            Console.ForegroundColor = original;

            foreach (var finding in resolvedFindings.OrderByDescending(f => f.Severity).ThenBy(f => f.Title))
            {
                var severityColor = finding.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    "Info" => ConsoleColor.Cyan,
                    _ => ConsoleColor.Green
                };

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  │  - ");
                Console.ForegroundColor = severityColor;
                Console.Write($"[{finding.Severity,-8}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {finding.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ({finding.ModuleName})");

                Console.ForegroundColor = original;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  └─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        if (newFindings.Count == 0 && resolvedFindings.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  No changes in findings between these two runs.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    // ── Baseline Formatting ──────────────────────────────────────────────


    /// <summary>
    /// Print the full trend analysis report.
    /// </summary>
    public static void PrintTrendReport(TrendReport report, bool showModules = false)
    {
        var original = Console.ForegroundColor;

        // ── Header ──────────────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ┌─────────────────────────────────────────────────────┐");
        Console.WriteLine("  │           🔎 SECURITY SCORE TREND ANALYSIS          │");
        Console.WriteLine("  └─────────────────────────────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Sparkline ───────────────────────────────────────────────
        if (report.SparklineScores.Count > 1)
        {
            var sparkline = TrendAnalyzer.GenerateSparkline(report.SparklineScores);
            Console.Write("  Score trend:  ");
            Console.ForegroundColor = report.TrendDirection switch
            {
                TrendDirection.Improving => ConsoleColor.Green,
                TrendDirection.Declining => ConsoleColor.Red,
                _ => ConsoleColor.Yellow,
            };
            Console.Write(sparkline);
            Console.ForegroundColor = original;

            var arrow = report.TrendDirection switch
            {
                TrendDirection.Improving => " ↑ Improving",
                TrendDirection.Declining => " ↓ Declining",
                _ => " → Stable",
            };
            Console.ForegroundColor = report.TrendDirection switch
            {
                TrendDirection.Improving => ConsoleColor.Green,
                TrendDirection.Declining => ConsoleColor.Red,
                _ => ConsoleColor.Yellow,
            };
            Console.WriteLine(arrow);
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Current Score ───────────────────────────────────────────
        Console.Write("  Current Score:  ");
        Console.ForegroundColor = GetScoreColor(report.CurrentScore);
        Console.Write($"{report.CurrentScore}/100 ({report.CurrentGrade})");
        Console.ForegroundColor = original;

        if (report.PreviousScore.HasValue)
        {
            var change = report.ScoreChange;
            var sign = change > 0 ? "+" : "";
            Console.ForegroundColor = change > 0 ? ConsoleColor.Green : change < 0 ? ConsoleColor.Red : ConsoleColor.Gray;
            Console.Write($"  ({sign}{change} from last scan)");
            Console.ForegroundColor = original;
        }
        Console.WriteLine();
        Console.WriteLine();

        // ── Statistics ──────────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  📊 Statistics");
        Console.ForegroundColor = original;
        Console.WriteLine($"  ├── Scans:     {report.TotalScans} over {FormatTimeSpan(report.TimeSpan)}");
        Console.WriteLine($"  ├── Average:   {report.AverageScore:F1}");
        Console.WriteLine($"  ├── Median:    {report.MedianScore}");
        Console.WriteLine($"  ├── Std Dev:   {report.ScoreStdDev:F1}");
        Console.Write("  ├── Best:      ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"{report.BestScore} ({report.BestScoreGrade}) on {report.BestScoreDate.LocalDateTime:MMM dd, yyyy}");
        Console.ForegroundColor = original;
        Console.Write("  └── Worst:     ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"{report.WorstScore} ({report.WorstScoreGrade}) on {report.WorstScoreDate.LocalDateTime:MMM dd, yyyy}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Score Distribution ──────────────────────────────────────
        if (report.Distribution.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📈 Score Distribution");
            Console.ForegroundColor = original;

            var maxCount = report.Distribution.Values.Max();
            foreach (var (bucket, count) in report.Distribution)
            {
                var barWidth = maxCount > 0 ? (int)Math.Round((double)count / maxCount * 20) : 0;
                var bar = new string('█', barWidth);
                var color = bucket switch
                {
                    "80-100" => ConsoleColor.Green,
                    "60-79" => ConsoleColor.Yellow,
                    "40-59" => ConsoleColor.DarkYellow,
                    "20-39" => ConsoleColor.Red,
                    _ => ConsoleColor.DarkRed,
                };
                Console.Write($"  {bucket,6}  ");
                Console.ForegroundColor = color;
                Console.Write(bar);
                Console.ForegroundColor = original;
                Console.WriteLine($" {count}");
            }
            Console.WriteLine();
        }

        // ── Streaks ─────────────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  🔥 Streaks");
        Console.ForegroundColor = original;
        if (report.CurrentImprovementStreak > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ├── Improvement streak: {report.CurrentImprovementStreak} scan(s)");
            Console.ForegroundColor = original;
        }
        if (report.CurrentDeclineStreak > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ├── Decline streak:     {report.CurrentDeclineStreak} scan(s)");
            Console.ForegroundColor = original;
        }
        Console.WriteLine($"  └── Best streak:        {report.BestImprovementStreak} scan(s)");
        Console.WriteLine();

        // ── Findings Trend ──────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  🔍 Findings");
        Console.ForegroundColor = original;
        Console.Write("  ├── Critical:  ");
        Console.ForegroundColor = report.TotalCriticalCurrent > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write(report.TotalCriticalCurrent);
        Console.ForegroundColor = original;
        if (report.CriticalChange != 0)
        {
            var sign = report.CriticalChange > 0 ? "+" : "";
            Console.ForegroundColor = report.CriticalChange > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.Write($" ({sign}{report.CriticalChange})");
            Console.ForegroundColor = original;
        }
        Console.WriteLine();
        Console.Write("  └── Warning:   ");
        Console.ForegroundColor = report.TotalWarningCurrent > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.Write(report.TotalWarningCurrent);
        Console.ForegroundColor = original;
        if (report.WarningChange != 0)
        {
            var sign = report.WarningChange > 0 ? "+" : "";
            Console.ForegroundColor = report.WarningChange > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.Write($" ({sign}{report.WarningChange})");
            Console.ForegroundColor = original;
        }
        Console.WriteLine();
        Console.WriteLine();

        // ── Module Trends ───────────────────────────────────────────
        if (showModules && report.ModuleTrends.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📋 Module Trends");
            Console.ForegroundColor = original;

            foreach (var mod in report.ModuleTrends)
            {
                var trendColor = mod.ScoreChange > 0 ? ConsoleColor.Green
                    : mod.ScoreChange < 0 ? ConsoleColor.Red
                    : ConsoleColor.Gray;
                var changeText = mod.PreviousScore.HasValue
                    ? $" {mod.TrendIndicator} {(mod.ScoreChange > 0 ? "+" : "")}{mod.ScoreChange}"
                    : "";

                Console.Write($"  │  {mod.ModuleName,-20} ");
                Console.ForegroundColor = GetScoreColor(mod.CurrentScore);
                Console.Write($"{mod.CurrentScore,3}/100");
                Console.ForegroundColor = trendColor;
                Console.Write(changeText);
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // ── Alerts ──────────────────────────────────────────────────
        if (report.Alerts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ⚠️  Alerts");
            Console.ForegroundColor = original;

            foreach (var alert in report.Alerts)
            {
                var (icon, color) = alert.Level switch
                {
                    AlertLevel.Critical => ("🔴", ConsoleColor.Red),
                    AlertLevel.Warning => ("🟡", ConsoleColor.Yellow),
                    _ => ("ℹ️", ConsoleColor.Cyan),
                };
                Console.ForegroundColor = color;
                Console.WriteLine($"  {icon} {alert.Message}");
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // ── Bar Chart ───────────────────────────────────────────────
        if (report.SparklineScores.Count > 1)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📉 Score History");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    private static ConsoleColor GetScoreColor(int score) =>
        score >= 80 ? ConsoleColor.Green
        : score >= 60 ? ConsoleColor.Yellow
        : score >= 40 ? ConsoleColor.DarkYellow
        : ConsoleColor.Red;

    private static string FormatTimeSpan(TimeSpan ts) =>
        ts.TotalDays >= 1 ? $"{ts.Days}d {ts.Hours}h"
        : ts.TotalHours >= 1 ? $"{ts.Hours}h {ts.Minutes}m"
        : $"{ts.Minutes}m";
}
