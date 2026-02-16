using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles all console output formatting with color-coded severity,
/// progress indicators, and clean table output.
/// </summary>
public static class ConsoleFormatter
{
    /// <summary>
    /// Print the application banner.
    /// </summary>
    public static void PrintBanner()
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🛡️  WinSentinel Security Audit        ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print a progress update for a module being scanned.
    /// </summary>
    public static void PrintProgress(string moduleName, int current, int total)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"\r  [{current}/{total}] Scanning {moduleName,-25}");
        Console.ForegroundColor = original;
    }

    /// <summary>
    /// Clear the progress line and print completion.
    /// </summary>
    public static void PrintProgressDone(int total, TimeSpan elapsed)
    {
        Console.Write("\r" + new string(' ', 60) + "\r");
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ✓ Scanned {total} modules");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($" in {elapsed.TotalSeconds:F1}s");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print the overall score and grade with color coding.
    /// </summary>
    public static void PrintScore(int score, bool quiet = false)
    {
        var grade = SecurityScorer.GetGrade(score);
        var color = GetScoreConsoleColor(score);
        var original = Console.ForegroundColor;

        if (quiet)
        {
            Console.ForegroundColor = color;
            Console.WriteLine($"{score}/100 ({grade})");
            Console.ForegroundColor = original;
            return;
        }

        Console.Write("  Security Score: ");
        Console.ForegroundColor = color;
        Console.Write($"{score}/100");
        Console.ForegroundColor = original;
        Console.Write("  Grade: ");
        Console.ForegroundColor = color;
        Console.WriteLine(grade);
        Console.ForegroundColor = original;

        // Score bar
        int barLength = 40;
        int filled = (int)(score / 100.0 * barLength);
        Console.Write("  ");
        Console.ForegroundColor = color;
        Console.Write(new string('█', filled));
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(new string('░', barLength - filled));
        Console.ForegroundColor = original;
        Console.WriteLine($"  {score}%");
        Console.WriteLine();
    }

    /// <summary>
    /// Print summary statistics.
    /// </summary>
    public static void PrintSummary(SecurityReport report)
    {
        var original = Console.ForegroundColor;

        Console.Write("  Findings: ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{report.TotalCritical} critical");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{report.TotalWarnings} warnings");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"{report.TotalInfo} info");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{report.TotalPass} pass");
        Console.ForegroundColor = original;
        Console.WriteLine($" │ {report.TotalFindings} total");
        Console.WriteLine();
    }

    /// <summary>
    /// Print a module breakdown table.
    /// </summary>
    public static void PrintModuleTable(SecurityReport report)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-22} {"Score",6} {"Grade",6} {"Crit",6} {"Warn",6} {"Total",6}  Status");
        Console.WriteLine($"  {new string('─', 22)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)}  {new string('─', 6)}");
        Console.ForegroundColor = original;

        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            var color = GetScoreConsoleColor(modScore);
            var status = result.Success
                ? (modScore >= 80 ? "PASS" : modScore >= 60 ? "WARN" : "FAIL")
                : "ERROR";
            var statusColor = status switch
            {
                "PASS" => ConsoleColor.Green,
                "WARN" => ConsoleColor.Yellow,
                "FAIL" => ConsoleColor.Red,
                "ERROR" => ConsoleColor.Red,
                _ => original
            };

            Console.Write($"  {result.Category,-22} ");
            Console.ForegroundColor = color;
            Console.Write($"{modScore,6} {modGrade,6}");
            Console.ForegroundColor = result.CriticalCount > 0 ? ConsoleColor.Red : original;
            Console.Write($" {result.CriticalCount,6}");
            Console.ForegroundColor = result.WarningCount > 0 ? ConsoleColor.Yellow : original;
            Console.Write($" {result.WarningCount,6}");
            Console.ForegroundColor = original;
            Console.Write($" {result.Findings.Count,6}  ");
            Console.ForegroundColor = statusColor;
            Console.WriteLine(status);
            Console.ForegroundColor = original;
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print detailed findings grouped by module.
    /// </summary>
    public static void PrintFindings(SecurityReport report)
    {
        var original = Console.ForegroundColor;

        foreach (var result in report.Results)
        {
            var actionableFindings = result.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Title)
                .ToList();

            if (actionableFindings.Count == 0) continue;

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  ┌─ {result.Category}");
            Console.ForegroundColor = original;

            foreach (var finding in actionableFindings)
            {
                var (icon, color) = finding.Severity switch
                {
                    Severity.Critical => ("CRITICAL", ConsoleColor.Red),
                    Severity.Warning => ("WARNING ", ConsoleColor.Yellow),
                    _ => ("INFO    ", ConsoleColor.Cyan)
                };

                Console.Write("  │  ");
                Console.ForegroundColor = color;
                Console.Write($"[{icon}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($" {finding.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  │    {finding.Description}");

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  │    → {finding.Remediation}");
                }

                Console.ForegroundColor = original;
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └─────────────────────────────────");
            Console.ForegroundColor = original;
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print fix results.
    /// </summary>
    public static void PrintFixResults(List<(Finding finding, FixResult result)> results)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  Fix Results:");
        Console.ForegroundColor = original;
        Console.WriteLine();

        int success = 0, failed = 0, skipped = 0;

        foreach (var (finding, fixResult) in results)
        {
            if (fixResult.Success)
            {
                success++;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  ✓ ");
            }
            else if (string.IsNullOrWhiteSpace(finding.FixCommand))
            {
                skipped++;
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  ○ ");
            }
            else
            {
                failed++;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("  ✗ ");
            }

            Console.ForegroundColor = original;
            Console.Write(finding.Title);

            if (fixResult.Success)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" (fixed)");
            }
            else if (string.IsNullOrWhiteSpace(finding.FixCommand))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" (no fix available)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" ({fixResult.Error ?? "failed"})");
            }

            Console.ForegroundColor = original;
        }

        Console.WriteLine();
        Console.Write($"  Summary: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{success} fixed");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{failed} failed");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{skipped} skipped");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print help text.
    /// </summary>
    public static void PrintHelp()
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  WinSentinel — Windows Security Auditing CLI");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine("  USAGE:");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("    winsentinel <command> [options]");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine("  COMMANDS:");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --audit, -a          ");
        Console.ForegroundColor = original;
        Console.WriteLine("Run full security audit and print results");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --score, -s          ");
        Console.ForegroundColor = original;
        Console.WriteLine("Print security score and grade only");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --fix-all, -f        ");
        Console.ForegroundColor = original;
        Console.WriteLine("Run audit and auto-fix all fixable findings");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --history            ");
        Console.ForegroundColor = original;
        Console.WriteLine("View past audit runs and score trends");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --help, -h           ");
        Console.ForegroundColor = original;
        Console.WriteLine("Show this help message");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --version, -v        ");
        Console.ForegroundColor = original;
        Console.WriteLine("Show version information");
        Console.WriteLine();
        Console.WriteLine("  OPTIONS:");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --json, -j           ");
        Console.ForegroundColor = original;
        Console.WriteLine("Output results as JSON (machine-parseable)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --html               ");
        Console.ForegroundColor = original;
        Console.WriteLine("Output results as HTML report");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    -o, --output <file>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Save output to file instead of stdout");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --modules, -m <list> ");
        Console.ForegroundColor = original;
        Console.WriteLine("Run only specific modules (comma-separated)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --quiet, -q          ");
        Console.ForegroundColor = original;
        Console.WriteLine("Minimal output (score + exit code only)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --threshold, -t <n>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Exit with error if score below n (0-100)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --compare            ");
        Console.ForegroundColor = original;
        Console.WriteLine("Compare latest two runs side-by-side (with --history)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --diff               ");
        Console.ForegroundColor = original;
        Console.WriteLine("Show new/resolved findings between runs (with --history)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --days <n>           ");
        Console.ForegroundColor = original;
        Console.WriteLine("History lookback period in days (default: 30)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --limit, -l <n>      ");
        Console.ForegroundColor = original;
        Console.WriteLine("Max number of history entries to show (default: 20)");
        Console.WriteLine();
        Console.WriteLine("  EXAMPLES:");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    winsentinel --audit                              # Full audit with colored output");
        Console.WriteLine("    winsentinel --audit --json                       # JSON output for scripting");
        Console.WriteLine("    winsentinel --audit --html -o report.html        # Save HTML report");
        Console.WriteLine("    winsentinel --audit --modules firewall,network   # Scan specific modules");
        Console.WriteLine("    winsentinel --score                              # Quick score check");
        Console.WriteLine("    winsentinel --score --quiet                      # Score only, no formatting");
        Console.WriteLine("    winsentinel --audit --threshold 90               # CI/CD gate: fail if < 90");
        Console.WriteLine("    winsentinel --fix-all                            # Auto-fix all findings");
        Console.WriteLine("    winsentinel --history                            # View past audit runs");
        Console.WriteLine("    winsentinel --history --compare                  # Compare latest two runs");
        Console.WriteLine("    winsentinel --history --diff                     # Show new/resolved findings");
        Console.WriteLine("    winsentinel --history --json                     # History as JSON");
        Console.WriteLine("    winsentinel --history --days 7                   # Last 7 days only");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine("  EXIT CODES:");
        Console.WriteLine("    0  All checks pass (or score >= threshold)");
        Console.WriteLine("    1  Warnings found (or score < threshold)");
        Console.WriteLine("    2  Critical findings found");
        Console.WriteLine("    3  Error during execution");
        Console.WriteLine();
        Console.WriteLine("  AVAILABLE MODULES:");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    firewall, updates, defender, accounts, network,");
        Console.WriteLine("    processes, startup, system, privacy, browser,");
        Console.WriteLine("    appsecurity, encryption, eventlog");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print version information.
    /// </summary>
    public static void PrintVersion()
    {
        var version = typeof(CliParser).Assembly.GetName().Version;
        Console.WriteLine($"WinSentinel CLI v{version?.Major ?? 1}.{version?.Minor ?? 0}.{version?.Build ?? 0}");
        Console.WriteLine($"  Runtime: .NET {Environment.Version}");
        Console.WriteLine($"  OS:      {Environment.OSVersion}");
        Console.WriteLine($"  Machine: {Environment.MachineName}");
    }

    /// <summary>
    /// Print an error message.
    /// </summary>
    public static void PrintError(string message)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.Write("  Error: ");
        Console.ForegroundColor = original;
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("  Run 'winsentinel --help' for usage information.");
        Console.Error.WriteLine();
    }

    // ── History Display Methods ──────────────────────────────────────────

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

    /// <summary>
    /// Get the console color for a given security score.
    /// </summary>
    public static ConsoleColor GetScoreConsoleColor(int score) => score switch
    {
        >= 80 => ConsoleColor.Green,
        >= 60 => ConsoleColor.Yellow,
        >= 40 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };
}
