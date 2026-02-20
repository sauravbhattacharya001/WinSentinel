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
        Console.Write("    --baseline <action>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Manage security baselines (save/list/check/delete)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --checklist          ");
        Console.ForegroundColor = original;
        Console.WriteLine("Generate prioritized remediation checklist");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --profiles           ");
        Console.ForegroundColor = original;
        Console.WriteLine("List available compliance profiles");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --ignore <action>    ");
        Console.ForegroundColor = original;
        Console.WriteLine("Manage finding ignore rules (add/list/remove/clear/purge)");
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
        Console.Write("    --markdown, --md     ");
        Console.ForegroundColor = original;
        Console.WriteLine("Output results as Markdown (GitHub-flavored)");
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
        Console.Write("    --profile, -p <name> ");
        Console.ForegroundColor = original;
        Console.WriteLine("Apply compliance profile (home/developer/enterprise/server)");
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
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --desc <text>        ");
        Console.ForegroundColor = original;
        Console.WriteLine("Description for a baseline (with --baseline save)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --force              ");
        Console.ForegroundColor = original;
        Console.WriteLine("Overwrite existing baseline (with --baseline save)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --show-ignored       ");
        Console.ForegroundColor = original;
        Console.WriteLine("Show suppressed findings in audit output");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --ignore-module <m>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Scope ignore rule to a specific module (with --ignore add)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --ignore-severity <s>");
        Console.ForegroundColor = original;
        Console.WriteLine(" Scope ignore rule to a severity (critical/warning/info/pass)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --ignore-reason <r>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Reason for ignoring (with --ignore add)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --match-mode <mode>  ");
        Console.ForegroundColor = original;
        Console.WriteLine("Pattern matching: exact, contains (default), or regex");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("    --expire-days <n>    ");
        Console.ForegroundColor = original;
        Console.WriteLine("Auto-expire ignore rule after n days (1-3650)");
        Console.WriteLine();
        Console.WriteLine("  EXAMPLES:");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    winsentinel --audit                              # Full audit with colored output");
        Console.WriteLine("    winsentinel --audit --json                       # JSON output for scripting");
        Console.WriteLine("    winsentinel --audit --html -o report.html        # Save HTML report");
        Console.WriteLine("    winsentinel --audit --markdown -o report.md       # Save Markdown report");
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
        Console.WriteLine("    winsentinel --baseline save prod                 # Save current state as baseline");
        Console.WriteLine("    winsentinel --baseline save prod --desc \"...\"    # With description");
        Console.WriteLine("    winsentinel --baseline list                      # List all saved baselines");
        Console.WriteLine("    winsentinel --baseline check prod                # Check current vs baseline");
        Console.WriteLine("    winsentinel --baseline check prod --json         # Check result as JSON");
        Console.WriteLine("    winsentinel --baseline delete prod               # Delete a baseline");
        Console.WriteLine("    winsentinel --checklist                          # Prioritized fix plan");
        Console.WriteLine("    winsentinel --checklist --json                   # Checklist as JSON");
        Console.WriteLine("    winsentinel --checklist -m firewall,network      # Checklist for specific modules");
        Console.WriteLine("    winsentinel --profiles                           # List compliance profiles");
        Console.WriteLine("    winsentinel --audit --profile home               # Audit with Home profile");
        Console.WriteLine("    winsentinel --audit --profile enterprise         # Audit with Enterprise profile");
        Console.WriteLine("    winsentinel --audit --profile server --json      # Server profile as JSON");
        Console.WriteLine("    winsentinel --ignore add \"Remote Desktop\"          # Suppress findings containing text");
        Console.WriteLine("    winsentinel --ignore add \"SMB\" --ignore-reason \"Accepted risk\"");
        Console.WriteLine("    winsentinel --ignore add \"Telemetry\" --match-mode exact  # Exact title match");
        Console.WriteLine("    winsentinel --ignore add \"^BitLocker\" --match-mode regex  # Regex pattern");
        Console.WriteLine("    winsentinel --ignore add \"LLMNR\" --ignore-module network  # Module-scoped");
        Console.WriteLine("    winsentinel --ignore add \"audit\" --ignore-severity warning  # Severity-scoped");
        Console.WriteLine("    winsentinel --ignore add \"test\" --expire-days 30   # Auto-expire in 30 days");
        Console.WriteLine("    winsentinel --ignore list                          # Show all ignore rules");
        Console.WriteLine("    winsentinel --ignore remove abc12345               # Remove rule by ID");
        Console.WriteLine("    winsentinel --ignore clear                         # Remove all rules");
        Console.WriteLine("    winsentinel --ignore purge                         # Remove expired rules");
        Console.WriteLine("    winsentinel --audit --show-ignored                 # Audit showing suppressed findings");
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

    // ── Baseline Formatting ──────────────────────────────────────────────

    /// <summary>
    /// Print confirmation after saving a baseline.
    /// </summary>
    public static void PrintBaselineSaved(SecurityBaseline baseline)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📌 Baseline Saved                     ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Name:     ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(baseline.Name);

        if (!string.IsNullOrEmpty(baseline.Description))
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("  Desc:     ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(baseline.Description);
        }

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Score:    ");
        Console.ForegroundColor = GetScoreConsoleColor(baseline.OverallScore);
        Console.WriteLine($"{baseline.OverallScore}/100 ({baseline.Grade})");

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Findings: ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{baseline.CriticalCount} critical");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{baseline.WarningCount} warnings");
        Console.ForegroundColor = original;
        Console.Write(" │ ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{baseline.TotalFindings} total");

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Modules:  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{baseline.ModuleScores.Count} captured");

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Machine:  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(baseline.MachineName);

        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✓ Baseline snapshot saved. Check against it with:");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"    winsentinel --baseline check {baseline.Name}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print a list of saved baselines.
    /// </summary>
    public static void PrintBaselineList(List<BaselineSummary> baselines, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       📌 Saved Baselines                    ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Table header
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Name",-20} {"Score",6} {"Grade",6} {"Crit",6} {"Warn",6} {"Total",6}  {"Created",-20} Machine");
        Console.WriteLine($"  {new string('─', 20)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)}  {new string('─', 20)} {new string('─', 15)}");
        Console.ForegroundColor = original;

        foreach (var b in baselines)
        {
            var scoreColor = GetScoreConsoleColor(b.OverallScore);

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {b.Name,-20}");
            Console.ForegroundColor = scoreColor;
            Console.Write($" {b.OverallScore,6}");
            Console.Write($" {b.Grade,6}");
            Console.ForegroundColor = b.CriticalCount > 0 ? ConsoleColor.Red : original;
            Console.Write($" {b.CriticalCount,6}");
            Console.ForegroundColor = b.WarningCount > 0 ? ConsoleColor.Yellow : original;
            Console.Write($" {b.WarningCount,6}");
            Console.ForegroundColor = original;
            Console.Write($" {b.TotalFindings,6}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {b.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm,-20}");
            Console.Write($" {b.MachineName}");
            Console.ForegroundColor = original;
            Console.WriteLine();

            if (!quiet && !string.IsNullOrEmpty(b.Description))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  └ {b.Description}");
                Console.ForegroundColor = original;
            }
        }

        Console.WriteLine();

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {baselines.Count} baseline(s) saved.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Print baseline check results showing deviations from the saved baseline.
    /// </summary>
    public static void PrintBaselineCheck(BaselineCheckResult result, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       📌 Baseline Check                     ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Baseline: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{result.Baseline.Name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  (saved {result.Baseline.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm})");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Score comparison
        var scoreChange = result.ScoreChange;
        var changeColor = scoreChange > 0 ? ConsoleColor.Green : scoreChange < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
        var changeArrow = scoreChange > 0 ? "↑" : scoreChange < 0 ? "↓" : "→";

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Baseline: ");
        Console.ForegroundColor = GetScoreConsoleColor(result.Baseline.OverallScore);
        Console.Write($"{result.Baseline.OverallScore}/100 ({result.Baseline.Grade})");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Current:  ");
        Console.ForegroundColor = GetScoreConsoleColor(result.CurrentScore);
        Console.Write($"{result.CurrentScore}/100 ({SecurityScorer.GetGrade(result.CurrentScore)})");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Change:   ");
        Console.ForegroundColor = changeColor;
        Console.WriteLine($"{changeArrow} {Math.Abs(scoreChange)} points");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Overall verdict
        var verdictColor = result.Passed ? ConsoleColor.Green : ConsoleColor.Red;
        var verdictIcon = result.Passed ? "✅" : "❌";
        var verdictText = result.Passed ? "BASELINE CHECK PASSED" : "BASELINE CHECK FAILED";

        Console.ForegroundColor = verdictColor;
        Console.WriteLine($"  {verdictIcon} {verdictText}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Deviation summary
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{result.Regressions.Count} regressions");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{result.Resolved.Count} resolved");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"{result.Unchanged.Count} unchanged");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Module deviations table
        if (!quiet)
        {
            var deviationsWithChange = result.ModuleDeviations.Where(d => d.ScoreChange != 0).ToList();
            if (deviationsWithChange.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  ── Module Deviations ─────────────────────────");
                Console.ForegroundColor = original;
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  {"Module",-22} {"Baseline",10} {"Current",10} {"Change",8}  Status");
                Console.WriteLine($"  {new string('─', 22)} {new string('─', 10)} {new string('─', 10)} {new string('─', 8)}  {new string('─', 10)}");
                Console.ForegroundColor = original;

                foreach (var dev in deviationsWithChange)
                {
                    var devChangeColor = dev.ScoreChange > 0 ? ConsoleColor.Green : ConsoleColor.Red;
                    var devArrow = dev.ScoreChange > 0 ? "↑" : "↓";
                    var statusEmoji = dev.ScoreChange > 0 ? "✅" : "⚠️";

                    Console.Write($"  {dev.Category,-22}");
                    Console.ForegroundColor = GetScoreConsoleColor(dev.BaselineScore);
                    Console.Write($" {dev.BaselineScore,10}");
                    Console.ForegroundColor = GetScoreConsoleColor(dev.CurrentScore);
                    Console.Write($" {dev.CurrentScore,10}");
                    Console.ForegroundColor = devChangeColor;
                    Console.Write($" {devArrow}{Math.Abs(dev.ScoreChange),6}");
                    Console.ForegroundColor = original;
                    Console.WriteLine($"  {statusEmoji}");
                }

                Console.WriteLine();
            }
        }

        // Regressions (new findings not in baseline)
        if (result.Regressions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ┌─ Regressions ({result.Regressions.Count})  — new issues since baseline");
            Console.ForegroundColor = original;

            foreach (var finding in result.Regressions)
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

        // Resolved findings (improvements since baseline)
        if (result.Resolved.Count > 0 && !quiet)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ┌─ Resolved ({result.Resolved.Count})  — fixed since baseline");
            Console.ForegroundColor = original;

            foreach (var finding in result.Resolved)
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

        if (result.Regressions.Count == 0 && result.Resolved.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No deviations from baseline — system state matches.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    // ── Checklist / Remediation Plan ─────────────────────────────────

    /// <summary>
    /// Print a prioritized remediation checklist with Quick Wins, Medium Effort, and Major Changes.
    /// </summary>
    public static void PrintChecklist(RemediationPlan plan, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (plan.TotalItems == 0)
        {
            if (!quiet)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  ✅ No actionable findings — your system is well secured!");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            return;
        }

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       📋 Remediation Checklist              ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Overview cards
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Current:   ");
        Console.ForegroundColor = GetScoreConsoleColor(plan.CurrentScore);
        Console.Write($"{plan.CurrentScore}/100 ({plan.CurrentGrade})");
        Console.ForegroundColor = original;
        Console.Write("   →   Projected: ");
        Console.ForegroundColor = GetScoreConsoleColor(plan.ProjectedScore);
        Console.WriteLine($"{plan.ProjectedScore}/100 ({plan.ProjectedGrade})");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"⚡ {plan.QuickWins.Count} quick wins");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"🔧 {plan.MediumEffort.Count} medium effort");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.Write($"🏗️ {plan.MajorChanges.Count} major changes");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"🤖 {plan.AutoFixableCount} auto-fixable");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Quick Wins
        if (plan.QuickWins.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ── ⚡ Quick Wins ({plan.QuickWins.Count}) ─ Less than 5 minutes each ──────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var item in plan.QuickWins)
            {
                PrintChecklistItem(item, quiet);
            }
        }

        // Medium Effort
        if (plan.MediumEffort.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ── 🔧 Medium Effort ({plan.MediumEffort.Count}) ─ 5-30 minutes each ──────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var item in plan.MediumEffort)
            {
                PrintChecklistItem(item, quiet);
            }
        }

        // Major Changes
        if (plan.MajorChanges.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"  ── 🏗️ Major Changes ({plan.MajorChanges.Count}) ─ 30+ minutes each ──────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var item in plan.MajorChanges)
            {
                PrintChecklistItem(item, quiet);
            }
        }

        // Summary
        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ── Summary ───────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var totalImpact = plan.TotalImpact;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"  📈 Fixing all {plan.TotalItems} items could improve your score by up to ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"+{totalImpact} points");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($" ({plan.CurrentScore} → {plan.ProjectedScore})");
            Console.ForegroundColor = original;

            if (plan.AutoFixableCount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"  🤖 {plan.AutoFixableCount} items can be auto-fixed with: winsentinel --fix-all");
                Console.ForegroundColor = original;
            }

            if (plan.QuickWins.Count > 0)
            {
                var quickImpact = plan.QuickWins.Sum(i => i.Impact);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ⚡ Start with quick wins for +{quickImpact} points in minutes!");
                Console.ForegroundColor = original;
            }

            Console.WriteLine();
        }
    }

    /// <summary>
    /// Print a single checklist item with severity, impact, and details.
    /// </summary>
    private static void PrintChecklistItem(RemediationItem item, bool quiet)
    {
        var original = Console.ForegroundColor;

        var severityColor = item.Severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.Warning => ConsoleColor.Yellow,
            _ => ConsoleColor.Cyan
        };

        var severityLabel = item.Severity switch
        {
            Severity.Critical => "CRITICAL",
            Severity.Warning => "WARNING ",
            _ => "INFO    "
        };

        // Step number and title
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  {item.StepNumber,3}. ");
        Console.ForegroundColor = severityColor;
        Console.Write($"[{severityLabel}]");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($" {item.Title}");

        if (item.HasAutoFix)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  🤖");
        }

        Console.ForegroundColor = original;
        Console.WriteLine();

        if (!quiet)
        {
            // Impact and timing
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"       +{item.Impact} pts");
            Console.Write($"  │  ⏱️ {item.EstimatedTime}");
            Console.Write($"  │  📂 {item.Category}");
            Console.ForegroundColor = original;
            Console.WriteLine();

            // Description
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"       {item.Description}");

            // Remediation
            if (!string.IsNullOrEmpty(item.Remediation))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"       → {item.Remediation}");
            }

            // Fix command
            if (item.HasAutoFix)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"       🔧 {item.FixCommand}");
            }

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

    // ── Compliance Profile Display ───────────────────────────────────

    /// <summary>
    /// Print a list of available compliance profiles.
    /// </summary>
    public static void PrintProfileList(IReadOnlyList<ComplianceProfile> profiles, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       📋 Compliance Profiles                ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        foreach (var profile in profiles)
        {
            var thresholdColor = GetScoreConsoleColor(profile.ComplianceThreshold);

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {profile.Name,-12}");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($" {profile.DisplayName}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  (threshold: ");
            Console.ForegroundColor = thresholdColor;
            Console.Write($"{profile.ComplianceThreshold}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(")");

            if (!quiet)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"             {profile.Description}");

                // Show key stats
                var weightedModules = profile.ModuleWeights.Count(w => Math.Abs(w.Value - 1.0) > 0.001);
                var overrides = profile.SeverityOverrides.Count;
                var skipped = profile.SkippedModules.Count;

                Console.Write("             ");
                if (weightedModules > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"⚖️ {weightedModules} weighted modules");
                }
                if (overrides > 0)
                {
                    if (weightedModules > 0) Console.Write("  │  ");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"🔄 {overrides} severity overrides");
                }
                if (skipped > 0)
                {
                    Console.Write("  │  ");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"⏭️ {skipped} skipped modules");
                }
                Console.WriteLine();
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Usage:");
            Console.WriteLine("    winsentinel --audit --profile home         # Audit with Home profile");
            Console.WriteLine("    winsentinel --audit --profile enterprise   # Audit with Enterprise profile");
            Console.WriteLine("    winsentinel --score --profile server       # Score with Server profile");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Print compliance result after applying a profile to an audit.
    /// </summary>
    public static void PrintComplianceResult(ComplianceResult result, bool quiet = false)
    {
        var original = Console.ForegroundColor;
        var profile = result.Profile;

        // Compliance verdict
        var verdictColor = result.IsCompliant ? ConsoleColor.Green : ConsoleColor.Red;
        var verdictIcon = result.IsCompliant ? "✅" : "❌";
        var verdictText = result.IsCompliant ? "COMPLIANT" : "NON-COMPLIANT";

        if (quiet)
        {
            Console.ForegroundColor = verdictColor;
            Console.WriteLine($"{result.AdjustedScore}/100 ({result.AdjustedGrade}) [{verdictText}] profile={profile.Name}");
            Console.ForegroundColor = original;
            return;
        }

        // Banner
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📋 Compliance Assessment              ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Profile info
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Profile:   ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(profile.DisplayName);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  ({profile.Name})");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Audience:  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(profile.TargetAudience);

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Threshold: ");
        Console.ForegroundColor = GetScoreConsoleColor(profile.ComplianceThreshold);
        Console.WriteLine($"{profile.ComplianceThreshold}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Score comparison
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Raw Score:      ");
        Console.ForegroundColor = GetScoreConsoleColor(result.OriginalScore);
        Console.WriteLine($"{result.OriginalScore}/100 ({result.OriginalGrade})");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Adjusted Score: ");
        Console.ForegroundColor = GetScoreConsoleColor(result.AdjustedScore);
        Console.WriteLine($"{result.AdjustedScore}/100 ({result.AdjustedGrade})");

        var scoreDiff = result.AdjustedScore - result.OriginalScore;
        if (scoreDiff != 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Adjustment:     ");
            Console.ForegroundColor = scoreDiff > 0 ? ConsoleColor.Green : ConsoleColor.Red;
            var arrow = scoreDiff > 0 ? "↑" : "↓";
            Console.WriteLine($"{arrow} {Math.Abs(scoreDiff)} points (from profile weights & overrides)");
        }

        Console.ForegroundColor = original;
        Console.WriteLine();

        // Adjusted score bar
        int barLength = 40;
        int filled = (int)(result.AdjustedScore / 100.0 * barLength);
        int thresholdPos = (int)(profile.ComplianceThreshold / 100.0 * barLength);

        Console.Write("  ");
        Console.ForegroundColor = GetScoreConsoleColor(result.AdjustedScore);
        Console.Write(new string('█', filled));
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(new string('░', barLength - filled));
        Console.ForegroundColor = original;
        Console.Write($"  {result.AdjustedScore}%");

        // Show threshold marker
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  (threshold: {profile.ComplianceThreshold})");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Verdict
        Console.ForegroundColor = verdictColor;
        Console.WriteLine($"  {verdictIcon} {verdictText} — {profile.DisplayName} profile");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Profile adjustment summary
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"🔄 {result.OverridesApplied} overrides");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"⚖️ {result.ModulesWeighted} weighted");
        Console.ForegroundColor = original;
        Console.Write("  │  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"⏭️ {result.ModulesSkipped} skipped");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Module scores table
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-25} {"Score",6} {"Weight",7} {"Status",8}");
        Console.WriteLine($"  {new string('─', 25)} {new string('─', 6)} {new string('─', 7)} {new string('─', 8)}");
        Console.ForegroundColor = original;

        foreach (var mod in result.ModuleScores)
        {
            if (mod.Skipped)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {mod.Category,-25}");
                Console.Write($" {"—",6}");
                Console.Write($" {"skip",7}");
                Console.Write($" {"⏭️",8}");
                Console.ForegroundColor = original;
                Console.WriteLine();
                continue;
            }

            var scoreColor = GetScoreConsoleColor(mod.OriginalScore);
            var weightStr = $"×{mod.Weight:F1}";
            var weightColor = mod.Weight > 1.0 ? ConsoleColor.Yellow
                : mod.Weight < 1.0 ? ConsoleColor.DarkGray
                : original;

            Console.Write($"  {mod.Category,-25}");
            Console.ForegroundColor = scoreColor;
            Console.Write($" {mod.OriginalScore,6}");
            Console.ForegroundColor = weightColor;
            Console.Write($" {weightStr,7}");
            Console.ForegroundColor = original;

            if (mod.OverridesInModule > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($" 🔄{mod.OverridesInModule}");
            }

            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        Console.WriteLine();

        // Applied overrides detail
        if (result.AppliedOverrides.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ── Severity Overrides Applied ────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var ov in result.AppliedOverrides)
            {
                var fromColor = GetSeverityConsoleColor(ov.OriginalSeverity);
                var toColor = GetSeverityConsoleColor(ov.NewSeverity);

                Console.Write("  ");
                Console.ForegroundColor = fromColor;
                Console.Write($"{ov.OriginalSeverity}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" → ");
                Console.ForegroundColor = toColor;
                Console.Write($"{ov.NewSeverity}");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  {ov.FindingTitle}");
                Console.ForegroundColor = original;
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"       {ov.Reason}");
                Console.ForegroundColor = original;
            }

            Console.WriteLine();
        }

        // Recommendations
        if (result.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ── Profile Recommendations ───────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in result.Recommendations)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  💡 ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(rec);
            }

            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Get console color for a severity level.
    /// </summary>
    private static ConsoleColor GetSeverityConsoleColor(Severity severity) => severity switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.Warning => ConsoleColor.Yellow,
        Severity.Info => ConsoleColor.Cyan,
        Severity.Pass => ConsoleColor.Green,
        _ => ConsoleColor.DarkGray
    };

    // ── Ignore Rule Display ──────────────────────────────────────────

    /// <summary>
    /// Print a summary of how many findings were suppressed by ignore rules.
    /// </summary>
    public static void PrintIgnoredSummary(int count)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  🔇 ");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.Write($"{count} finding(s) suppressed");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(" by ignore rules (use --show-ignored to reveal)");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print details of all ignored/suppressed findings.
    /// </summary>
    public static void PrintIgnoredFindings(List<IgnoredFinding> ignored)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine($"  ┌─ Suppressed Findings ({ignored.Count})");
        Console.ForegroundColor = original;

        foreach (var item in ignored.OrderByDescending(i => i.Finding.Severity).ThenBy(i => i.Finding.Title))
        {
            var severityColor = item.Finding.Severity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.Warning => ConsoleColor.Yellow,
                Severity.Info => ConsoleColor.Cyan,
                _ => ConsoleColor.Green
            };

            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("  │  🔇 ");
            Console.ForegroundColor = severityColor;
            Console.Write($"[{item.Finding.Severity,-8}]");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {item.Finding.Title}");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  │     Rule: {item.MatchedRule.Id}");
            Console.Write($"  Pattern: \"{item.MatchedRule.Pattern}\" ({item.MatchedRule.MatchMode})");
            if (!string.IsNullOrEmpty(item.MatchedRule.Reason))
            {
                Console.Write($"  Reason: {item.MatchedRule.Reason}");
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("  └─────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print confirmation after adding an ignore rule.
    /// </summary>
    public static void PrintIgnoreRuleAdded(IgnoreRule rule)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🔇 Ignore Rule Added                  ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  ID:       ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(rule.Id);

        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Pattern:  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"\"{rule.Pattern}\"");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ({rule.MatchMode})");

        if (!string.IsNullOrEmpty(rule.Module))
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("  Module:   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule.Module);
        }

        if (rule.Severity.HasValue)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("  Severity: ");
            Console.ForegroundColor = GetSeverityConsoleColor(rule.Severity.Value);
            Console.WriteLine(rule.Severity.Value);
        }

        if (!string.IsNullOrEmpty(rule.Reason))
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("  Reason:   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule.Reason);
        }

        if (rule.ExpiresAt.HasValue)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("  Expires:  ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule.ExpiresAt.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
        }

        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✓ Matching findings will be suppressed in future audits.");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    Use --show-ignored with --audit to see suppressed findings.");
        Console.WriteLine($"    Remove with: winsentinel --ignore remove {rule.Id}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>
    /// Print a table of all ignore rules.
    /// </summary>
    public static void PrintIgnoreRuleList(List<IgnoreRule> rules, bool quiet = false)
    {
        var original = Console.ForegroundColor;

        if (!quiet)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════════╗");
            Console.WriteLine("  ║       🔇 Ignore Rules                       ║");
            Console.WriteLine("  ╚══════════════════════════════════════════════╝");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Table header
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"ID",-10} {"Pattern",-30} {"Mode",-10} {"Module",-15} {"Severity",-10} {"Status",-10}");
        Console.WriteLine($"  {new string('─', 10)} {new string('─', 30)} {new string('─', 10)} {new string('─', 15)} {new string('─', 10)} {new string('─', 10)}");
        Console.ForegroundColor = original;

        foreach (var rule in rules)
        {
            var statusColor = rule.IsActive ? ConsoleColor.Green
                : rule.IsExpired ? ConsoleColor.Red
                : ConsoleColor.DarkGray;
            var statusText = rule.IsActive ? "Active"
                : rule.IsExpired ? "Expired"
                : "Disabled";

            // Truncate pattern if too long
            var displayPattern = rule.Pattern.Length > 28
                ? rule.Pattern[..25] + "..."
                : rule.Pattern;

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {rule.Id,-10}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {displayPattern,-30}");
            Console.ForegroundColor = original;
            Console.Write($" {rule.MatchMode,-10}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {(rule.Module ?? "—"),-15}");

            if (rule.Severity.HasValue)
            {
                Console.ForegroundColor = GetSeverityConsoleColor(rule.Severity.Value);
                Console.Write($" {rule.Severity.Value,-10}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" {"Any",-10}");
            }

            Console.ForegroundColor = statusColor;
            Console.Write($" {statusText,-10}");
            Console.ForegroundColor = original;
            Console.WriteLine();

            // Show reason and expiry details if not quiet
            if (!quiet)
            {
                if (!string.IsNullOrEmpty(rule.Reason))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  └ {rule.Reason}");
                }
                if (rule.ExpiresAt.HasValue)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    var expiresStr = rule.IsExpired
                        ? $"Expired {rule.ExpiresAt.Value.ToLocalTime():yyyy-MM-dd}"
                        : $"Expires {rule.ExpiresAt.Value.ToLocalTime():yyyy-MM-dd}";
                    Console.WriteLine($"  └ ⏰ {expiresStr}");
                }
                Console.ForegroundColor = original;
            }
        }

        Console.WriteLine();

        if (!quiet)
        {
            var activeCount = rules.Count(r => r.IsActive);
            var expiredCount = rules.Count(r => r.IsExpired);
            var disabledCount = rules.Count(r => !r.Enabled);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{activeCount} active");
            if (expiredCount > 0)
            {
                Console.ForegroundColor = original;
                Console.Write("  │  ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{expiredCount} expired");
            }
            if (disabledCount > 0)
            {
                Console.ForegroundColor = original;
                Console.Write("  │  ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{disabledCount} disabled");
            }
            Console.ForegroundColor = original;
            Console.WriteLine($"  │  {rules.Count} total");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }
}
