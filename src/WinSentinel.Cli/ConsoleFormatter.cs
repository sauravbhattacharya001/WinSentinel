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
