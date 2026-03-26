using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles all console output formatting with color-coded severity,
/// progress indicators, and clean table output.
/// </summary>
public static partial class ConsoleFormatter
{
    // ── Shared color helpers ────────────────────────────────────────
    // Eliminates the repetitive save/restore ForegroundColor pattern
    // that appeared 22+ times across this file.

    /// <summary>Write <paramref name="text"/> in the given color, then restore.</summary>
    private static void WriteColored(string text, ConsoleColor color)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = prev;
    }

    /// <summary>Write <paramref name="text"/> + newline in the given color, then restore.</summary>
    private static void WriteLineColored(string text, ConsoleColor color)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = prev;
    }

    /// <summary>
    /// Print a help-text entry: highlighted option name followed by its description
    /// in the default foreground color.  Replaces the 4-line
    /// <c>ForegroundColor = White / Write(option) / ForegroundColor = original / WriteLine(desc)</c>
    /// pattern that was repeated 40+ times in <see cref="PrintHelp"/>.
    /// </summary>
    private static void WriteHelpEntry(string option, string description)
    {
        WriteColored(option, ConsoleColor.White);
        Console.WriteLine(description);
    }

    /// <summary>
    /// Print the application banner.
    /// </summary>
    public static void PrintBanner()
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🛡️  WinSentinel Security Audit        ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();
    }

    /// <summary>
    /// Print a progress update for a module being scanned.
    /// </summary>
    public static void PrintProgress(string moduleName, int current, int total)
    {
        WriteColored($"\r  [{current}/{total}] Scanning {moduleName,-25}", ConsoleColor.DarkGray);
    }

    /// <summary>
    /// Clear the progress line and print completion.
    /// </summary>
    public static void PrintProgressDone(int total, TimeSpan elapsed)
    {
        Console.Write("\r" + new string(' ', 60) + "\r");
        WriteColored($"  ✓ Scanned {total} modules", ConsoleColor.Green);
        WriteLineColored($" in {elapsed.TotalSeconds:F1}s", ConsoleColor.DarkGray);
        Console.WriteLine();
    }

    /// <summary>
    /// Print the overall score and grade with color coding.
    /// </summary>
    public static void PrintScore(int score, bool quiet = false)
    {
        var grade = SecurityScorer.GetGrade(score);
        var color = GetScoreConsoleColor(score);

        if (quiet)
        {
            WriteLineColored($"{score}/100 ({grade})", color);
            return;
        }

        Console.Write("  Security Score: ");
        WriteColored($"{score}/100", color);
        Console.Write("  Grade: ");
        WriteLineColored(grade, color);

        // Score bar
        int barLength = 40;
        int filled = (int)(score / 100.0 * barLength);
        Console.Write("  ");
        WriteColored(new string('█', filled), color);
        WriteColored(new string('░', barLength - filled), ConsoleColor.DarkGray);
        Console.WriteLine($"  {score}%");
        Console.WriteLine();
    }

    /// <summary>
    /// Print summary statistics.
    /// </summary>
    public static void PrintSummary(SecurityReport report)
    {
        Console.Write("  Findings: ");
        WriteColored($"{report.TotalCritical} critical", ConsoleColor.Red);
        Console.Write(" │ ");
        WriteColored($"{report.TotalWarnings} warnings", ConsoleColor.Yellow);
        Console.Write(" │ ");
        WriteColored($"{report.TotalInfo} info", ConsoleColor.Cyan);
        Console.Write(" │ ");
        WriteColored($"{report.TotalPass} pass", ConsoleColor.Green);
        Console.WriteLine($" │ {report.TotalFindings} total");
        Console.WriteLine();
    }

    /// <summary>
    /// Print a module breakdown table.
    /// </summary>
    public static void PrintModuleTable(SecurityReport report)
    {
        // Header
        WriteLineColored($"  {"Module",-22} {"Score",6} {"Grade",6} {"Crit",6} {"Warn",6} {"Total",6}  Status", ConsoleColor.DarkGray);
        WriteLineColored($"  {new string('─', 22)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)} {new string('─', 6)}  {new string('─', 6)}", ConsoleColor.DarkGray);

        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            var color = GetScoreConsoleColor(modScore);
            var original = Console.ForegroundColor;
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
            WriteColored($"{modScore,6} {modGrade,6}", color);
            WriteColored($" {result.CriticalCount,6}", result.CriticalCount > 0 ? ConsoleColor.Red : original);
            WriteColored($" {result.WarningCount,6}", result.WarningCount > 0 ? ConsoleColor.Yellow : original);
            Console.Write($" {result.Findings.Count,6}  ");
            WriteLineColored(status, statusColor);
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print detailed findings grouped by module.
    /// </summary>
    public static void PrintFindings(SecurityReport report)
    {
        foreach (var result in report.Results)
        {
            var actionableFindings = result.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Title)
                .ToList();

            if (actionableFindings.Count == 0) continue;

            WriteLineColored($"  ┌─ {result.Category}", ConsoleColor.White);

            foreach (var finding in actionableFindings)
            {
                var (icon, color) = finding.Severity switch
                {
                    Severity.Critical => ("CRITICAL", ConsoleColor.Red),
                    Severity.Warning => ("WARNING ", ConsoleColor.Yellow),
                    _ => ("INFO    ", ConsoleColor.Cyan)
                };

                Console.Write("  │  ");
                WriteColored($"[{icon}]", color);
                WriteLineColored($" {finding.Title}", ConsoleColor.White);
                WriteLineColored($"  │    {finding.Description}", ConsoleColor.DarkGray);

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    WriteLineColored($"  │    → {finding.Remediation}", ConsoleColor.Green);
                }
            }

            WriteLineColored("  └─────────────────────────────────", ConsoleColor.DarkGray);
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print fix results.
    /// </summary>
    public static void PrintFixResults(List<(Finding finding, FixResult result)> results)
    {
        WriteLineColored("  Fix Results:", ConsoleColor.White);
        Console.WriteLine();

        int success = 0, failed = 0, skipped = 0;

        foreach (var (finding, fixResult) in results)
        {
            if (fixResult.Success)
            {
                success++;
                WriteColored("  ✓ ", ConsoleColor.Green);
            }
            else if (string.IsNullOrWhiteSpace(finding.FixCommand))
            {
                skipped++;
                WriteColored("  ○ ", ConsoleColor.DarkGray);
            }
            else
            {
                failed++;
                WriteColored("  ✗ ", ConsoleColor.Red);
            }

            Console.Write(finding.Title);

            if (fixResult.Success)
            {
                WriteLineColored(" (fixed)", ConsoleColor.DarkGray);
            }
            else if (string.IsNullOrWhiteSpace(finding.FixCommand))
            {
                WriteLineColored(" (no fix available)", ConsoleColor.DarkGray);
            }
            else
            {
                WriteLineColored($" ({fixResult.Error ?? "failed"})", ConsoleColor.DarkGray);
            }
        }

        Console.WriteLine();
        Console.Write($"  Summary: ");
        WriteColored($"{success} fixed", ConsoleColor.Green);
        Console.Write(" │ ");
        WriteColored($"{failed} failed", ConsoleColor.Red);
        Console.Write(" │ ");
        WriteLineColored($"{skipped} skipped", ConsoleColor.DarkGray);
        Console.WriteLine();
    }

    /// <summary>
    /// Print help text.
    /// </summary>
    public static void PrintHelp()
    {
        WriteLineColored("  WinSentinel — Windows Security Auditing CLI", ConsoleColor.Cyan);
        Console.WriteLine();
        Console.WriteLine("  USAGE:");
        WriteLineColored("    winsentinel <command> [options]", ConsoleColor.White);
        Console.WriteLine();
        Console.WriteLine("  COMMANDS:");
        WriteHelpEntry("    --audit, -a          ", "Run full security audit and print results");
        WriteHelpEntry("    --score, -s          ", "Print security score and grade only");
        WriteHelpEntry("    --fix-all, -f        ", "Run audit and auto-fix all fixable findings");
        WriteHelpEntry("    --history            ", "View past audit runs and score trends");
        WriteHelpEntry("    --baseline <action>  ", "Manage security baselines (save/list/check/delete)");
        WriteHelpEntry("    --checklist          ", "Generate prioritized remediation checklist");
        WriteHelpEntry("    --profiles           ", "List available compliance profiles");
        WriteHelpEntry("    --ignore <action>    ", "Manage finding ignore rules (add/list/remove/clear/purge)");
        WriteHelpEntry("    --trend              ", "Show security score trend analysis over time");
        WriteHelpEntry("    --age [action]       ", "Finding age tracker (report/priority/chronic/new/resolved)");
        WriteHelpEntry("    --status             ", "Quick security posture dashboard (no new scan)");
        WriteHelpEntry("    --harden             ", "Generate reviewable PowerShell hardening script");
        WriteHelpEntry("    --policy <action>    ", "Security Policy as Code (export/import/validate/diff)");
        WriteHelpEntry("    --threats            ", "STRIDE threat model from audit findings");
        WriteHelpEntry("    --attack-paths       ", "Kill chain attack path analysis with chokepoints");
        WriteHelpEntry("    --summary            ", "Executive security summary (plain-English brief)");
        WriteHelpEntry("    --help, -h           ", "Show this help message");
        WriteHelpEntry("    --version, -v        ", "Show version information");
        Console.WriteLine();
        Console.WriteLine("  OPTIONS:");
        WriteHelpEntry("    --json, -j           ", "Output results as JSON (machine-parseable)");
        WriteHelpEntry("    --html               ", "Output results as HTML report");
        WriteHelpEntry("    --markdown, --md     ", "Output results as Markdown (GitHub-flavored)");
        WriteHelpEntry("    --csv                ", "Output results as CSV (one row per finding)");
        WriteHelpEntry("    -o, --output <file>  ", "Save output to file instead of stdout");
        WriteHelpEntry("    --modules, -m <list> ", "Run only specific modules (comma-separated)");
        WriteHelpEntry("    --quiet, -q          ", "Minimal output (score + exit code only)");
        WriteHelpEntry("    --profile, -p <name> ", "Apply compliance profile (home/developer/enterprise/server)");
        WriteHelpEntry("    --threshold, -t <n>  ", "Exit with error if score below n (0-100)");
        WriteHelpEntry("    --compare            ", "Compare latest two runs side-by-side (with --history)");
        WriteHelpEntry("    --diff               ", "Show new/resolved findings between runs (with --history)");
        WriteHelpEntry("    --days <n>           ", "History lookback period in days (default: 30)");
        WriteHelpEntry("    --limit, -l <n>      ", "Max number of history entries to show (default: 20)");
        WriteHelpEntry("    --desc <text>        ", "Description for a baseline (with --baseline save)");
        WriteHelpEntry("    --force              ", "Overwrite existing baseline (with --baseline save)");
        WriteHelpEntry("    --show-ignored       ", "Show suppressed findings in audit output");
        WriteHelpEntry("    --ignore-module <m>  ", "Scope ignore rule to a specific module (with --ignore add)");
        WriteHelpEntry("    --ignore-severity <s>", " Scope ignore rule to a severity (critical/warning/info/pass)");
        WriteHelpEntry("    --ignore-reason <r>  ", "Reason for ignoring (with --ignore add)");
        WriteHelpEntry("    --match-mode <mode>  ", "Pattern matching: exact, contains (default), or regex");
        WriteHelpEntry("    --expire-days <n>    ", "Auto-expire ignore rule after n days (1-3650)");
        WriteHelpEntry("    --trend-days <n>     ", "Trend analysis lookback period in days (default: 30)");
        WriteHelpEntry("    --alert-below <n>    ", "Alert if current score is below n (with --trend)");
        WriteHelpEntry("    --trend-modules      ", "Include per-module trend breakdown (with --trend)");
        WriteHelpEntry("    --age-days <n>       ", "Finding age lookback period in days (default: 90)");
        WriteHelpEntry("    --age-severity <s>   ", "Filter age report by severity (critical/warning/info)");
        WriteHelpEntry("    --age-module <m>     ", "Filter age report by module name");
        WriteHelpEntry("    --age-class <c>      ", "Filter by classification (chronic/recurring/new/intermittent)");
        WriteHelpEntry("    --age-top <n>        ", "Number of findings to show (default: 10)");
        WriteHelpEntry("    --summary-format <f> ", "Summary format: text (default), json, md");
        WriteHelpEntry("    --summary-trend-days ", "Trend lookback for summary (default: 30)");
        Console.WriteLine();
        WriteLineColored("  PEER BENCHMARK:", ConsoleColor.Yellow);
        WriteHelpEntry("    --benchmark              ", "Compare scores against peer group benchmarks");
        WriteHelpEntry("    --benchmark-group <g>    ", "Peer group: home, developer, enterprise, server, auto (default)");
        WriteHelpEntry("    --benchmark-format <f>   ", "Output format: text (default), json");
        WriteHelpEntry("    --benchmark-all          ", "Compare against all peer groups at once");
        Console.WriteLine();
        WriteLineColored("  COMPLIANCE MAPPING:", ConsoleColor.Yellow);
        WriteHelpEntry("    --compliance             ", "Map findings to compliance frameworks (CIS, NIST, PCI-DSS, HIPAA)");
        WriteHelpEntry("    --compliance-framework <f>", "Single framework: cis, nist, pci-dss, hipaa");
        WriteHelpEntry("    --compliance-format <f>  ", "Output format: text (default), json, markdown");
        WriteHelpEntry("    --compliance-gaps        ", "Show only failing/partial controls (gap analysis)");
        WriteHelpEntry("    --compliance-all         ", "Show all frameworks in detail");
        Console.WriteLine();
        WriteLineColored("  SYSTEM INVENTORY:", ConsoleColor.Yellow);
        WriteHelpEntry("    --inventory              ", "Snapshot installed apps, services, ports, startup, tasks");
        WriteHelpEntry("    --inventory-format <f>   ", "Output format: text (default), json, markdown");
        WriteHelpEntry("    --no-apps                ", "Skip installed applications");
        WriteHelpEntry("    --no-services            ", "Skip Windows services");
        WriteHelpEntry("    --no-ports               ", "Skip listening ports");
        WriteHelpEntry("    --no-startup             ", "Skip startup programs");
        WriteHelpEntry("    --no-tasks               ", "Skip scheduled tasks");
        Console.WriteLine();
        WriteLineColored("  FINDING TAG MANAGEMENT:", ConsoleColor.Yellow);
        WriteHelpEntry("    --tag [action]           ", "Manage finding tags (add/remove/list/search/report/autotag/rename/delete/export/import)");
        WriteHelpEntry("    --tag-finding <title>    ", "Finding title to tag");
        WriteHelpEntry("    --tag-category <cat>     ", "Finding category/module (default: Unknown)");
        WriteHelpEntry("    --tag-value <tag>        ", "Tag value (repeatable for multiple tags)");
        WriteHelpEntry("    --tag-search <query>     ", "Search findings by title, category, or tag");
        WriteHelpEntry("    --tag-note <text>        ", "Add an annotation/note when tagging");
        WriteHelpEntry("    --tag-author <name>      ", "Author for annotations");
        WriteHelpEntry("    --tag-rename-from <old>  ", "Tag to rename (with --tag rename)");
        WriteHelpEntry("    --tag-rename-to <new>    ", "New tag name (with --tag rename)");
        WriteHelpEntry("    --tag-file <path>        ", "File path for tag export/import");
        WriteHelpEntry("    --tag-no-merge           ", "Overwrite on import (default: merge)");
        Console.WriteLine();
        Console.WriteLine("  EXAMPLES:");
        WriteLineColored("    winsentinel --audit                              # Full audit with colored output", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --json                       # JSON output for scripting", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --html -o report.html        # Save HTML report", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --markdown -o report.md       # Save Markdown report", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --modules firewall,network   # Scan specific modules", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --score                              # Quick score check", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --score --quiet                      # Score only, no formatting", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --threshold 90               # CI/CD gate: fail if < 90", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --fix-all                            # Auto-fix all findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --history                            # View past audit runs", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --history --compare                  # Compare latest two runs", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --history --diff                     # Show new/resolved findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --history --json                     # History as JSON", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --history --days 7                   # Last 7 days only", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline save prod                 # Save current state as baseline", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline save prod --desc \"...\"    # With description", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline list                      # List all saved baselines", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline check prod                # Check current vs baseline", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline check prod --json         # Check result as JSON", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --baseline delete prod               # Delete a baseline", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --checklist                          # Prioritized fix plan", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --checklist --json                   # Checklist as JSON", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --checklist -m firewall,network      # Checklist for specific modules", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --profiles                           # List compliance profiles", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --profile home               # Audit with Home profile", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --profile enterprise         # Audit with Enterprise profile", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --profile server --json      # Server profile as JSON", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"Remote Desktop\"          # Suppress findings containing text", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"SMB\" --ignore-reason \"Accepted risk\"", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"Telemetry\" --match-mode exact  # Exact title match", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"^BitLocker\" --match-mode regex  # Regex pattern", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"LLMNR\" --ignore-module network  # Module-scoped", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"audit\" --ignore-severity warning  # Severity-scoped", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore add \"test\" --expire-days 30   # Auto-expire in 30 days", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore list                          # Show all ignore rules", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore remove abc12345               # Remove rule by ID", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore clear                         # Remove all rules", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --ignore purge                         # Remove expired rules", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --audit --show-ignored                 # Audit showing suppressed findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --trend                                # Score trend analysis", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --trend --trend-days 90                # 90-day trend window", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --trend --alert-below 80               # Alert if score < 80", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --trend --trend-modules                # Include per-module breakdown", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --trend --json                         # Trend data as JSON", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age                                   # Full finding age report", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age priority                           # Priority queue (fix first)", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age chronic                            # Show chronic findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age new                                # Show new findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age resolved                           # Show resolved findings", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age --age-severity critical            # Critical findings only", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age --age-module firewall              # Filter by module", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --age --age-days 7 --json               # Last 7 days as JSON", ConsoleColor.DarkGray);
        Console.WriteLine();
        WriteLineColored("  NOISE ANALYSIS:", ConsoleColor.Yellow);
        WriteHelpEntry("    --noise                  ", "Identify noisiest finding sources across audit history");
        WriteHelpEntry("    --noise-days <n>         ", "Analysis window in days (default: 90)");
        WriteHelpEntry("    --noise-top <n>          ", "Number of top noisy items to show (default: 15)");
        WriteHelpEntry("    --noise-format <fmt>     ", "Output format: text, json, markdown");
        WriteLineColored("    winsentinel --noise                                 # Full noise analysis", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --noise --noise-days 30 --noise-top 5   # Last 30 days, top 5", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --noise --json                          # Noise data as JSON", ConsoleColor.DarkGray);
        Console.WriteLine();
        WriteLineColored("  CALENDAR HEATMAP:", ConsoleColor.Yellow);
        WriteHelpEntry("    --heatmap                ", "Show GitHub-style calendar heatmap of audit activity");
        WriteHelpEntry("    --heatmap-weeks <n>      ", "Number of weeks to display (default: 26)");
        WriteHelpEntry("    --heatmap-format <fmt>   ", "Output format: text, json, markdown");
        WriteLineColored("    winsentinel --heatmap                               # 6-month activity heatmap", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --heatmap --heatmap-weeks 52            # Full year heatmap", ConsoleColor.DarkGray);
        WriteLineColored("    winsentinel --heatmap --json                        # Heatmap data as JSON", ConsoleColor.DarkGray);
        Console.WriteLine();
        Console.WriteLine("  EXIT CODES:");
        Console.WriteLine("    0  All checks pass (or score >= threshold)");
        Console.WriteLine("    1  Warnings found (or score < threshold)");
        Console.WriteLine("    2  Critical findings found (or trend alert triggered)");
        Console.WriteLine("    3  Error during execution");
        Console.WriteLine();
        Console.WriteLine("  AVAILABLE MODULES:");
        WriteLineColored("    firewall, updates, defender, accounts, network,", ConsoleColor.DarkGray);
        WriteLineColored("    processes, startup, system, privacy, browser,", ConsoleColor.DarkGray);
        WriteLineColored("    appsecurity, encryption, eventlog", ConsoleColor.DarkGray);
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

    // ── Trend Analysis Display ───────────────────────────────────────────

    /// <summary>
    /// Print a warning message (yellow).
    /// </summary>
    public static void PrintWarning(string message)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  ⚠ ");
        Console.ForegroundColor = original;
        Console.WriteLine(message);
        Console.WriteLine();
    }

    /// <summary>
    /// Print the Security KPI dashboard to the console.
    /// </summary>
    public static void PrintKpiReport(SecurityKpiReport report, bool quiet)
    {
        if (!quiet)
        {
            PrintBanner();
        }

        var healthColor = report.HealthScore >= 90 ? ConsoleColor.Green
            : report.HealthScore >= 75 ? ConsoleColor.DarkGreen
            : report.HealthScore >= 60 ? ConsoleColor.Yellow
            : report.HealthScore >= 40 ? ConsoleColor.DarkYellow
            : ConsoleColor.Red;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("  📊 SECURITY KPI DASHBOARD");
        Console.ResetColor();
        Console.ForegroundColor = healthColor;
        Console.Write($"   [{report.HealthRating} {report.HealthScore}/100]");
        Console.ResetColor();
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ─── {report.PeriodStart:yyyy-MM-dd} → {report.PeriodEnd:yyyy-MM-dd}  ({report.DaysSpan} days, {report.RunsAnalyzed} scans) ───");
        Console.ResetColor();
        Console.WriteLine();

        // Score KPIs
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("SCORE");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                            ║");

        var trendArrow = report.ScoreChange > 0 ? "↑" : report.ScoreChange < 0 ? "↓" : "→";
        var trendColor = report.ScoreChange > 0 ? ConsoleColor.Green : report.ScoreChange < 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;

        Console.Write("  ║   Current: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.CurrentScore,3}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   Avg: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.AverageScore,5:F1}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   Trend: ");
        Console.ForegroundColor = trendColor;
        Console.Write($"{trendArrow}{Math.Abs(report.ScoreChange),3}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"   σ={report.ScoreVolatility,4:F1}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ║");

        Console.WriteLine("  ╠══════════════════════════════════════════════════╣");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("FINDINGS");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                         ║");

        var netColor = report.FindingNetChange < 0 ? ConsoleColor.Green : report.FindingNetChange > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
        Console.Write("  ║   Current: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.CurrentFindings,3}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   New: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{report.NewFindings,3}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   Resolved: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{report.ResolvedFindings,3}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   Net: ");
        Console.ForegroundColor = netColor;
        Console.Write($"{report.FindingNetChange:+#;-#;0}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ║");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ║   Recurring: ");
        Console.ForegroundColor = report.RecurrenceRate > 20 ? ConsoleColor.Red : report.RecurrenceRate > 10 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.Write($"{report.RecurringFindings} ({report.RecurrenceRate}%)");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(new string(' ', Math.Max(1, 36 - $"{report.RecurringFindings} ({report.RecurrenceRate}%)".Length)) + "║");

        Console.WriteLine("  ╠══════════════════════════════════════════════════╣");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("SEVERITY & MTTR");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                  ║");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ║   Critical: ");
        Console.ForegroundColor = report.CurrentCritical > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.CurrentCritical}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  Warnings: ");
        Console.ForegroundColor = report.CurrentWarnings > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.Write($"{report.CurrentWarnings}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  Peak Crit: {report.PeakCritical}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(new string(' ', Math.Max(1, 20 - $"  Peak Crit: {report.PeakCritical}".Length)) + "║");

        var mttrCrit = report.MeanTimeToRemediateCritical.HasValue ? $"{report.MeanTimeToRemediateCritical:F1}d" : "N/A";
        var mttrWarn = report.MeanTimeToRemediateWarning.HasValue ? $"{report.MeanTimeToRemediateWarning:F1}d" : "N/A";
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  ║   MTTR Critical: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(mttrCrit);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"   MTTR Warning: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(mttrWarn);
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(new string(' ', Math.Max(1, 33 - mttrCrit.Length - mttrWarn.Length)) + "║");

        Console.WriteLine("  ╠══════════════════════════════════════════════════╣");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("SECURITY DEBT");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                    ║");

        var debtColor = report.DebtTrend == "Decreasing" ? ConsoleColor.Green : report.DebtTrend == "Increasing" ? ConsoleColor.Red : ConsoleColor.DarkGray;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ║   Debt: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.SecurityDebt:F1}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("   Trend: ");
        Console.ForegroundColor = debtColor;
        Console.Write($"{report.DebtTrend} ({report.DebtChange:+#.#;-#.#;0})");
        Console.ForegroundColor = ConsoleColor.White;
        var debtInfo = $"{report.SecurityDebt:F1}   Trend: {report.DebtTrend} ({report.DebtChange:+#.#;-#.#;0})";
        Console.WriteLine(new string(' ', Math.Max(1, 41 - debtInfo.Length)) + "║");

        Console.WriteLine("  ╠══════════════════════════════════════════════════╣");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("SCAN CADENCE");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                     ║");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ║   Scans/Week: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.ScansPerWeek}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"   Avg Gap: {report.AvgDaysBetweenScans}d");
        Console.Write($"   Max Gap: {report.MaxScanGap}d");
        Console.ForegroundColor = ConsoleColor.White;
        var cadenceInfo = $"{report.ScansPerWeek}   Avg Gap: {report.AvgDaysBetweenScans}d   Max Gap: {report.MaxScanGap}d";
        Console.WriteLine(new string(' ', Math.Max(1, 35 - cadenceInfo.Length)) + "║");

        Console.WriteLine("  ╠══════════════════════════════════════════════════╣");
        Console.Write("  ║ ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("MODULES");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("                                          ║");

        if (report.WeakestModule != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  ║   Weakest: ");
            Console.ForegroundColor = ConsoleColor.Red;
            var weakStr = $"{report.WeakestModule} ({report.WeakestModuleScore}/100)";
            Console.Write(weakStr);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(new string(' ', Math.Max(1, 38 - weakStr.Length)) + "║");
        }
        if (report.MostImprovedModule != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  ║   Most Improved: ");
            Console.ForegroundColor = ConsoleColor.Green;
            var impStr = $"{report.MostImprovedModule} (+{report.MostImprovedChange})";
            Console.Write(impStr);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(new string(' ', Math.Max(1, 32 - impStr.Length)) + "║");
        }
        if (report.MostRegressedModule != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  ║   Most Regressed: ");
            Console.ForegroundColor = ConsoleColor.Red;
            var regStr = $"{report.MostRegressedModule} ({report.MostRegressedChange})";
            Console.Write(regStr);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(new string(' ', Math.Max(1, 31 - regStr.Length)) + "║");
        }

        Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
        Console.ResetColor();

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  💡 Recommendations:");
            Console.ResetColor();
            foreach (var rec in report.Recommendations)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("     • ");
                Console.ResetColor();
                Console.WriteLine(rec);
            }
        }

        Console.WriteLine();
    }

}
