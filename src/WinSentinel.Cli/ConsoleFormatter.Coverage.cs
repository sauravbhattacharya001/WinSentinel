using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print the security coverage report in a visual map format.
    /// </summary>
    public static void PrintCoverage(SecurityCoverageService.CoverageReport report)
    {
        var orig = Console.ForegroundColor;
        Console.WriteLine();

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  🛡️  SECURITY COVERAGE MAP");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ══════════════════════════════════════════════════════════");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Summary bar
        Console.Write("  Coverage: ");
        Console.ForegroundColor = report.OverallCoveragePercent >= 80 ? ConsoleColor.Green
            : report.OverallCoveragePercent >= 60 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.Write($"{report.OverallCoveragePercent:F0}%");
        Console.ForegroundColor = orig;
        Console.Write($"  ({report.CoveredDomains}/{report.TotalDomains} domains)");
        if (report.GapDomains > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"  ⚠ {report.GapDomains} gap(s)");
        }
        Console.ForegroundColor = orig;
        Console.WriteLine();
        Console.WriteLine();

        // Visual coverage bar
        Console.Write("  [");
        int barWidth = 40;
        int filled = (int)(report.OverallCoveragePercent / 100.0 * barWidth);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(new string('█', filled));
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(new string('░', barWidth - filled));
        Console.ForegroundColor = orig;
        Console.WriteLine("]");
        Console.WriteLine();

        // Covered domains
        var coveredDomains = report.Domains.Where(d => !d.HasGap).OrderByDescending(d => d.TotalChecks).ToList();
        if (coveredDomains.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ COVERED DOMAINS");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            // Header row
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Domain",-28} {"Checks",7} {"Pass",6} {"Fail",6}  {"Health",7}");
            Console.ForegroundColor = orig;

            foreach (var d in coveredDomains)
            {
                Console.Write($"  {d.Domain,-28}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" {d.TotalChecks,7}");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($" {d.PassingChecks,6}");
                Console.ForegroundColor = d.FailingChecks > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
                Console.Write($" {d.FailingChecks,6}");
                Console.ForegroundColor = orig;

                // Mini health bar
                Console.Write("  ");
                if (d.TotalChecks > 0)
                {
                    double healthPct = (double)d.PassingChecks / d.TotalChecks * 100;
                    Console.ForegroundColor = healthPct >= 80 ? ConsoleColor.Green
                        : healthPct >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red;
                    int miniWidth = 8;
                    int miniFilled = (int)(healthPct / 100.0 * miniWidth);
                    Console.Write(new string('■', miniFilled));
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write(new string('□', miniWidth - miniFilled));
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("  active");
                }
                Console.ForegroundColor = orig;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Gap domains
        var gapDomains = report.Domains.Where(d => d.HasGap).ToList();
        if (gapDomains.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ⚠ COVERAGE GAPS");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            foreach (var d in gapDomains)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"  ○ {d.Domain,-25}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" {d.Description}");
                if (d.GapReason != null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"    └─ {d.GapReason}");
                }
                Console.ForegroundColor = orig;
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  💡 RECOMMENDATIONS");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            foreach (var rec in report.Recommendations)
            {
                Console.ForegroundColor = rec.StartsWith("  →") ? ConsoleColor.DarkGray : ConsoleColor.White;
                Console.WriteLine($"  {rec}");
            }
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    /// <summary>
    /// Print the coverage report in markdown format.
    /// </summary>
    public static string FormatCoverageMarkdown(SecurityCoverageService.CoverageReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# Security Coverage Map");
        sb.AppendLine();
        sb.AppendLine($"**Coverage:** {report.OverallCoveragePercent:F0}% ({report.CoveredDomains}/{report.TotalDomains} domains)");
        if (report.GapDomains > 0)
            sb.AppendLine($"**Gaps:** {report.GapDomains} domain(s) have no audit coverage");
        sb.AppendLine();

        sb.AppendLine("## Covered Domains");
        sb.AppendLine();
        sb.AppendLine("| Domain | Checks | Pass | Fail | Health |");
        sb.AppendLine("|--------|-------:|-----:|-----:|--------|");

        foreach (var d in report.Domains.Where(d => !d.HasGap))
        {
            string health = d.TotalChecks > 0
                ? $"{(double)d.PassingChecks / d.TotalChecks * 100:F0}%"
                : "Active";
            sb.AppendLine($"| {d.Domain} | {d.TotalChecks} | {d.PassingChecks} | {d.FailingChecks} | {health} |");
        }
        sb.AppendLine();

        var gaps = report.Domains.Where(d => d.HasGap).ToList();
        if (gaps.Count > 0)
        {
            sb.AppendLine("## Coverage Gaps");
            sb.AppendLine();
            foreach (var d in gaps)
            {
                sb.AppendLine($"- **{d.Domain}** — {d.Description}");
                if (d.GapReason != null)
                    sb.AppendLine($"  - {d.GapReason}");
            }
            sb.AppendLine();
        }

        if (report.Recommendations.Count > 0)
        {
            sb.AppendLine("## Recommendations");
            sb.AppendLine();
            foreach (var rec in report.Recommendations)
                sb.AppendLine($"- {rec}");
        }

        return sb.ToString();
    }
}
