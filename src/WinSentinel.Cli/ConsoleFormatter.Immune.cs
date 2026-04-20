using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintImmuneReport(SecurityImmuneSystem.ImmuneHealthReport report, CliOptions options)
    {

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🛡️  Security Immune System            ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        // ── Immunity Score Gauge ─────────────────────────────────────
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Overall Immunity: ");
        var scoreColor = report.OverallImmunityScore >= 80 ? ConsoleColor.Green
            : report.OverallImmunityScore >= 50 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.ForegroundColor = scoreColor;
        Console.Write($"{report.OverallImmunityScore}%");
        Console.ResetColor();

        // ASCII gauge bar
        int barWidth = 30;
        int filled = (int)(report.OverallImmunityScore / 100.0 * barWidth);
        Console.Write("  [");
        Console.ForegroundColor = scoreColor;
        Console.Write(new string('█', filled));
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(new string('░', barWidth - filled));
        Console.ResetColor();
        Console.WriteLine("]");

        // ── Antibody Summary ─────────────────────────────────────────
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Antibody Summary ──────────────────────────");
        Console.ResetColor();
        Console.Write("  Total: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.TotalAntibodies}");
        Console.ResetColor();
        Console.Write("  Active: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{report.ActiveAntibodies}");
        Console.ResetColor();
        Console.Write("  Weakened: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{report.WeakenedAntibodies}");
        Console.ResetColor();
        Console.Write("  Expired: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{report.ExpiredAntibodies}");
        Console.ResetColor();

        // ── Vaccination Card ─────────────────────────────────────────
        if (report.Vaccinations.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Vaccination Card ──────────────────────────");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Category               │ Antibodies │ Coverage │ Immunity  │ Last Booster");
            Console.WriteLine("  ───────────────────────┼────────────┼──────────┼───────────┼─────────────");
            Console.ResetColor();

            foreach (var vax in report.Vaccinations)
            {
                var cat = vax.ThreatCategory.Length > 22
                    ? vax.ThreatCategory[..22]
                    : vax.ThreatCategory.PadRight(22);
                var immColor = vax.ImmunityLevel switch
                {
                    "Full" => ConsoleColor.Green,
                    "Partial" => ConsoleColor.Yellow,
                    "Weakened" => ConsoleColor.DarkYellow,
                    _ => ConsoleColor.Red
                };
                Console.Write($"  {cat} │ ");
                Console.Write($"{vax.AntibodyCount,10} │ ");
                Console.ForegroundColor = immColor;
                Console.Write($"{vax.CoveragePercent,6:F1}% │ ");
                Console.Write($"{vax.ImmunityLevel,-9}");
                Console.ResetColor();
                Console.WriteLine($" │ {vax.LastBooster:yyyy-MM-dd}");
            }
        }

        // ── Threat Memory ────────────────────────────────────────────
        if (report.RecentThreats.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Threat Memory ─────────────────────────────");
            Console.ResetColor();

            foreach (var threat in report.RecentThreats.Take(15))
            {
                var icon = threat.IsImmunized ? "✓" : "⚠";
                var color = threat.IsImmunized ? ConsoleColor.Green : ConsoleColor.Yellow;
                var title = threat.FindingTitle.Length > 40
                    ? threat.FindingTitle[..40] + "..."
                    : threat.FindingTitle;

                Console.Write("  ");
                Console.ForegroundColor = color;
                Console.Write($"[{icon}]");
                Console.ResetColor();
                Console.Write($" {title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  ({threat.Module}, x{threat.RecurrenceCount})");
                Console.ResetColor();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine($"      → {threat.RecommendedAction}");
                Console.ResetColor();
            }
        }

        // ── Vulnerable Areas ─────────────────────────────────────────
        if (report.VulnerableAreas.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ── Vulnerable Areas (No Immunity) ───────────");
            Console.ResetColor();
            foreach (var area in report.VulnerableAreas)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("  ○ ");
                Console.ResetColor();
                Console.WriteLine(area);
            }
        }

        // ── Proactive Recommendations ────────────────────────────────
        if (report.ProactiveRecommendations.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Proactive Recommendations ─────────────────");
            Console.ResetColor();
            foreach (var rec in report.ProactiveRecommendations)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write("  → ");
                Console.ResetColor();
                Console.WriteLine(rec);
            }
        }

        Console.WriteLine();
    }
}
