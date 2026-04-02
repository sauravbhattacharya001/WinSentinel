namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintChangelog(ChangelogReport report)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📋  Security Changelog                ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (report.Periods.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit history found. Run at least two audits to generate a changelog.");
            Console.ResetColor();
            return;
        }

        // Overview
        Console.WriteLine();
        Console.Write("  Period: ");
        WriteColored($"{report.StartDate:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write(" → ");
        WriteColored($"{report.EndDate:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write($"  ({report.TotalDays} days, {report.TotalAudits} audits)");
        Console.WriteLine();

        Console.Write("  Score: ");
        var startColor = ChangelogScoreColor(report.StartScore);
        var endColor = ChangelogScoreColor(report.EndScore);
        WriteColored($"{report.StartScore}", startColor);
        Console.Write(" → ");
        WriteColored($"{report.EndScore}", endColor);
        var scoreDelta = report.EndScore - report.StartScore;
        Console.Write("  (");
        var deltaStr = scoreDelta >= 0 ? $"+{scoreDelta}" : $"{scoreDelta}";
        WriteColored(deltaStr, scoreDelta >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine(")");

        // Net stats
        Console.Write("  Net: ");
        WriteColored($"+{report.TotalNew} new", ConsoleColor.Red);
        Console.Write(", ");
        WriteColored($"-{report.TotalResolved} resolved", ConsoleColor.Green);

        if (report.TotalNew > report.TotalResolved)
        {
            Console.Write("  ");
            WriteColored("⚠ findings growing", ConsoleColor.Yellow);
        }
        else if (report.TotalResolved > report.TotalNew)
        {
            Console.Write("  ");
            WriteColored("✓ findings shrinking", ConsoleColor.Green);
        }
        Console.WriteLine();

        // Per-period breakdown
        foreach (var period in report.Periods)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"  ── {period.Label} ({period.AuditCount} audit{(period.AuditCount == 1 ? "" : "s")}) ──");
            Console.ResetColor();

            Console.Write("    Score: ");
            WriteColored($"{period.StartScore}", ChangelogScoreColor(period.StartScore));
            Console.Write(" → ");
            WriteColored($"{period.EndScore}", ChangelogScoreColor(period.EndScore));
            Console.WriteLine();

            if (period.NewFindings.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"    🔴 New ({period.NewFindings.Count}):");
                Console.ResetColor();
                foreach (var f in period.NewFindings.Take(8))
                {
                    Console.Write("      ");
                    var sevColor = ChangelogSeverityColor(f.Severity);
                    WriteColored($"[{f.Severity}]", sevColor);
                    Console.Write($" {f.Title}");
                    if (!string.IsNullOrEmpty(f.Module))
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write($" ({f.Module})");
                        Console.ResetColor();
                    }
                    Console.WriteLine();
                }
                if (period.NewFindings.Count > 8)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"      ... and {period.NewFindings.Count - 8} more");
                    Console.ResetColor();
                }
            }

            if (period.ResolvedFindings.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"    🟢 Resolved ({period.ResolvedFindings.Count}):");
                Console.ResetColor();
                foreach (var f in period.ResolvedFindings.Take(8))
                {
                    Console.Write("      ");
                    var sevColor = ChangelogSeverityColor(f.Severity);
                    WriteColored($"[{f.Severity}]", sevColor);
                    Console.Write($" {f.Title}");
                    if (!string.IsNullOrEmpty(f.Module))
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write($" ({f.Module})");
                        Console.ResetColor();
                    }
                    Console.WriteLine();
                }
                if (period.ResolvedFindings.Count > 8)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"      ... and {period.ResolvedFindings.Count - 8} more");
                    Console.ResetColor();
                }
            }

            if (period.NewFindings.Count == 0 && period.ResolvedFindings.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    No changes");
                Console.ResetColor();
            }
        }

        // Module impact summary
        if (report.ModuleImpact.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("  ── MODULE IMPACT ──");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ┌────────────────────────┬──────┬──────────┬──────────┐");
            Console.WriteLine("  │ Module                 │ Net  │ New      │ Resolved │");
            Console.WriteLine("  ├────────────────────────┼──────┼──────────┼──────────┤");
            Console.ResetColor();

            foreach (var m in report.ModuleImpact.OrderByDescending(x => Math.Abs(x.Net)).Take(10))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  │ ");
                Console.ResetColor();
                Console.Write($"{Truncate(m.Module, 22),-22}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" │ ");
                var netColor = m.Net <= 0 ? ConsoleColor.Green : ConsoleColor.Red;
                var netStr = m.Net >= 0 ? $"+{m.Net}" : $"{m.Net}";
                WriteColored($"{netStr,4}", netColor);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" │ ");
                WriteColored($"{m.NewCount,8}", ConsoleColor.Red);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" │ ");
                WriteColored($"{m.ResolvedCount,8}", ConsoleColor.Green);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" │");
                Console.ResetColor();
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └────────────────────────┴──────┴──────────┴──────────┘");
            Console.ResetColor();
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ℹ Changelog compares findings between consecutive audits to detect drift.");
        Console.WriteLine("    Use --changelog-days N to adjust the lookback window (default: 30).");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static ConsoleColor ChangelogSeverityColor(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" => ConsoleColor.Red,
            "warning" => ConsoleColor.Yellow,
            "info" => ConsoleColor.Cyan,
            _ => ConsoleColor.White
        };

    private static ConsoleColor ChangelogScoreColor(int score) =>
        score >= 80 ? ConsoleColor.Green :
        score >= 60 ? ConsoleColor.Yellow :
        ConsoleColor.Red;
}

// ── Changelog Models ────────────────────────────────────────────

public class ChangelogReport
{
    public DateTimeOffset StartDate { get; set; }
    public DateTimeOffset EndDate { get; set; }
    public int TotalDays { get; set; }
    public int TotalAudits { get; set; }
    public int StartScore { get; set; }
    public int EndScore { get; set; }
    public int TotalNew { get; set; }
    public int TotalResolved { get; set; }
    public List<ChangelogPeriod> Periods { get; set; } = [];
    public List<ModuleImpactEntry> ModuleImpact { get; set; } = [];
}

public class ChangelogPeriod
{
    public string Label { get; set; } = "";
    public int AuditCount { get; set; }
    public int StartScore { get; set; }
    public int EndScore { get; set; }
    public List<ChangelogFinding> NewFindings { get; set; } = [];
    public List<ChangelogFinding> ResolvedFindings { get; set; } = [];
}

public class ChangelogFinding
{
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Module { get; set; } = "";
}

public class ModuleImpactEntry
{
    public string Module { get; set; } = "";
    public int NewCount { get; set; }
    public int ResolvedCount { get; set; }
    public int Net => NewCount - ResolvedCount;
}
