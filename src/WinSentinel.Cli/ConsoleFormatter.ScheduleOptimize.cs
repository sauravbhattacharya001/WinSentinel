using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Console formatting for schedule optimization output.
/// </summary>
public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print the schedule optimization banner.
    /// </summary>
    public static void PrintScheduleOptimizeBanner(int runCount, string period)
    {
        WriteLineColored("", ConsoleColor.Cyan);
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║     ⏱️  Audit Schedule Optimizer             ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();
        WriteLineColored($"  Analyzed {runCount} audit runs over {period}", ConsoleColor.DarkGray);
        Console.WriteLine();
    }

    /// <summary>
    /// Print the full schedule optimization result.
    /// </summary>
    public static void PrintScheduleOptimizeResult(AuditScheduleOptimizer.ScheduleOptimizationResult result)
    {
        if (result.Modules.Count == 0)
        {
            WriteLineColored($"  {result.Summary}", ConsoleColor.Yellow);
            return;
        }

        var period = FormatOptPeriod(result.AnalysisPeriod);
        PrintScheduleOptimizeBanner(result.RunsAnalyzed, period);

        // Savings highlight
        if (result.EstimatedSavingsPercent > 0)
        {
            WriteColored("  💡 Estimated scan time savings: ", ConsoleColor.White);
            var savingsColor = result.EstimatedSavingsPercent >= 30 ? ConsoleColor.Green
                : result.EstimatedSavingsPercent >= 15 ? ConsoleColor.Yellow
                : ConsoleColor.DarkGray;
            WriteLineColored($"{result.EstimatedSavingsPercent:F1}%", savingsColor);
            Console.WriteLine();
        }

        // Module table
        WriteLineColored("  Module Volatility Analysis", ConsoleColor.White);
        WriteLineColored("  " + new string('─', 88), ConsoleColor.DarkGray);

        WriteColored("  ", ConsoleColor.DarkGray);
        WriteColored("Module".PadRight(28), ConsoleColor.DarkGray);
        WriteColored("Volatility".PadRight(12), ConsoleColor.DarkGray);
        WriteColored("Score Δ".PadRight(10), ConsoleColor.DarkGray);
        WriteColored("Churn".PadRight(10), ConsoleColor.DarkGray);
        WriteColored("Range".PadRight(10), ConsoleColor.DarkGray);
        WriteLineColored("Cadence", ConsoleColor.DarkGray);

        WriteLineColored("  " + new string('─', 88), ConsoleColor.DarkGray);

        foreach (var mod in result.Modules)
        {
            Console.Write("  ");
            WriteColored(Truncate(mod.ModuleName, 26).PadRight(28), ConsoleColor.White);

            var volColor = mod.VolatilityScore >= 50 ? ConsoleColor.Red
                : mod.VolatilityScore >= 25 ? ConsoleColor.Yellow
                : ConsoleColor.Green;
            WriteColored($"{mod.VolatilityScore,5:F1}".PadRight(12), volColor);

            WriteColored($"{mod.ScoreChangeRate,5:F2}".PadRight(10), ConsoleColor.Gray);
            WriteColored($"{mod.FindingChurnRate,5:F2}".PadRight(10), ConsoleColor.Gray);
            WriteColored($"{mod.MinScore}-{mod.MaxScore}".PadRight(10), ConsoleColor.Gray);

            var cadColor = mod.RecommendedCadence switch
            {
                AuditScheduleOptimizer.ScanCadence.EveryRun => ConsoleColor.Red,
                AuditScheduleOptimizer.ScanCadence.Hourly => ConsoleColor.DarkYellow,
                AuditScheduleOptimizer.ScanCadence.Daily => ConsoleColor.Yellow,
                AuditScheduleOptimizer.ScanCadence.Weekly => ConsoleColor.Cyan,
                AuditScheduleOptimizer.ScanCadence.Monthly => ConsoleColor.Green,
                _ => ConsoleColor.Gray
            };
            WriteLineColored(FormatCadence(mod.RecommendedCadence), cadColor);
        }

        WriteLineColored("  " + new string('─', 88), ConsoleColor.DarkGray);
        Console.WriteLine();

        // High priority callout
        if (result.HighPriority.Count > 0)
        {
            WriteLineColored("  🔴 High-Priority Modules (scan every run or hourly):", ConsoleColor.Red);
            foreach (var mod in result.HighPriority)
            {
                WriteColored("     • ", ConsoleColor.Red);
                WriteColored(mod.ModuleName, ConsoleColor.White);
                WriteLineColored($" — volatility {mod.VolatilityScore:F1}, {mod.FindingChurns} finding churns", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }

        // Low priority callout
        if (result.LowPriority.Count > 0)
        {
            WriteLineColored("  🟢 Low-Priority Modules (safe to scan weekly or monthly):", ConsoleColor.Green);
            foreach (var mod in result.LowPriority)
            {
                WriteColored("     • ", ConsoleColor.Green);
                WriteColored(mod.ModuleName, ConsoleColor.White);
                WriteLineColored($" — volatility {mod.VolatilityScore:F1}, score range {mod.MinScore}-{mod.MaxScore}", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }
    }

    private static string FormatCadence(AuditScheduleOptimizer.ScanCadence cadence) => cadence switch
    {
        AuditScheduleOptimizer.ScanCadence.EveryRun => "Every Run",
        AuditScheduleOptimizer.ScanCadence.Hourly => "Hourly",
        AuditScheduleOptimizer.ScanCadence.Daily => "Daily",
        AuditScheduleOptimizer.ScanCadence.Weekly => "Weekly",
        AuditScheduleOptimizer.ScanCadence.Monthly => "Monthly",
        _ => "Unknown"
    };

    private static string Truncate(string text, int maxLen) =>
        text.Length <= maxLen ? text : text[..(maxLen - 2)] + "..";

    private static string FormatOptPeriod(TimeSpan period)
    {
        if (period.TotalDays >= 1)
            return $"{(int)period.TotalDays} day(s)";
        if (period.TotalHours >= 1)
            return $"{(int)period.TotalHours} hour(s)";
        return $"{(int)period.TotalMinutes} minute(s)";
    }
}
