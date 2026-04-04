using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a security debt report showing estimated remediation effort per finding,
    /// grouped by module, with a payoff priority ranking and summary stats.
    /// </summary>
    public static void PrintDebt(
        List<DebtItem> items,
        int totalFindings,
        double totalDebtHours,
        List<(string Module, double Hours, int Count)> moduleBreakdown,
        List<(string Severity, double Hours, int Count)> severityBreakdown,
        string sortBy,
        TimeSpan elapsed)
    {
        Console.WriteLine();
        WriteLineColored("  💳 Security Debt Calculator", ConsoleColor.Cyan);
        Console.WriteLine($"  Analyzed {totalFindings} findings in {elapsed.TotalSeconds:F1}s");
        Console.WriteLine();

        if (items.Count == 0)
        {
            WriteLineColored("  ✅ No security debt! All findings resolved.", ConsoleColor.Green);
            Console.WriteLine();
            return;
        }

        // ── Total debt summary ──
        WriteLineColored("  📊 Debt Summary", ConsoleColor.White);
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");

        var debtColor = totalDebtHours switch
        {
            > 80 => ConsoleColor.Red,
            > 40 => ConsoleColor.Yellow,
            > 10 => ConsoleColor.Cyan,
            _ => ConsoleColor.Green
        };

        Console.Write("  Total estimated remediation effort: ");
        WriteLineColored(FormatDebtHours(totalDebtHours), debtColor);

        var debtLevel = totalDebtHours switch
        {
            > 80 => ("CRITICAL", ConsoleColor.Red),
            > 40 => ("HIGH", ConsoleColor.Yellow),
            > 10 => ("MODERATE", ConsoleColor.Cyan),
            _ => ("LOW", ConsoleColor.Green)
        };
        Console.Write("  Debt level: ");
        WriteLineColored(debtLevel.Item1, debtLevel.Item2);
        Console.WriteLine();

        // ── By severity ──
        WriteLineColored("  🎯 Debt by Severity", ConsoleColor.White);
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");

        foreach (var (sev, hours, count) in severityBreakdown)
        {
            var sevColor = sev switch
            {
                "Critical" => ConsoleColor.Red,
                "Warning" => ConsoleColor.Yellow,
                "Info" => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            var pct = totalDebtHours > 0 ? (hours / totalDebtHours * 100) : 0;
            var barLen = (int)(pct / 100 * 30);
            var bar = new string('█', barLen) + new string('░', 30 - barLen);

            Console.Write("  ");
            WriteColored($"{sev,-10}", sevColor);
            Console.Write($" {bar} ");
            WriteColored($"{FormatDebtHours(hours),8}", sevColor);
            Console.WriteLine($" ({count} findings, {pct:F0}%)");
        }
        Console.WriteLine();

        // ── By module ──
        WriteLineColored("  🏗️  Debt by Module", ConsoleColor.White);
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");

        var maxModuleHours = moduleBreakdown.Count > 0 ? moduleBreakdown.Max(m => m.Hours) : 1;
        foreach (var (module, hours, count) in moduleBreakdown.Take(15))
        {
            var pct = totalDebtHours > 0 ? (hours / totalDebtHours * 100) : 0;
            var barLen = (int)(hours / maxModuleHours * 25);
            var bar = new string('█', Math.Max(1, barLen)) + new string('░', Math.Max(0, 25 - barLen));

            var modColor = hours switch
            {
                > 16 => ConsoleColor.Red,
                > 8 => ConsoleColor.Yellow,
                _ => ConsoleColor.Green
            };

            Console.Write($"  {DebtTruncate(module, 20),-20} {bar} ");
            WriteColored($"{FormatDebtHours(hours),8}", modColor);
            Console.WriteLine($" ({count} items, {pct:F0}%)");
        }
        Console.WriteLine();

        // ── Top payoff priority ──
        WriteLineColored($"  🏆 Payoff Priority (sorted by {sortBy})", ConsoleColor.White);
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"#",-4} {"Severity",-10} {"Effort",-10} {"ROI",-6} {"Module",-18} Title");
        Console.ResetColor();
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");

        int rank = 1;
        foreach (var item in items.Take(25))
        {
            var sevColor = item.Severity switch
            {
                "Critical" => ConsoleColor.Red,
                "Warning" => ConsoleColor.Yellow,
                "Info" => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            Console.Write($"  {rank,-4} ");
            WriteColored($"{item.Severity,-10}", sevColor);

            var effortColor = item.EstimatedHours switch
            {
                > 4 => ConsoleColor.Red,
                > 2 => ConsoleColor.Yellow,
                _ => ConsoleColor.Green
            };
            WriteColored($"{FormatDebtHours(item.EstimatedHours),-10}", effortColor);

            var roiColor = item.RoiScore switch
            {
                >= 8 => ConsoleColor.Green,
                >= 4 => ConsoleColor.Yellow,
                _ => ConsoleColor.DarkGray
            };
            WriteColored($"{item.RoiScore,-6:F1}", roiColor);

            Console.Write($" {DebtTruncate(item.Module, 18),-18} ");
            Console.WriteLine(DebtTruncate(item.Title, 40));

            if (item.IsFixable)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("       ⚡ Auto-fixable");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" — saves ~{item.EstimatedHours:F1}h manual effort");
                Console.ResetColor();
            }

            rank++;
        }

        Console.WriteLine();

        // ── Quick wins ──
        var quickWins = items.Where(i => i.EstimatedHours <= 0.5 && i.RoiScore >= 5).ToList();
        if (quickWins.Count > 0)
        {
            WriteLineColored($"  ⚡ Quick Wins ({quickWins.Count} items, ≤30min each, high ROI)", ConsoleColor.Green);
            Console.WriteLine($"  {"─",1}{new string('─', 60)}");
            foreach (var qw in quickWins.Take(10))
            {
                Console.Write("  • ");
                WriteColored($"[{qw.Severity}]", qw.Severity == "Critical" ? ConsoleColor.Red : ConsoleColor.Yellow);
                Console.Write($" {DebtTruncate(qw.Title, 45)}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" ({qw.Module})");
                Console.ResetColor();
                if (qw.IsFixable)
                {
                    WriteColored(" ⚡", ConsoleColor.Green);
                }
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // ── Debt repayment plan ──
        WriteLineColored("  📅 Suggested Repayment Plan", ConsoleColor.White);
        Console.WriteLine($"  {"─",1}{new string('─', 60)}");

        var sprint1 = items.Where(i => i.EstimatedHours <= 1 && i.Severity == "Critical").Sum(i => i.EstimatedHours);
        var sprint2 = items.Where(i => i.Severity == "Critical" && i.EstimatedHours > 1).Sum(i => i.EstimatedHours);
        var sprint3 = items.Where(i => i.Severity == "Warning").Sum(i => i.EstimatedHours);
        var sprint4 = items.Where(i => i.Severity == "Info").Sum(i => i.EstimatedHours);

        Console.Write("  Sprint 1 (this week):   ");
        WriteLineColored($"Critical quick fixes — {FormatDebtHours(sprint1)}", ConsoleColor.Red);
        Console.Write("  Sprint 2 (next week):   ");
        WriteLineColored($"Remaining criticals — {FormatDebtHours(sprint2)}", ConsoleColor.Yellow);
        Console.Write("  Sprint 3 (2-4 weeks):   ");
        WriteLineColored($"Warnings — {FormatDebtHours(sprint3)}", ConsoleColor.Cyan);
        Console.Write("  Sprint 4 (backlog):     ");
        WriteLineColored($"Info items — {FormatDebtHours(sprint4)}", ConsoleColor.DarkGray);
        Console.WriteLine();

        // ── Footer ──
        var fixable = items.Count(i => i.IsFixable);
        var fixableHours = items.Where(i => i.IsFixable).Sum(i => i.EstimatedHours);
        if (fixable > 0)
        {
            Console.Write("  ");
            WriteColored($"⚡ {fixable} auto-fixable items", ConsoleColor.Green);
            Console.WriteLine($" could save {FormatDebtHours(fixableHours)} of manual effort");
        }

        Console.WriteLine();
    }

    private static string FormatDebtHours(double hours)
    {
        if (hours < 1) return $"{hours * 60:F0}min";
        if (hours < 8) return $"{hours:F1}h";
        var days = hours / 8;
        return days < 5 ? $"{days:F1}d" : $"{days / 5:F1}w";
    }

    private static string DebtTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "(untitled)";
        return text.Length <= maxLen ? text : text[..(maxLen - 3)] + "...";
    }
}

/// <summary>
/// A single security debt item with estimated remediation effort and ROI score.
/// </summary>
public class DebtItem
{
    public string Module { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public double EstimatedHours { get; set; }
    public double RoiScore { get; set; }
    public bool IsFixable { get; set; }
    public string? Remediation { get; set; }
}
