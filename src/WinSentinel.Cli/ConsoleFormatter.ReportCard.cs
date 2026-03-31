using System.Text;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public class ModuleGrade
    {
        public string ModuleName { get; set; } = "";
        public string Category { get; set; } = "";
        public int Score { get; set; }
        public string Grade { get; set; } = "";
        public int CriticalCount { get; set; }
        public int WarningCount { get; set; }
        public int InfoCount { get; set; }
        public int PassCount { get; set; }
        public string? TopIssue { get; set; }
    }

    public class ReportCardData
    {
        public string MachineName { get; set; } = "";
        public DateTimeOffset GeneratedAt { get; set; }
        public int OverallScore { get; set; }
        public string OverallGrade { get; set; } = "";
        public int? PreviousScore { get; set; }
        public int TotalModules { get; set; }
        public int TotalFindings { get; set; }
        public int TotalCritical { get; set; }
        public int TotalWarnings { get; set; }
        public List<ModuleGrade> ModuleGrades { get; set; } = new();
        public List<string> TopActions { get; set; } = new();
        public TimeSpan ScanDuration { get; set; }
        public int HistoryDays { get; set; }
        public int RunsInPeriod { get; set; }
    }

    public static void PrintReportCard(ReportCardData card)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║              🎓  SECURITY REPORT CARD                       ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Overall grade display
        Console.Write("  Machine: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(card.MachineName);
        Console.ForegroundColor = original;
        Console.Write("  │  Date: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(card.GeneratedAt.ToString("yyyy-MM-dd HH:mm"));
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Big grade display
        Console.Write("  Overall Grade: ");
        Console.ForegroundColor = RcGradeColor(card.OverallGrade);
        Console.Write($"  {card.OverallGrade}  ");
        Console.ForegroundColor = original;
        Console.Write($"({card.OverallScore}/100)");

        if (card.PreviousScore.HasValue)
        {
            var diff = card.OverallScore - card.PreviousScore.Value;
            if (diff > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"  ▲ +{diff}");
            }
            else if (diff < 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  ▼ {diff}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  ─ no change");
            }
            Console.ForegroundColor = original;
        }
        Console.WriteLine();
        Console.WriteLine();

        // Module grades table
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌─────────────────────────────┬───────┬───────┬──────┬──────┬──────┬──────────────────────────────┐");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  │ Module                      │ Grade │ Score │ Crit │ Warn │ Pass │ Top Issue                    │");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ├─────────────────────────────┼───────┼───────┼──────┼──────┼──────┼──────────────────────────────┤");
        Console.ForegroundColor = original;

        foreach (var m in card.ModuleGrades)
        {
            var moduleName = RcTruncate(m.ModuleName, 27);
            var topIssue = RcTruncate(m.TopIssue ?? "—", 28);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(moduleName.PadRight(28));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("│ ");
            Console.ForegroundColor = RcGradeColor(m.Grade);
            Console.Write($"  {m.Grade}  ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = RcScoreColor(m.Score);
            Console.Write(m.Score.ToString().PadLeft(4));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = m.CriticalCount > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
            Console.Write(m.CriticalCount.ToString().PadLeft(4));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = m.WarningCount > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            Console.Write(m.WarningCount.ToString().PadLeft(4));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = m.PassCount > 0 ? ConsoleColor.Green : ConsoleColor.DarkGray;
            Console.Write(m.PassCount.ToString().PadLeft(4));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = original;
            Console.Write(topIssue.PadRight(29));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("│");
            Console.ForegroundColor = original;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └─────────────────────────────┴───────┴───────┴──────┴──────┴──────┴──────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Summary stats
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Summary: ");
        Console.ForegroundColor = original;
        Console.Write($"{card.TotalModules} modules scanned, ");
        Console.Write($"{card.TotalFindings} total findings (");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{card.TotalCritical} critical");
        Console.ForegroundColor = original;
        Console.Write(", ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{card.TotalWarnings} warnings");
        Console.ForegroundColor = original;
        Console.WriteLine(")");

        Console.Write($"  History:  {card.RunsInPeriod} scans in the last {card.HistoryDays} days");
        Console.Write($"  │  Scan time: {card.ScanDuration.TotalSeconds:F1}s");
        Console.WriteLine();

        // Top actions
        if (card.TopActions.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📋 Priority Actions:");
            Console.ForegroundColor = original;
            for (int i = 0; i < card.TopActions.Count; i++)
            {
                Console.Write($"    {i + 1}. ");
                var action = card.TopActions[i];
                if (action.StartsWith("[Critical]"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("● ");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("● ");
                }
                Console.ForegroundColor = original;
                Console.WriteLine(action.Replace("[Critical] ", "").Replace("[Warning] ", ""));
            }
        }

        Console.WriteLine();
    }

    public static string RenderReportCardMarkdown(ReportCardData card)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# 🎓 Security Report Card");
        sb.AppendLine();
        sb.AppendLine($"**Machine:** {card.MachineName}  ");
        sb.AppendLine($"**Date:** {card.GeneratedAt:yyyy-MM-dd HH:mm}  ");
        sb.AppendLine($"**Overall Grade:** **{card.OverallGrade}** ({card.OverallScore}/100)");
        if (card.PreviousScore.HasValue)
        {
            var diff = card.OverallScore - card.PreviousScore.Value;
            var arrow = diff > 0 ? "▲" : diff < 0 ? "▼" : "─";
            sb.AppendLine($"**Trend:** {arrow} {(diff >= 0 ? "+" : "")}{diff} from previous scan");
        }
        sb.AppendLine();
        sb.AppendLine("## Module Grades");
        sb.AppendLine();
        sb.AppendLine("| Module | Grade | Score | Critical | Warning | Pass | Top Issue |");
        sb.AppendLine("|--------|-------|-------|----------|---------|------|-----------|");
        foreach (var m in card.ModuleGrades)
        {
            sb.AppendLine($"| {m.ModuleName} | {m.Grade} | {m.Score} | {m.CriticalCount} | {m.WarningCount} | {m.PassCount} | {m.TopIssue ?? "—"} |");
        }
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- **Modules scanned:** {card.TotalModules}");
        sb.AppendLine($"- **Total findings:** {card.TotalFindings} ({card.TotalCritical} critical, {card.TotalWarnings} warnings)");
        sb.AppendLine($"- **Scan history:** {card.RunsInPeriod} scans in {card.HistoryDays} days");
        sb.AppendLine($"- **Scan duration:** {card.ScanDuration.TotalSeconds:F1}s");

        if (card.TopActions.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Priority Actions");
            sb.AppendLine();
            for (int i = 0; i < card.TopActions.Count; i++)
            {
                sb.AppendLine($"{i + 1}. {card.TopActions[i]}");
            }
        }

        return sb.ToString();
    }

    private static ConsoleColor RcGradeColor(string grade) => grade switch
    {
        "A+" or "A" => ConsoleColor.Green,
        "A-" or "B+" or "B" => ConsoleColor.DarkGreen,
        "B-" or "C+" or "C" => ConsoleColor.Yellow,
        "C-" or "D+" or "D" => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red,
    };

    private static ConsoleColor RcScoreColor(int score) => score switch
    {
        >= 90 => ConsoleColor.Green,
        >= 70 => ConsoleColor.Yellow,
        >= 50 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red,
    };

    private static string RcTruncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
}
