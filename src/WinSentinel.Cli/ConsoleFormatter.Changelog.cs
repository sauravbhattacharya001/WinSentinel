using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a formatted security changelog to the console.
    /// </summary>
    public static void PrintChangelog(ChangelogReport report, bool quiet = false)
    {
        if (report.TotalScans == 0)
        {
            WriteLineColored("  No audit history found. Run some audits first!", ConsoleColor.Yellow);
            return;
        }

        if (!quiet)
        {
            Console.WriteLine();
            WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
            WriteLineColored("  ║       📋  Security Changelog                ║", ConsoleColor.Cyan);
            WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
            Console.WriteLine();
        }

        // Summary header
        WriteLineColored($"  Period: last {report.Period} days ({report.TotalScans} scans)", ConsoleColor.White);
        if (report.FirstScan.HasValue && report.LastScan.HasValue)
        {
            WriteColored("  Range:  ", ConsoleColor.DarkGray);
            Console.WriteLine($"{report.FirstScan.Value:yyyy-MM-dd} → {report.LastScan.Value:yyyy-MM-dd}");
        }

        // Score summary
        Console.WriteLine();
        WriteColored("  Score:  ", ConsoleColor.DarkGray);
        var scoreColor = report.NetScoreChange > 0 ? ConsoleColor.Green
            : report.NetScoreChange < 0 ? ConsoleColor.Red : ConsoleColor.Yellow;
        var arrow = report.NetScoreChange > 0 ? "↑" : report.NetScoreChange < 0 ? "↓" : "→";
        WriteLineColored(
            $"{report.StartScore} → {report.EndScore} ({report.StartGrade} → {report.EndGrade}) " +
            $"{arrow} {(report.NetScoreChange >= 0 ? "+" : "")}{report.NetScoreChange}",
            scoreColor);

        WriteColored("  Best:   ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.BestScore}", ConsoleColor.Green);
        WriteColored("  Worst:  ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.WorstScore}", ConsoleColor.Red);
        WriteColored("  Stats:  ", ConsoleColor.DarkGray);
        Console.WriteLine($"{report.ImprovementCount} improvements, {report.RegressionCount} regressions");

        // Milestones
        if (report.Milestones.Count > 0)
        {
            Console.WriteLine();
            WriteLineColored("  🏆 Milestones", ConsoleColor.Yellow);
            WriteLineColored("  " + new string('─', 50), ConsoleColor.DarkGray);
            foreach (var m in report.Milestones)
            {
                WriteColored($"  {m.Timestamp:MM-dd HH:mm}  ", ConsoleColor.DarkGray);
                WriteLineColored(m.Description, ConsoleColor.Yellow);
            }
        }

        // Changelog entries (newest first)
        if (report.Entries.Count > 0)
        {
            Console.WriteLine();
            WriteLineColored("  📜 Changes", ConsoleColor.White);
            WriteLineColored("  " + new string('─', 50), ConsoleColor.DarkGray);

            foreach (var entry in report.Entries.AsEnumerable().Reverse().Take(quiet ? 5 : 20))
            {
                Console.WriteLine();
                WriteColored($"  {entry.Timestamp:yyyy-MM-dd HH:mm}  ", ConsoleColor.DarkGray);
                var entryColor = entry.ScoreChange > 0 ? ConsoleColor.Green
                    : entry.ScoreChange < 0 ? ConsoleColor.Red : ConsoleColor.White;
                WriteLineColored(
                    $"Score: {entry.PreviousScore} → {entry.CurrentScore}",
                    entryColor);

                foreach (var evt in entry.Events)
                {
                    WriteLineColored($"    {evt.Icon} {evt.Summary}", entryColor);
                }

                // Module changes
                foreach (var mod in entry.ModuleChanges.OrderByDescending(m => Math.Abs(m.Delta)).Take(3))
                {
                    var modColor = mod.Delta > 0 ? ConsoleColor.Green : ConsoleColor.Red;
                    WriteColored($"    │ ", ConsoleColor.DarkGray);
                    WriteLineColored(
                        $"{mod.ModuleName}: {mod.PreviousScore} → {mod.CurrentScore} ({(mod.Delta > 0 ? "+" : "")}{mod.Delta})",
                        modColor);
                }

                // Finding changes
                foreach (var fc in entry.FindingChanges)
                {
                    var fcIcon = fc.Type == FindingChangeType.Resolved ? "  ✓" : "  ✗";
                    var fcColor = fc.Type == FindingChangeType.Resolved ? ConsoleColor.Green : ConsoleColor.Red;
                    WriteColored($"    │ ", ConsoleColor.DarkGray);
                    WriteColored(fcIcon, fcColor);
                    WriteColored($" [{fc.Severity}] ", ConsoleColor.DarkGray);
                    WriteLineColored(fc.Title, fcColor);
                }

                if (entry.FindingChangesOmitted > 0)
                {
                    WriteColored($"    │ ", ConsoleColor.DarkGray);
                    WriteLineColored($"  ... and {entry.FindingChangesOmitted} more", ConsoleColor.DarkGray);
                }
            }
        }

        Console.WriteLine();
    }
}
