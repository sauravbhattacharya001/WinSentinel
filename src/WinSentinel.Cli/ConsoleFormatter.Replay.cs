namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintReplay(ReplayResult result, CliOptions options)
    {
        if (result.ErrorMessage != null)
        {
            PrintWarning(result.ErrorMessage);
            return;
        }

        switch (result.Mode)
        {
            case "snapshot":
                PrintReplaySnapshot(result);
                break;
            case "bisect":
                PrintReplayBisect(result);
                break;
            case "diff":
                PrintReplayDiff(result);
                break;
        }
    }

    private static void PrintReplaySnapshot(ReplayResult result)
    {
        var snap = result.Snapshot!;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║    ⏪  Security Replay — Time Travel         ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine();
        Console.Write("  Replaying: ");
        WriteColored($"Run #{snap.RunIndex}", ConsoleColor.White);
        Console.Write(" — ");
        WriteColored(snap.RunDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm"), ConsoleColor.Yellow);
        Console.WriteLine();

        Console.Write("  Historical Score: ");
        WriteColored($"{snap.Score}/100", ReplayScoreColor(snap.Score));
        Console.Write("    Current Score: ");
        WriteColored($"{snap.CurrentScore}/100", ReplayScoreColor(snap.CurrentScore));
        Console.Write("    Delta: ");
        var deltaStr = snap.ScoreDelta > 0 ? $"+{snap.ScoreDelta}" : snap.ScoreDelta.ToString();
        WriteColored(deltaStr, snap.ScoreDelta >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine();

        Console.Write("  Findings: ");
        WriteColored(snap.TotalFindings.ToString(), ConsoleColor.White);
        Console.Write("  (Critical: ");
        WriteColored(snap.CriticalCount.ToString(), snap.CriticalCount > 0 ? ConsoleColor.Red : ConsoleColor.Green);
        Console.Write(", High: ");
        WriteColored(snap.HighCount.ToString(), snap.HighCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
        Console.WriteLine(")");

        // Module table
        if (snap.Modules.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ┌─────────────────────────────┬──────────┬─────────┬───────┐");
            Console.WriteLine("  │ Module                      │ Then     │ Now     │ Delta │");
            Console.WriteLine("  ├─────────────────────────────┼──────────┼─────────┼───────┤");
            Console.ResetColor();

            foreach (var mod in snap.Modules.OrderBy(m => m.Score))
            {
                var name = mod.Name.Length > 27 ? mod.Name[..27] : mod.Name;
                var d = mod.Delta > 0 ? $"+{mod.Delta}" : mod.Delta.ToString();
                Console.Write($"  │ {name,-27} │ ");
                WriteColored($"{mod.Score,5}/100", ReplayScoreColor(mod.Score));
                Console.Write(" │ ");
                WriteColored($"{mod.CurrentScore,4}/100", ReplayScoreColor(mod.CurrentScore));
                Console.Write(" │ ");
                WriteColored($"{d,5}", mod.Delta >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
                Console.WriteLine(" │");
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └─────────────────────────────┴──────────┴─────────┴───────┘");
            Console.ResetColor();
        }

        // Top findings
        if (snap.TopFindings.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("  Top Findings at this point:");
            Console.ResetColor();
            foreach (var f in snap.TopFindings)
            {
                Console.Write("    ");
                if (f.Contains("[Critical]", StringComparison.OrdinalIgnoreCase))
                    WriteColored("● ", ConsoleColor.Red);
                else if (f.Contains("[Warning]") || f.Contains("[High]"))
                    WriteColored("● ", ConsoleColor.Yellow);
                else
                    WriteColored("● ", ConsoleColor.DarkGray);
                Console.WriteLine(f);
            }
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {snap.Narrative}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintReplayBisect(ReplayResult result)
    {
        var bisect = result.Bisect!;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║    🔍  Security Bisect — Regression Finder   ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine();
        Console.Write("  Criteria: ");
        WriteColored(bisect.SearchCriteria, ConsoleColor.Yellow);
        Console.WriteLine();
        Console.Write("  Runs searched: ");
        WriteColored(bisect.TotalRunsSearched.ToString(), ConsoleColor.White);
        Console.Write("    Bisect steps: ");
        WriteColored(bisect.BisectSteps.ToString(), ConsoleColor.Cyan);
        Console.WriteLine();

        // Steps log
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("  Bisect Log:");
        Console.ResetColor();
        foreach (var step in bisect.Steps)
        {
            var icon = step.Direction == "good" ? "✓" : "✗";
            var color = step.Direction == "good" ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write($"    Step {step.StepNumber}: → Run #{step.RunIndex} ({step.RunDate.ToLocalTime():MM-dd HH:mm}) Score={step.Score}  ");
            WriteColored($"{icon} {step.Direction.ToUpper()}", color);
            Console.WriteLine();
        }

        // Result
        Console.WriteLine();
        if (bisect.RegressionIntroduced != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────");
            Console.ResetColor();

            if (bisect.LastGoodRun != null)
            {
                Console.Write("  Last good: ");
                WriteColored($"Run #{bisect.LastGoodRun.RunIndex}", ConsoleColor.Green);
                Console.Write($" ({bisect.LastGoodRun.RunDate.ToLocalTime():yyyy-MM-dd HH:mm}) Score=");
                WriteColored(bisect.LastGoodRun.Score.ToString(), ConsoleColor.Green);
                Console.WriteLine();
            }

            Console.Write("  Regression: ");
            WriteColored($"Run #{bisect.RegressionIntroduced.RunIndex}", ConsoleColor.Red);
            Console.Write($" ({bisect.RegressionIntroduced.RunDate.ToLocalTime():yyyy-MM-dd HH:mm}) Score=");
            WriteColored(bisect.RegressionIntroduced.Score.ToString(), ConsoleColor.Red);
            Console.WriteLine();
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {bisect.Narrative}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintReplayDiff(ReplayResult result)
    {
        var diff = result.Diff!;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║    📊  Security Diff — State Comparison      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine();
        Console.Write("  FROM: ");
        WriteColored($"Run #{diff.From.RunIndex}", ConsoleColor.Yellow);
        Console.Write($" ({diff.From.RunDate.ToLocalTime():yyyy-MM-dd HH:mm}) Score=");
        WriteColored(diff.From.Score.ToString(), ReplayScoreColor(diff.From.Score));
        Console.WriteLine();

        Console.Write("    TO: ");
        WriteColored($"Run #{diff.To.RunIndex}", ConsoleColor.Cyan);
        Console.Write($" ({diff.To.RunDate.ToLocalTime():yyyy-MM-dd HH:mm}) Score=");
        WriteColored(diff.To.Score.ToString(), ReplayScoreColor(diff.To.Score));
        Console.WriteLine();

        Console.Write("  Score Change: ");
        var changeStr = diff.ScoreChange > 0 ? $"+{diff.ScoreChange}" : diff.ScoreChange.ToString();
        WriteColored(changeStr, diff.ScoreChange >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine();

        // New findings
        if (diff.Added.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ➕ New Findings ({diff.Added.Count}):");
            Console.ResetColor();
            foreach (var e in diff.Added.Take(15))
            {
                Console.Write("    ");
                WriteColored($"[{e.Severity}]", ReplaySeverityColor(e.Severity));
                Console.WriteLine($" {e.Module}: {e.Finding}");
            }
            if (diff.Added.Count > 15)
                Console.WriteLine($"    ... and {diff.Added.Count - 15} more");
        }

        // Resolved findings
        if (diff.Removed.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ➖ Resolved Findings ({diff.Removed.Count}):");
            Console.ResetColor();
            foreach (var e in diff.Removed.Take(15))
            {
                Console.Write("    ");
                WriteColored($"[{e.Severity}]", ReplaySeverityColor(e.Severity));
                Console.WriteLine($" {e.Module}: {e.Finding}");
            }
            if (diff.Removed.Count > 15)
                Console.WriteLine($"    ... and {diff.Removed.Count - 15} more");
        }

        if (diff.Added.Count == 0 && diff.Removed.Count == 0)
        {
            Console.WriteLine();
            WriteColored("  No finding changes between these runs.", ConsoleColor.DarkGray);
            Console.WriteLine();
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {diff.Narrative}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static ConsoleColor ReplayScoreColor(int score) => score switch
    {
        >= 90 => ConsoleColor.Green,
        >= 70 => ConsoleColor.Yellow,
        >= 50 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };

    private static ConsoleColor ReplaySeverityColor(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => ConsoleColor.Red,
        "high" or "warning" => ConsoleColor.Yellow,
        "medium" => ConsoleColor.DarkYellow,
        _ => ConsoleColor.DarkGray
    };
}
