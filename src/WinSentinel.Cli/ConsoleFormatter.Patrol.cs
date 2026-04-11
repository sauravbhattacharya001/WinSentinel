namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a security patrol report — a multi-checkpoint autonomous inspection.
    /// </summary>
    public static void PrintPatrol(PatrolReport report)
    {
        Console.WriteLine();
        WriteColored("  ╔══════════════════════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteColored("  ║              🛡️  SECURITY PATROL REPORT                     ║", ConsoleColor.Cyan);
        WriteColored("  ╚══════════════════════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        WriteColored($"  Patrol Time: {report.PatrolTime:yyyy-MM-dd HH:mm:ss}", ConsoleColor.Gray);
        WriteColored($"  Lookback:    {report.LookbackDays} days  ({report.RunsAnalyzed} audit runs analyzed)", ConsoleColor.Gray);
        Console.WriteLine();

        // Route map — ASCII visualization of checkpoint results
        WriteColored("  ── PATROL ROUTE ──────────────────────────────────────────────", ConsoleColor.White);
        Console.WriteLine();

        foreach (var (cp, idx) in report.Checkpoints.Select((c, i) => (c, i)))
        {
            var icon = cp.Status switch
            {
                PatrolStatus.Pass => "✅",
                PatrolStatus.Warn => "⚠️",
                PatrolStatus.Fail => "❌",
                _ => "⬜"
            };
            var color = cp.Status switch
            {
                PatrolStatus.Pass => ConsoleColor.Green,
                PatrolStatus.Warn => ConsoleColor.Yellow,
                PatrolStatus.Fail => ConsoleColor.Red,
                _ => ConsoleColor.Gray
            };

            var connector = idx < report.Checkpoints.Count - 1 ? "│" : " ";

            WriteColored($"  {icon} Checkpoint {idx + 1}: {cp.Name}", color);
            WriteColored($"  {connector}   {cp.Summary}", ConsoleColor.Gray);

            if (cp.Details.Count > 0)
            {
                foreach (var detail in cp.Details)
                    WriteColored($"  {connector}     • {detail}", ConsoleColor.DarkGray);
            }

            if (idx < report.Checkpoints.Count - 1)
            {
                WriteColored($"  │", ConsoleColor.DarkGray);
            }
        }

        Console.WriteLine();

        // Score bar
        var passCount = report.Checkpoints.Count(c => c.Status == PatrolStatus.Pass);
        var warnCount = report.Checkpoints.Count(c => c.Status == PatrolStatus.Warn);
        var failCount = report.Checkpoints.Count(c => c.Status == PatrolStatus.Fail);
        var total = report.Checkpoints.Count;

        WriteColored("  ── PATROL SUMMARY ────────────────────────────────────────────", ConsoleColor.White);
        Console.WriteLine();

        var barWidth = 40;
        var passBar = total > 0 ? (int)Math.Round((double)passCount / total * barWidth) : 0;
        var warnBar = total > 0 ? (int)Math.Round((double)warnCount / total * barWidth) : 0;
        var failBar = barWidth - passBar - warnBar;
        if (failBar < 0) failBar = 0;

        Console.Write("  [");
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(new string('█', passBar));
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(new string('▓', warnBar));
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(new string('░', failBar));
        Console.ForegroundColor = prev;
        Console.WriteLine("]");

        Console.WriteLine($"  ✅ Pass: {passCount}  ⚠️ Warn: {warnCount}  ❌ Fail: {failCount}  (of {total} checkpoints)");
        Console.WriteLine();

        // Overall verdict
        var verdict = report.OverallVerdict;
        var verdictColor = verdict switch
        {
            PatrolVerdict.AllClear => ConsoleColor.Green,
            PatrolVerdict.Caution => ConsoleColor.Yellow,
            PatrolVerdict.Alert => ConsoleColor.Red,
            _ => ConsoleColor.Gray
        };
        var verdictIcon = verdict switch
        {
            PatrolVerdict.AllClear => "🟢",
            PatrolVerdict.Caution => "🟡",
            PatrolVerdict.Alert => "🔴",
            _ => "⚪"
        };
        var verdictText = verdict switch
        {
            PatrolVerdict.AllClear => "ALL CLEAR — Security posture is healthy",
            PatrolVerdict.Caution => "CAUTION — Some areas need attention",
            PatrolVerdict.Alert => "ALERT — Immediate action recommended",
            _ => "UNKNOWN"
        };

        WriteColored($"  {verdictIcon} Verdict: {verdictText}", verdictColor);
        Console.WriteLine();

        // Recommended actions
        if (report.RecommendedActions.Count > 0)
        {
            WriteColored("  ── RECOMMENDED ACTIONS ───────────────────────────────────────", ConsoleColor.White);
            Console.WriteLine();
            for (int i = 0; i < report.RecommendedActions.Count; i++)
            {
                var action = report.RecommendedActions[i];
                var priorityColor = action.Priority switch
                {
                    "high" => ConsoleColor.Red,
                    "medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };
                WriteColored($"  {i + 1}. [{action.Priority.ToUpperInvariant()}] {action.Description}", priorityColor);
                if (!string.IsNullOrEmpty(action.Command))
                    WriteColored($"     → {action.Command}", ConsoleColor.DarkCyan);
            }
            Console.WriteLine();
        }

        // Next patrol hint
        WriteColored($"  💡 Run patrols regularly to track posture changes over time.", ConsoleColor.DarkGray);
        Console.WriteLine();
    }
}

// ── Patrol models ────────────────────────────────────────────────────

public class PatrolReport
{
    public DateTimeOffset PatrolTime { get; set; } = DateTimeOffset.Now;
    public int LookbackDays { get; set; }
    public int RunsAnalyzed { get; set; }
    public List<PatrolCheckpoint> Checkpoints { get; set; } = [];
    public List<PatrolAction> RecommendedActions { get; set; } = [];

    public PatrolVerdict OverallVerdict
    {
        get
        {
            var failCount = Checkpoints.Count(c => c.Status == PatrolStatus.Fail);
            var warnCount = Checkpoints.Count(c => c.Status == PatrolStatus.Warn);
            if (failCount > 0) return PatrolVerdict.Alert;
            if (warnCount > 0) return PatrolVerdict.Caution;
            return PatrolVerdict.AllClear;
        }
    }
}

public class PatrolCheckpoint
{
    public string Name { get; set; } = "";
    public PatrolStatus Status { get; set; }
    public string Summary { get; set; } = "";
    public List<string> Details { get; set; } = [];
}

public class PatrolAction
{
    public string Priority { get; set; } = "low";
    public string Description { get; set; } = "";
    public string? Command { get; set; }
}

public enum PatrolStatus { Pass, Warn, Fail, Skip }
public enum PatrolVerdict { AllClear, Caution, Alert }
