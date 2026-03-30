namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print peer benchmark comparison — how the user's score stacks up
    /// against typical security profiles for different machine types.
    /// </summary>
    public static void PrintPeers(
        int userScore, int critCount, int warnCount, int infoCount, int passCount,
        PeerProfile[] peers)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║  👥 Peer Benchmark — How Do You Compare?        ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Your score summary
        var scoreColor = userScore >= 80 ? ConsoleColor.Green
                       : userScore >= 60 ? ConsoleColor.Yellow
                       : userScore >= 40 ? ConsoleColor.DarkYellow
                       : ConsoleColor.Red;

        WriteColored("  Your Score: ", ConsoleColor.Gray);
        WriteLineColored($"{userScore}/100", scoreColor);

        WriteColored("  Findings:   ", ConsoleColor.Gray);
        if (critCount > 0) WriteColored($"{critCount} Critical  ", ConsoleColor.Red);
        if (warnCount > 0) WriteColored($"{warnCount} Warning  ", ConsoleColor.Yellow);
        if (infoCount > 0) WriteColored($"{infoCount} Info  ", ConsoleColor.Gray);
        WriteColored($"{passCount} Pass", ConsoleColor.Green);
        Console.WriteLine();
        Console.WriteLine();

        // Ranking
        var ranked = peers
            .Append(new PeerProfile("➤ YOU", userScore, critCount, warnCount, infoCount, passCount, ""))
            .OrderByDescending(p => p.TypicalScore)
            .ToList();

        var userRank = ranked.FindIndex(p => p.Name == "➤ YOU") + 1;
        WriteColored("  Ranking: ", ConsoleColor.Gray);
        WriteLineColored($"#{userRank} of {ranked.Count}", ConsoleColor.White);
        Console.WriteLine();

        // Comparison table
        WriteLineColored("  ┌──────────────────────────────────┬───────┬───────────────────────────┐", ConsoleColor.DarkGray);
        WriteLineColored("  │ Profile                          │ Score │ Findings (Crit/Warn/Info) │", ConsoleColor.DarkGray);
        WriteLineColored("  ├──────────────────────────────────┼───────┼───────────────────────────┤", ConsoleColor.DarkGray);

        foreach (var p in ranked)
        {
            var isUser = p.Name == "➤ YOU";
            var nameColor = isUser ? ConsoleColor.Cyan : ConsoleColor.White;
            var rowScoreColor = p.TypicalScore >= 80 ? ConsoleColor.Green
                              : p.TypicalScore >= 60 ? ConsoleColor.Yellow
                              : p.TypicalScore >= 40 ? ConsoleColor.DarkYellow
                              : ConsoleColor.Red;

            WriteColored("  │ ", ConsoleColor.DarkGray);
            var name = p.Name.Length > 32 ? p.Name[..32] : p.Name.PadRight(32);
            WriteColored(name, nameColor);
            WriteColored(" │ ", ConsoleColor.DarkGray);
            WriteColored($"{p.TypicalScore,5}", rowScoreColor);
            WriteColored(" │ ", ConsoleColor.DarkGray);

            var findingsStr = $"{p.Critical}/{p.Warning}/{p.Info}";
            WriteColored(findingsStr.PadRight(25), isUser ? ConsoleColor.Cyan : ConsoleColor.Gray);
            WriteLineColored(" │", ConsoleColor.DarkGray);
        }

        WriteLineColored("  └──────────────────────────────────┴───────┴───────────────────────────┘", ConsoleColor.DarkGray);
        Console.WriteLine();

        // Score bar visualization
        WriteLineColored("  Score Comparison:", ConsoleColor.White);
        Console.WriteLine();

        foreach (var p in ranked)
        {
            var isUser = p.Name == "➤ YOU";
            var label = p.Name.Length > 20 ? p.Name[..20] : p.Name.PadRight(20);
            var barLen = p.TypicalScore / 2; // max 50 chars
            var barColor = p.TypicalScore >= 80 ? ConsoleColor.Green
                         : p.TypicalScore >= 60 ? ConsoleColor.Yellow
                         : p.TypicalScore >= 40 ? ConsoleColor.DarkYellow
                         : ConsoleColor.Red;

            WriteColored($"  {label} ", isUser ? ConsoleColor.Cyan : ConsoleColor.Gray);
            WriteColored(new string('█', barLen), barColor);
            WriteColored(new string('░', 50 - barLen), ConsoleColor.DarkGray);
            WriteLineColored($" {p.TypicalScore}%", barColor);
        }

        Console.WriteLine();

        // Insights
        var better = peers.Where(p => p.TypicalScore < userScore).ToList();
        var worse = peers.Where(p => p.TypicalScore > userScore).ToList();

        if (better.Count > 0)
        {
            WriteColored("  ✅ Better than: ", ConsoleColor.Green);
            WriteLineColored(string.Join(", ", better.Select(p => p.Name)), ConsoleColor.White);
        }
        if (worse.Count > 0)
        {
            WriteColored("  🎯 Aspire to:   ", ConsoleColor.Yellow);
            WriteLineColored(string.Join(", ", worse.Select(p => p.Name)), ConsoleColor.White);
        }

        // Closest peer
        var closest = peers.OrderBy(p => Math.Abs(p.TypicalScore - userScore)).First();
        Console.WriteLine();
        WriteColored("  📊 Closest match: ", ConsoleColor.Gray);
        WriteLineColored(closest.Name, ConsoleColor.White);
        WriteColored("     ", ConsoleColor.Gray);
        WriteLineColored(closest.Description, ConsoleColor.DarkGray);
        Console.WriteLine();
    }
}
