using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintWarGame(WarGameResult result)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       ⚔️  Security War Game                                 ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        // Scenario header
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  SCENARIO: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(result.ScenarioName);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {result.ScenarioDescription}");
        Console.ResetColor();
        Console.WriteLine();

        // Battle rounds
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ┌─────────────────────── BATTLE LOG ──────────────────────────┐");
        Console.ResetColor();

        for (int i = 0; i < result.Rounds.Count; i++)
        {
            var round = result.Rounds[i];
            Console.Write($"  │  Round {i + 1}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(round.TacticName);
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" [{round.MitreId}]");
            Console.ResetColor();
            Console.Write($" ({round.Category})");

            // Right-align outcome
            string outcomeText = round.Defended ? "BLOCKED" : "BREACHED";
            var outcomeColor = round.Defended ? ConsoleColor.Green : ConsoleColor.Red;
            string leftPart = $"  │  Round {i + 1}: {round.TacticName} [{round.MitreId}] ({round.Category})";
            int padding = Math.Max(1, 63 - leftPart.Length - outcomeText.Length - 2);
            Console.Write(new string(' ', padding));
            Console.ForegroundColor = outcomeColor;
            Console.Write(round.Defended ? "🛡️ BLOCKED" : "💥 BREACHED");
            Console.ResetColor();
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  │    {round.Detail}");
            if (!round.Defended)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  │    → {round.Recommendation}");
            }
            Console.ResetColor();

            if (i < result.Rounds.Count - 1)
                Console.WriteLine("  │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─");
        }

        Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
        Console.WriteLine();

        // Scoreboard
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌─────────────────── SCOREBOARD ──────────────────────────────┐");
        Console.ResetColor();

        // Defense score gauge
        Console.Write("  │  Defense Score: ");
        var scoreColor = result.DefenseScore >= 75 ? ConsoleColor.Green
            : result.DefenseScore >= 50 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.ForegroundColor = scoreColor;
        int filled = result.DefenseScore / 5;
        Console.Write($"[{new string('█', filled)}{new string('░', 20 - filled)}] {result.DefenseScore}/100");
        Console.ResetColor();
        Console.WriteLine();

        Console.Write("  │  Grade: ");
        var gradeColor = result.Grade switch
        {
            "A" => ConsoleColor.Green,
            "B" => ConsoleColor.Cyan,
            "C" => ConsoleColor.Yellow,
            "D" => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };
        Console.ForegroundColor = gradeColor;
        Console.Write(result.Grade);
        Console.ResetColor();
        Console.Write($"  |  Defended: {result.DefenseWins}/{result.TotalRounds}");
        Console.Write($"  |  Breached: {result.AttackSuccesses}/{result.TotalRounds}");
        Console.WriteLine();

        Console.Write("  │  Verdict: ");
        Console.ForegroundColor = scoreColor;
        Console.WriteLine(result.Verdict);
        Console.ResetColor();

        Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
        Console.WriteLine();

        // Recommendations
        if (result.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  📋 RECOMMENDATIONS");
            Console.ResetColor();
            Console.WriteLine("  ┌─────────────────────────────────────────────────────────────┐");
            for (int i = 0; i < result.Recommendations.Count; i++)
                Console.WriteLine($"  │  {i + 1}. {result.Recommendations[i]}");
            Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
            Console.WriteLine();
        }

        // Proactive insights
        if (result.ProactiveInsights.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  🔮 PROACTIVE INSIGHTS");
            Console.ResetColor();
            Console.WriteLine("  ┌─────────────────────────────────────────────────────────────┐");
            foreach (var insight in result.ProactiveInsights)
                Console.WriteLine($"  │  • {insight}");
            Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
            Console.WriteLine();
        }
    }

    public static void PrintWarGameScenarios(List<WarGameScenarioInfo> scenarios)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ⚔️  Available War Game Scenarios");
        Console.ResetColor();
        Console.WriteLine("  ─────────────────────────────────────────────────────");
        foreach (var s in scenarios)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {s.Id,-15}");
            Console.ResetColor();
            Console.Write($" {s.Name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" ({s.TacticCount} tactics)");
            Console.ResetColor();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"                  {s.Description}");
            Console.ResetColor();
        }
        Console.WriteLine();
    }
}
