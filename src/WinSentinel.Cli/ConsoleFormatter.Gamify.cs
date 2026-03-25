using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print the gamification profile: level, XP, streaks, achievements.
    /// </summary>
    public static void PrintGamification(GamificationProfile profile)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Magenta);
        WriteLineColored("  ║  🎮 Security Gamification Profile           ║", ConsoleColor.Magenta);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Magenta);
        Console.WriteLine();

        if (profile.TotalAudits == 0)
        {
            WriteLineColored("  No audit history found. Run some audits to start earning XP!", ConsoleColor.Yellow);
            return;
        }

        // Level & XP
        var levelColor = profile.Level >= 8 ? ConsoleColor.Yellow
                       : profile.Level >= 5 ? ConsoleColor.Cyan
                       : ConsoleColor.White;

        WriteColored("  Level: ", ConsoleColor.Gray);
        WriteLineColored($"⚔️  Level {profile.Level}", levelColor);

        WriteColored("  Total XP: ", ConsoleColor.Gray);
        WriteLineColored($"{profile.TotalXp:N0}", ConsoleColor.Green);

        if (profile.XpToNextLevel > 0)
        {
            WriteColored("  XP to next level: ", ConsoleColor.Gray);
            WriteLineColored($"{profile.XpToNextLevel:N0}", ConsoleColor.DarkGray);
        }
        else
        {
            WriteLineColored("  🌟 MAX LEVEL REACHED!", ConsoleColor.Yellow);
        }

        // XP Progress Bar
        if (profile.Level < 10)
        {
            var xpThresholds = new[] { 0, 500, 1500, 3000, 5000, 8000, 12000, 17000, 23000, 30000 };
            int currentLevelXp = xpThresholds[profile.Level - 1];
            int nextLevelXp = xpThresholds[profile.Level];
            int progressXp = profile.TotalXp - currentLevelXp;
            int rangeXp = nextLevelXp - currentLevelXp;
            double pct = (double)progressXp / rangeXp;
            int barWidth = 30;
            int filled = (int)(pct * barWidth);
            filled = Math.Clamp(filled, 0, barWidth);

            WriteColored("  Progress: ", ConsoleColor.Gray);
            WriteColored("[", ConsoleColor.DarkGray);
            WriteColored(new string('█', filled), ConsoleColor.Green);
            WriteColored(new string('░', barWidth - filled), ConsoleColor.DarkGray);
            WriteColored("]", ConsoleColor.DarkGray);
            Console.WriteLine($" {pct:P0}");
        }

        Console.WriteLine();

        // Stats
        WriteLineColored("  ── Stats ─────────────────────────────────", ConsoleColor.DarkGray);
        WriteColored("  Total Audits:      ", ConsoleColor.Gray);
        Console.WriteLine(profile.TotalAudits);
        WriteColored("  Latest Score:      ", ConsoleColor.Gray);
        WriteLineColored($"{profile.LatestScore}", ScoreColor(profile.LatestScore));
        WriteColored("  Highest Score:     ", ConsoleColor.Gray);
        WriteLineColored($"{profile.HighestScore}", ScoreColor(profile.HighestScore));
        WriteColored("  Average Score:     ", ConsoleColor.Gray);
        Console.WriteLine(profile.AverageScore);
        WriteColored("  Criticals Fixed:   ", ConsoleColor.Gray);
        Console.WriteLine(profile.TotalCriticalFixed);
        Console.WriteLine();

        // Streaks
        WriteLineColored("  ── Streaks ───────────────────────────────", ConsoleColor.DarkGray);
        WriteColored("  🔥 Improvement:  ", ConsoleColor.Gray);
        WriteColored($"{profile.CurrentImprovementStreak} current", ConsoleColor.White);
        WriteColored(" / ", ConsoleColor.DarkGray);
        WriteLineColored($"{profile.BestImprovementStreak} best", ConsoleColor.Cyan);

        WriteColored("  💪 Perfect (90+): ", ConsoleColor.Gray);
        WriteColored($"{profile.CurrentPerfectStreak} current", ConsoleColor.White);
        WriteColored(" / ", ConsoleColor.DarkGray);
        WriteLineColored($"{profile.BestPerfectStreak} best", ConsoleColor.Cyan);
        Console.WriteLine();

        // Achievements
        WriteLineColored("  ── Achievements ──────────────────────────", ConsoleColor.DarkGray);
        if (profile.Achievements.Count == 0)
        {
            WriteLineColored("  No achievements yet. Keep auditing!", ConsoleColor.DarkGray);
        }
        else
        {
            foreach (var a in profile.Achievements)
            {
                WriteColored($"  {a.Icon} ", ConsoleColor.White);
                WriteColored(a.Name, ConsoleColor.Yellow);
                WriteLineColored($"  — {a.Description}", ConsoleColor.DarkGray);
            }
        }
        Console.WriteLine();
    }
}
