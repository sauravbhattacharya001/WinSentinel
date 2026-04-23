namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintMentor(MentorReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║          🎓 SECURITY MENTOR — Training Coach            ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Overall level
        var levelEmoji = report.OverallLevel switch
        {
            "Expert" => "🏆",
            "Advanced" => "💎",
            "Intermediate" => "⚡",
            "Beginner" => "🌱",
            _ => "🚀"
        };
        Console.Write("  Overall Level: ");
        Console.ForegroundColor = GetMentorColor(report.OverallScore);
        Console.WriteLine($"{levelEmoji} {report.OverallLevel} ({report.OverallScore}/100)");
        Console.ForegroundColor = original;

        Console.Write("  Strongest: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(report.StrongestDomain);
        Console.ForegroundColor = original;
        Console.Write("  |  Weakest: ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(report.WeakestDomain);
        Console.ForegroundColor = original;

        if (report.StreakDays > 0)
        {
            Console.Write("  Improvement Streak: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"🔥 {report.StreakDays} consecutive runs");
            Console.ForegroundColor = original;
        }
        Console.WriteLine();

        // Skill radar (horizontal bar chart)
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌─ Skill Assessment ─────────────────────────────────────┐");
        Console.ForegroundColor = original;

        foreach (var skill in report.Skills)
        {
            var barLen = skill.Score / 4; // max 25 chars
            var bar = new string('█', barLen) + new string('░', 25 - barLen);
            Console.Write($"  │ {skill.Domain,-14} ");
            Console.ForegroundColor = GetMentorColor(skill.Score);
            Console.Write(bar);
            Console.ForegroundColor = original;
            Console.Write($" {skill.Score,3}% {skill.Trend} ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"({skill.Level})");
            Console.ForegroundColor = original;
            if (skill.CriticalCount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($" ⚠{skill.CriticalCount}");
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  └────────────────────────────────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Learning paths
        if (report.LearningPaths.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  📚 Learning Paths");
            Console.ForegroundColor = original;
            Console.WriteLine("  ─────────────────");

            foreach (var path in report.LearningPaths)
            {
                var prioColor = path.Priority switch
                {
                    "High" => ConsoleColor.Red,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };
                Console.Write($"  [{path.Priority.ToUpperInvariant()}]");
                Console.ForegroundColor = prioColor;
                Console.Write($" {path.Domain}");
                Console.ForegroundColor = original;
                Console.WriteLine();

                for (int i = 0; i < path.Topics.Count; i++)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"    {i + 1}. ");
                    Console.ForegroundColor = original;
                    Console.WriteLine(path.Topics[i]);
                }
                Console.WriteLine();
            }
        }

        // Challenges
        if (report.Challenges.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  🎯 Challenges");
            Console.ForegroundColor = original;
            Console.WriteLine("  ──────────────");

            foreach (var ch in report.Challenges)
            {
                var diffBadge = ch.Difficulty switch
                {
                    "Hard" => "🔴",
                    "Medium" => "🟡",
                    _ => "🟢"
                };
                Console.Write($"  {diffBadge} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(ch.Title);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" [{ch.Domain}]");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($" +{ch.PointsReward}pts");
                Console.ForegroundColor = original;
                Console.WriteLine($"     {ch.Description}");
                Console.WriteLine();
            }
        }

        // Encouragement
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  {report.Encouragement}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    static ConsoleColor GetMentorColor(int score) => score switch
    {
        >= 80 => ConsoleColor.Green,
        >= 60 => ConsoleColor.Cyan,
        >= 40 => ConsoleColor.Yellow,
        >= 20 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };
}
