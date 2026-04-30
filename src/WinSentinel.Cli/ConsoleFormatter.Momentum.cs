namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintMomentum(MomentumReport report)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║      🏎️ MOMENTUM — Security Posture Kinematic Analyzer      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        if (report.Phase == MomentumPhase.InsufficientData)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ⚠️  {report.Summary}");
            Console.ForegroundColor = original;
            Console.WriteLine();
            return;
        }

        // ── Momentum Score Gauge ─────────────────────────────────
        var scoreColor = report.MomentumScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.Cyan,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        Console.Write("  Momentum Score: ");
        Console.ForegroundColor = scoreColor;
        Console.Write($"{report.MomentumScore}/100");
        Console.ForegroundColor = original;

        var phaseEmoji = report.Phase switch
        {
            MomentumPhase.Surging => "🚀",
            MomentumPhase.Accelerating => "📈",
            MomentumPhase.Cruising => "✈️",
            MomentumPhase.Stalled => "⏸️",
            MomentumPhase.FalsePlateau => "⚠️",
            MomentumPhase.Decelerating => "📉",
            MomentumPhase.Regressing => "🔻",
            MomentumPhase.FreeFall => "💥",
            _ => "❓"
        };

        var phaseColor = report.Phase switch
        {
            MomentumPhase.Surging or MomentumPhase.Accelerating => ConsoleColor.Green,
            MomentumPhase.Cruising => ConsoleColor.Cyan,
            MomentumPhase.Stalled or MomentumPhase.Decelerating => ConsoleColor.Yellow,
            MomentumPhase.FalsePlateau or MomentumPhase.Regressing => ConsoleColor.DarkYellow,
            MomentumPhase.FreeFall => ConsoleColor.Red,
            _ => ConsoleColor.Gray
        };

        Console.Write("  │  Phase: ");
        Console.ForegroundColor = phaseColor;
        Console.WriteLine($"{phaseEmoji} {report.Phase}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Kinematics Dashboard ─────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌─ Kinematics ──────────────────────────────────────────┐");
        Console.ForegroundColor = original;

        var k = report.Kinematics;
        PrintKinematicRow("  Position (Score)", $"{k.Position}/100", k.Position >= 70 ? ConsoleColor.Green : k.Position >= 40 ? ConsoleColor.Yellow : ConsoleColor.Red);
        PrintKinematicRow("  Velocity", $"{k.Velocity:+0.000;-0.000} pts/day", k.Velocity > 0 ? ConsoleColor.Green : k.Velocity < -0.05 ? ConsoleColor.Red : ConsoleColor.Yellow);
        PrintKinematicRow("  Recent Velocity", $"{k.RecentVelocity:+0.000;-0.000} pts/day", k.RecentVelocity > 0 ? ConsoleColor.Green : k.RecentVelocity < -0.05 ? ConsoleColor.Red : ConsoleColor.Yellow);
        PrintKinematicRow("  Acceleration", $"{k.Acceleration:+0.0000;-0.0000}", k.Acceleration > 0 ? ConsoleColor.Green : k.Acceleration < -0.01 ? ConsoleColor.Red : ConsoleColor.Yellow);
        PrintKinematicRow("  Variance", $"{k.Variance:F1}", k.Variance < 5 ? ConsoleColor.Green : k.Variance < 20 ? ConsoleColor.Yellow : ConsoleColor.Red);
        PrintKinematicRow("  Trend Slope", $"{k.TrendSlope:+0.00;-0.00}", k.TrendSlope > 0 ? ConsoleColor.Green : ConsoleColor.Red);
        PrintKinematicRow("  Risk Momentum", $"{k.RiskMomentum:+0.000;-0.000}", k.RiskMomentum < 0 ? ConsoleColor.Green : k.RiskMomentum > 0.05 ? ConsoleColor.Red : ConsoleColor.Yellow);

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Patterns ─────────────────────────────────────────────
        if (report.Patterns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Detected Patterns ──────────────────────────────────────┐");
            Console.ForegroundColor = original;

            foreach (var pattern in report.Patterns)
            {
                var sevColor = pattern.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkYellow,
                    "Medium" => ConsoleColor.Yellow,
                    "Good" => ConsoleColor.Green,
                    _ => ConsoleColor.Gray
                };

                Console.Write($"  {pattern.Emoji} ");
                Console.ForegroundColor = sevColor;
                Console.Write($"[{pattern.Severity}]");
                Console.ForegroundColor = original;
                Console.WriteLine($" {pattern.Name} — {pattern.Description} (×{pattern.Occurrences})");
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Module Momentum (top 5 worst + top 5 best) ──────────
        if (report.ModuleMomentum.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Module Momentum ────────────────────────────────────────┐");
            Console.ForegroundColor = original;

            var worst = report.ModuleMomentum.Where(m => m.RecentVelocity < -0.05).Take(5).ToList();
            var best = report.ModuleMomentum.Where(m => m.RecentVelocity > 0.05).OrderByDescending(m => m.RecentVelocity).Take(5).ToList();

            if (worst.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  ▼ Declining:");
                Console.ForegroundColor = original;
                foreach (var m in worst)
                {
                    Console.WriteLine($"    {m.ModuleName,-30} Score: {m.CurrentScore,3} │ {m.RecentVelocity:+0.00;-0.00} pts/day │ {m.Direction}");
                }
            }

            if (best.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  ▲ Improving:");
                Console.ForegroundColor = original;
                foreach (var m in best)
                {
                    Console.WriteLine($"    {m.ModuleName,-30} Score: {m.CurrentScore,3} │ {m.RecentVelocity:+0.00;-0.00} pts/day │ {m.Direction}");
                }
            }

            var stable = report.ModuleMomentum.Count - worst.Count - best.Count;
            if (stable > 0)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine($"  ─ {stable} module(s) stable");
                Console.ForegroundColor = original;
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // ── Interventions ────────────────────────────────────────
        if (report.Interventions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ┌─ Autonomous Interventions ───────────────────────────────┐");
            Console.ForegroundColor = original;

            foreach (var intervention in report.Interventions)
            {
                var priColor = intervention.Priority switch
                {
                    "Critical" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkYellow,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.Write("  ");
                Console.ForegroundColor = priColor;
                Console.Write($"[{intervention.Priority}]");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($" {intervention.Action}");
                Console.ForegroundColor = original;
                Console.WriteLine($"    Rationale: {intervention.Rationale}");

                Console.ForegroundColor = ConsoleColor.Gray;
                foreach (var step in intervention.Steps)
                    Console.WriteLine($"      • {step}");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"    Expected: {intervention.ExpectedImpact}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
            Console.ForegroundColor = original;
        }

        // ── Footer ───────────────────────────────────────────────
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"  Analyzed {report.DataPointCount} data points over {report.AnalyzedDays} days │ {report.AnalyzedAt:yyyy-MM-dd HH:mm} UTC");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    private static void PrintKinematicRow(string label, string value, ConsoleColor valueColor)
    {
        var original = Console.ForegroundColor;
        Console.Write($"  {label,-22} ");
        Console.ForegroundColor = valueColor;
        Console.WriteLine(value);
        Console.ForegroundColor = original;
    }
}
