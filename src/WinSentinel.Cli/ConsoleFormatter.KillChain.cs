namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Prints the kill chain reconstruction report to the console.
    /// </summary>
    public static void PrintKillChain(KillChainReport report)
    {
        var original = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║   ⚔️  KILL CHAIN RECONSTRUCTOR — Attack Phase Mapping   ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Threat level banner
        var levelColor = report.ThreatLevel switch
        {
            "Critical" => ConsoleColor.Red,
            "High" => ConsoleColor.DarkRed,
            "Moderate" => ConsoleColor.Yellow,
            "Low" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Green
        };
        Console.Write("  Threat Level: ");
        Console.ForegroundColor = levelColor;
        Console.Write($"▓▓ {report.ThreatLevel.ToUpperInvariant()} ▓▓");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine($"  Coverage: {report.CoverageScore}% ({report.ActivePhaseCount}/{report.Phases.Count} phases active)");
        Console.WriteLine($"  Mapped: {report.MappedFindingCount} findings  |  Unmapped: {report.UnmappedFindingCount}");
        Console.WriteLine();

        // Kill chain visualization
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ─── Kill Chain Phases ─────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();

        foreach (var phase in report.Phases)
        {
            var marker = phase.IsActive ? "██" : "░░";
            var sevColor = phase.MaxSeverity switch
            {
                "Critical" => ConsoleColor.Red,
                "Warning" => ConsoleColor.Yellow,
                "Info" => ConsoleColor.Cyan,
                _ => ConsoleColor.DarkGray
            };

            Console.ForegroundColor = sevColor;
            Console.Write($"  {marker} ");
            Console.ForegroundColor = original;

            var label = $"[{phase.TacticId}] {phase.Phase}";
            if (phase.IsActive)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{label,-40}");
                Console.ForegroundColor = sevColor;
                Console.Write($" ({phase.FindingCount} findings, {phase.MaxSeverity})");
                Console.ForegroundColor = original;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{label,-40} (inactive)");
                Console.ForegroundColor = original;
            }
            Console.WriteLine();

            if (phase.IsActive && phase.ObservedTechniques.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                foreach (var tech in phase.ObservedTechniques.Take(3))
                    Console.WriteLine($"       └─ {tech}");
                Console.ForegroundColor = original;
            }
        }

        // Attack progressions
        if (report.Progressions.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Detected Attack Progressions ─────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var prog in report.Progressions)
            {
                var progColor = prog.Severity switch
                {
                    "Critical" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkRed,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkYellow
                };

                Console.ForegroundColor = progColor;
                Console.Write($"  ⚠ {prog.Name}");
                Console.ForegroundColor = original;
                Console.WriteLine($" [{prog.Severity}] — {prog.Confidence}% confidence");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    {prog.Description}");
                Console.Write("    Phases: ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(string.Join(" → ", prog.Phases));
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Predictions
        if (report.Predictions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Next Phase Predictions ───────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var pred in report.Predictions)
            {
                var probColor = pred.Probability >= 70 ? ConsoleColor.Red
                    : pred.Probability >= 50 ? ConsoleColor.Yellow
                    : ConsoleColor.DarkYellow;

                Console.ForegroundColor = probColor;
                Console.Write($"  ◆ {pred.Phase}");
                Console.ForegroundColor = original;
                Console.WriteLine($" — {pred.Probability}% probability");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    Rationale: {pred.Rationale}");
                Console.ForegroundColor = original;

                if (pred.PreventiveActions.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    foreach (var action in pred.PreventiveActions.Take(2))
                        Console.WriteLine($"    ✓ {action}");
                    Console.ForegroundColor = original;
                }
                Console.WriteLine();
            }
        }

        // Response plan
        if (report.ResponsePlan.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Response Plan ────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var action in report.ResponsePlan)
            {
                var urgColor = action.Urgency switch
                {
                    "Immediate" => ConsoleColor.Red,
                    "High" => ConsoleColor.Yellow,
                    _ => ConsoleColor.White
                };

                Console.ForegroundColor = urgColor;
                Console.Write($"  {action.Priority}. [{action.Urgency}]");
                Console.ForegroundColor = original;
                Console.WriteLine($" {action.Action}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"     Target: {action.TargetPhase} | Impact: {action.Impact}");
                Console.ForegroundColor = original;
            }
        }

        // Narrative
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ─── Narrative Summary ────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {report.Narrative}");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
