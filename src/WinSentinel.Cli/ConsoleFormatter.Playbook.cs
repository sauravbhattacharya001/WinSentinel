using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.IncidentResponsePlaybook;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>Print a table listing all available playbooks.</summary>
    public static void PrintPlaybookList(IReadOnlyList<Playbook> playbooks, bool verbose)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║              📋  Incident Response Playbooks                ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"ID",-20} {"Name",-30} {"Priority",-12} {"Steps",6}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"────────────────────",-20} {"──────────────────────────────",-30} {"────────────",-12} {"──────",6}");
        Console.ForegroundColor = original;

        foreach (var pb in playbooks)
        {
            var priorityColor = pb.DefaultPriority switch
            {
                Priority.P1_Critical => ConsoleColor.Red,
                Priority.P2_High => ConsoleColor.Yellow,
                Priority.P3_Medium => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            Console.Write($"  {pb.Id,-20} ");
            Console.Write($"{TruncatePlaybook(pb.Name, 28),-30} ");
            Console.ForegroundColor = priorityColor;
            Console.Write($"{pb.DefaultPriority,-12} ");
            Console.ForegroundColor = original;
            Console.WriteLine($"{pb.Steps.Count,6}");

            if (verbose)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    {pb.Description}");
                Console.WriteLine($"    Triggers: {string.Join(", ", pb.TriggerCategories)}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {playbooks.Count} playbooks available. Use --playbook-id <id> to view details.");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    /// <summary>Print detailed steps for a single playbook.</summary>
    public static void PrintPlaybookDetail(Playbook pb)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine($"  ║  📋  {pb.Name,-55}║");
        Console.WriteLine($"  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  ID:          {pb.Id}");
        Console.WriteLine($"  Priority:    {pb.DefaultPriority}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Description: {pb.Description}");
        Console.WriteLine($"  Triggers:    {string.Join(", ", pb.TriggerCategories)}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        foreach (var phase in Enum.GetValues<ResponsePhase>())
        {
            var steps = pb.StepsForPhase(phase);
            if (steps.Count == 0) continue;

            var phaseIcon = phase switch
            {
                ResponsePhase.Identification => "🔍",
                ResponsePhase.Containment => "🛡️",
                ResponsePhase.Eradication => "🧹",
                ResponsePhase.Recovery => "🔄",
                ResponsePhase.LessonsLearned => "📝",
                _ => "•"
            };

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  {phaseIcon} {phase}");
            Console.ForegroundColor = original;

            foreach (var step in steps)
            {
                var elevatedTag = step.RequiresElevation ? " [ADMIN]" : "";
                var durationTag = step.EstimatedDuration.HasValue
                    ? $" (~{FormatDuration(step.EstimatedDuration.Value)})"
                    : "";

                Console.Write($"    {step.Order,2}. ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(step.Action);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"{elevatedTag}{durationTag}");
                Console.ForegroundColor = original;
                Console.WriteLine($"        {step.Details}");

                if (step.Command is not null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"        > {step.Command}");
                    Console.ForegroundColor = original;
                }
            }

            Console.WriteLine();
        }

        if (pb.References.Length > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  References:");
            foreach (var r in pb.References)
                Console.WriteLine($"    • {r}");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    /// <summary>Print the full incident response plan generated from audit results.</summary>
    public static void PrintPlaybookPlan(IncidentResponsePlan plan, bool verbose)
    {
        var original = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║           🚨  Incident Response Plan                        ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Summary
        var priorityColor = plan.OverallPriority switch
        {
            Priority.P1_Critical => ConsoleColor.Red,
            Priority.P2_High => ConsoleColor.Yellow,
            Priority.P3_Medium => ConsoleColor.Cyan,
            _ => ConsoleColor.Gray
        };

        Console.Write("  Overall Priority: ");
        Console.ForegroundColor = priorityColor;
        Console.WriteLine(plan.OverallPriority);
        Console.ForegroundColor = original;
        Console.WriteLine($"  Findings Analyzed: {plan.TotalFindings}");
        Console.WriteLine($"  Playbooks Matched: {plan.MatchedPlaybooks}");
        Console.WriteLine($"  Est. Response Time: {FormatDuration(plan.EstimatedResponseTime)}");
        Console.WriteLine();

        // Immediate actions
        if (plan.ImmediateActions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ⚡ IMMEDIATE ACTIONS:");
            Console.ForegroundColor = original;
            foreach (var action in plan.ImmediateActions)
            {
                Console.WriteLine($"    ► {action}");
            }
            Console.WriteLine();
        }

        // Matched playbooks
        foreach (var match in plan.Matches)
        {
            var mPriorityColor = match.AdjustedPriority switch
            {
                Priority.P1_Critical => ConsoleColor.Red,
                Priority.P2_High => ConsoleColor.Yellow,
                Priority.P3_Medium => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  ┌─ {match.Playbook.Name}");
            Console.ForegroundColor = mPriorityColor;
            Console.Write($"  [{match.AdjustedPriority}]");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  (confidence: {match.ConfidenceScore:P0})");
            Console.ForegroundColor = original;

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  │  Reason: {match.MatchReason}");
            Console.WriteLine($"  │  Triggering findings: {match.TriggeringFindings.Count}");
            Console.ForegroundColor = original;

            if (verbose)
            {
                foreach (var finding in match.TriggeringFindings.Take(5))
                {
                    var sevColor = finding.Severity switch
                    {
                        Severity.Critical => ConsoleColor.Red,
                        Severity.Warning => ConsoleColor.Yellow,
                        _ => ConsoleColor.Gray
                    };

                    Console.Write("  │    • ");
                    Console.ForegroundColor = sevColor;
                    Console.Write($"[{finding.Severity}] ");
                    Console.ForegroundColor = original;
                    Console.WriteLine(TruncatePlaybook(finding.Title, 50));
                }

                if (match.TriggeringFindings.Count > 5)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  │    ... and {match.TriggeringFindings.Count - 5} more");
                    Console.ForegroundColor = original;
                }

                Console.WriteLine("  │");

                // Print condensed steps per phase
                foreach (var phase in Enum.GetValues<ResponsePhase>())
                {
                    var steps = match.Playbook.StepsForPhase(phase);
                    if (steps.Count == 0) continue;

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write($"  │  {phase}: ");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"{steps.Count} steps");
                    Console.ForegroundColor = original;

                    foreach (var step in steps.Take(3))
                    {
                        Console.WriteLine($"  │    {step.Order}. {step.Action}");
                    }

                    if (steps.Count > 3)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"  │    ... +{steps.Count - 3} more");
                        Console.ForegroundColor = original;
                    }
                }
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  └──────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Summary
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {plan.Summary}");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Use --playbook --verbose for detailed steps per matched playbook.");
        Console.WriteLine("  Use --playbook-list to see all available playbooks.");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalMinutes < 1) return "<1 min";
        if (duration.TotalHours < 1) return $"{(int)duration.TotalMinutes} min";
        if (duration.TotalDays < 1) return $"{(int)duration.TotalHours}h {duration.Minutes}m";
        return $"{(int)duration.TotalDays}d {duration.Hours}h";
    }

    private static string TruncatePlaybook(string text, int maxLength)
    {
        if (text.Length <= maxLength) return text;
        return text[..(maxLength - 1)] + "…";
    }
}
