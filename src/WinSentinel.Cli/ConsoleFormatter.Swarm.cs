using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintSwarmReport(SecuritySwarmIntelligence.SwarmReport report, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🐝  Security Swarm Intelligence       ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        // ── Collective Confidence Gauge ──────────────────────────────
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Collective Confidence: ");
        var scoreColor = report.CollectiveConfidence >= 80 ? ConsoleColor.Green
            : report.CollectiveConfidence >= 60 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.ForegroundColor = scoreColor;
        Console.Write($"{report.CollectiveConfidence}%");
        Console.ResetColor();

        int barWidth = 30;
        int filled = (int)(report.CollectiveConfidence / 100.0 * barWidth);
        Console.Write("  [");
        Console.ForegroundColor = scoreColor;
        Console.Write(new string('█', filled));
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(new string('░', barWidth - filled));
        Console.ResetColor();
        Console.WriteLine("]");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Agents: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{report.AgentAnalyses.Count} active");
        Console.ResetColor();

        // ── Agent Analyses ───────────────────────────────────────────
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Agent Analyses ────────────────────────────────");
        Console.ResetColor();

        foreach (var analysis in report.AgentAnalyses)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"  {analysis.Agent.Emoji} {analysis.Agent.Name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" ({analysis.Agent.Role})");
            Console.ResetColor();

            // Confidence on the right
            var agentColor = analysis.OverallConfidence >= 80 ? ConsoleColor.Green
                : analysis.OverallConfidence >= 60 ? ConsoleColor.Yellow
                : ConsoleColor.Red;
            var padding = Math.Max(1, 50 - analysis.Agent.Name.Length - analysis.Agent.Role.Length - 5);
            Console.Write(new string(' ', padding));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("Confidence: ");
            Console.ForegroundColor = agentColor;
            Console.WriteLine($"{analysis.OverallConfidence:F0}%");
            Console.ResetColor();

            // Show insights
            var insightsToShow = options.SwarmVerbose
                ? analysis.Insights
                : analysis.Insights.Take(3).ToList();

            for (int i = 0; i < insightsToShow.Count; i++)
            {
                var insight = insightsToShow[i];
                var connector = i < insightsToShow.Count - 1 ? "├─" : "└─";
                Console.Write($"  {connector} ");

                var sevColor = insight.Severity switch
                {
                    "CRITICAL" => ConsoleColor.Red,
                    "HIGH" => ConsoleColor.DarkYellow,
                    "WARNING" => ConsoleColor.Yellow,
                    "MEDIUM" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                Console.ForegroundColor = sevColor;
                Console.Write($"[{insight.Severity}]");
                Console.ResetColor();
                Console.WriteLine($" {insight.Finding}");
            }

            if (!options.SwarmVerbose && analysis.Insights.Count > 3)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"     ... +{analysis.Insights.Count - 3} more (use --swarm-verbose)");
                Console.ResetColor();
            }

            // Summary
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Summary: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(analysis.Summary);
            Console.ResetColor();
        }

        // ── Consensus Recommendations ────────────────────────────────
        if (report.Consensus.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Consensus Recommendations ─────────────────────");
            Console.ResetColor();
            Console.WriteLine();

            for (int i = 0; i < report.Consensus.Count; i++)
            {
                var item = report.Consensus[i];
                var priorityColor = item.Priority switch
                {
                    "URGENT" => ConsoleColor.Red,
                    "HIGH" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                Console.Write($"  #{i + 1}  ");
                Console.ForegroundColor = priorityColor;
                Console.Write($"[{item.Priority}]");
                Console.ResetColor();
                Console.WriteLine($" {item.Recommendation}");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("      Agreement: ");
                var agrColor = item.AgreementLevel >= 80 ? ConsoleColor.Green
                    : item.AgreementLevel >= 50 ? ConsoleColor.Yellow
                    : ConsoleColor.DarkGray;
                Console.ForegroundColor = agrColor;
                Console.Write($"{item.AgreementLevel}%");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" ({item.SupportingAgents.Count}/{report.AgentAnalyses.Count})");
                Console.Write("      Supported by: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(string.Join(", ", item.SupportingAgents));
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        // ── Voting Record ────────────────────────────────────────────
        if (report.VotingRecord.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Voting Record ─────────────────────────────────");
            Console.ResetColor();
            Console.WriteLine();

            var maxVotes = report.VotingRecord.Values.DefaultIfEmpty(1).Max();
            foreach (var (topic, votes) in report.VotingRecord.OrderByDescending(kv => kv.Value))
            {
                var barLen = (int)((votes * 20.0) / Math.Max(1, maxVotes));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  ");
                var label = topic.Length > 40 ? topic[..40] + "..." : topic;
                Console.Write(label.PadRight(44));
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(new string('█', barLen));
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($" {votes} vote{(votes != 1 ? "s" : "")}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // ── Dissenting Opinions ──────────────────────────────────────
        if (report.Dissents.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ── Dissenting Opinions ───────────────────────────");
            Console.ResetColor();
            Console.WriteLine();

            foreach (var dissent in report.Dissents)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.Write("  ⚡ ");
                Console.ResetColor();
                Console.WriteLine(dissent);
            }
            Console.WriteLine();
        }

        // ── Verdict ──────────────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  Verdict: ");
        Console.ForegroundColor = scoreColor;
        Console.WriteLine(report.CollectiveVerdict);
        Console.ResetColor();
        Console.WriteLine();
    }
}
