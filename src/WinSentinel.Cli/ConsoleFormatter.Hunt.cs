namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintHunt(HuntReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║        🎯 THREAT HUNT — Autonomous Hunt Engine          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Hunt Score Gauge
        Console.Write("  Hunt Safety Score: ");
        var scoreColor = report.HuntScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.DarkGreen,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };
        Console.ForegroundColor = scoreColor;
        var filled = report.HuntScore / 5;
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.HuntScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Summary Stats
        Console.Write("  Hypotheses Tested: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.TotalHypotheses}");
        Console.ForegroundColor = original;

        Console.Write("  │  Confirmed: ");
        Console.ForegroundColor = report.ConfirmedThreats > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.ConfirmedThreats}");
        Console.ForegroundColor = original;

        Console.Write("  │  Suspicious: ");
        Console.ForegroundColor = report.SuspiciousFindings > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.Write($"{report.SuspiciousFindings}");
        Console.ForegroundColor = original;

        Console.Write("  │  Cleared: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"{report.ClearedHypotheses}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Findings Analyzed: {report.TotalFindings}  │  History Runs: {report.HistoryRunsAnalyzed}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Confirmed Threats
        var confirmed = report.Hypotheses.Where(h => h.Status == HuntStatus.Confirmed).ToList();
        if (confirmed.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ── 🚨 Confirmed Threats ──────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var h in confirmed)
            {
                PrintHypothesis(h, original);
            }
        }

        // Suspicious
        var suspicious = report.Hypotheses.Where(h => h.Status == HuntStatus.Suspicious).ToList();
        if (suspicious.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── ⚠️  Suspicious Findings ───────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var h in suspicious)
            {
                PrintHypothesis(h, original);
            }
        }

        // Cleared
        var cleared = report.Hypotheses.Where(h => h.Status == HuntStatus.Cleared).ToList();
        if (cleared.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ── ✅ Cleared Hypotheses ─────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var h in cleared)
            {
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.Write($"  ✓ {h.Name}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{h.MitreId}]");
                Console.Write($"  Score: {h.ThreatScore}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Recommended Actions
        if (report.RecommendedActions.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── 📋 Recommended Actions ────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var action in report.RecommendedActions.Take(options.HuntTop))
            {
                var urgencyColor = action.Urgency switch
                {
                    "Immediate" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkRed,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  #{action.Priority} ");
                Console.ForegroundColor = urgencyColor;
                Console.Write($"[{action.Urgency}] ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(action.HypothesisName);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{action.MitreId}]");
                Console.ForegroundColor = original;
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    → {HuntTruncate(action.Action, 80)}");
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // No threats scenario
        if (report.TotalHypotheses == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✨ No threat hypotheses generated — current findings look clean.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        else if (report.ConfirmedThreats == 0 && report.SuspiciousFindings == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✨ All hunt hypotheses cleared — no active threats detected.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Footer
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Hunt completed at {report.HuntTimestamp:yyyy-MM-dd HH:mm:ss} UTC");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    private static void PrintHypothesis(HuntHypothesis h, ConsoleColor original)
    {
        var statusColor = h.Status switch
        {
            HuntStatus.Confirmed => ConsoleColor.Red,
            HuntStatus.Suspicious => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };

        var statusIcon = h.Status switch
        {
            HuntStatus.Confirmed => "🚨",
            HuntStatus.Suspicious => "⚠️",
            _ => "✅"
        };

        Console.ForegroundColor = statusColor;
        Console.Write($"  {statusIcon} ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(h.Name);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  [{h.MitreId}]");
        Console.ForegroundColor = statusColor;
        Console.Write($"  Score: {h.ThreatScore}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"    {HuntTruncate(h.Description, 90)}");
        Console.ForegroundColor = original;

        if (h.Evidence.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    Evidence: ");
            Console.ForegroundColor = ConsoleColor.Gray;
            foreach (var e in h.Evidence.Take(5))
            {
                Console.Write($"• {HuntTruncate(e, 50)}  ");
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        if (!string.IsNullOrEmpty(h.Recommendation))
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("    ↳ ");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(HuntTruncate(h.Recommendation, 85));
            Console.ForegroundColor = original;
        }

        Console.WriteLine();
    }

    private static string HuntTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLen ? text : text[..(maxLen - 1)] + "…";
    }
}
