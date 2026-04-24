namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintProphecy(ProphecyReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║         🔮 SECURITY PROPHECY — Threat Forecast          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Storm Probability Gauge
        Console.Write("  Storm Probability: ");
        var stormColor = report.StormProbability switch
        {
            <= 15 => ConsoleColor.Green,
            <= 35 => ConsoleColor.DarkGreen,
            <= 55 => ConsoleColor.Yellow,
            <= 80 => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };
        Console.ForegroundColor = stormColor;
        var filled = report.StormProbability / 5;
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.StormProbability}%");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Outlook
        var outlookEmoji = report.Outlook switch
        {
            "Clearing" => "☀️",
            "Stable" => "🌤️",
            "Gathering" => "⛅",
            "Stormy" => "🌩️",
            "Critical" => "🌪️",
            _ => "🔮"
        };
        Console.Write("  Outlook: ");
        Console.ForegroundColor = stormColor;
        Console.WriteLine($"{outlookEmoji}  {report.Outlook}");
        Console.ForegroundColor = original;
        Console.Write("  Analyzed: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{report.AnalyzedRuns} runs  |  Forecast window: {report.ForecastDays} days");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Rising Threats
        if (report.RisingThreats.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ── Rising Threats ─────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var t in report.RisingThreats.Take(options.ProphecyTop))
            {
                var arrow = t.Momentum >= 2.0 ? "↑↑↑" : t.Momentum >= 1.0 ? "↑↑" : "↑";
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  {arrow} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(ProphecyTruncate(t.Category, 35));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{t.Module}]");
                Console.ForegroundColor = ProphecySevColor(t.Severity);
                Console.Write($"  {t.Severity}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  momentum:{t.Momentum:+0.0;-0.0}  recent:{t.OccurrencesRecent} older:{t.OccurrencesOlder}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Dormant Threats
        if (report.DormantThreats.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── Dormant Threats (may recur) ────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var t in report.DormantThreats.Take(options.ProphecyTop))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("  💤 ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(ProphecyTruncate(t.Category, 35));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{t.Module}]");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"  recurrence: {(int)(t.RecurrenceProbability * 100)}%");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  past occurrences: {t.OccurrencesOlder}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Fading Threats
        if (report.FadingThreats.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ── Fading Threats (improving) ─────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var t in report.FadingThreats.Take(options.ProphecyTop))
            {
                var arrow = t.Momentum <= -2.0 ? "↓↓↓" : t.Momentum <= -1.0 ? "↓↓" : "↓";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"  {arrow} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(ProphecyTruncate(t.Category, 35));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{t.Module}]  momentum:{t.Momentum:+0.0;-0.0}");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Module Momentum
        if (report.ModuleMomentum.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Module Momentum ────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            var maxName = report.ModuleMomentum.Keys.Max(k => k.Length);
            maxName = Math.Min(maxName, 25);
            foreach (var (mod, mom) in report.ModuleMomentum.OrderByDescending(kv => kv.Value))
            {
                var label = ProphecyTruncate(mod, maxName).PadRight(maxName);
                Console.Write($"  {label} ");
                var barLen = (int)Math.Min(Math.Abs(mom) * 10, 20);
                if (mom > 0.05)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(new string('▸', barLen));
                    Console.Write($" +{mom:0.00}");
                }
                else if (mom < -0.05)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write(new string('◂', barLen));
                    Console.Write($" {mom:0.00}");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("─ stable");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Prophecies
        if (report.Prophecies.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  ── Prophecies ─────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var p in report.Prophecies)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  🔮 ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(p);
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Proactive Recommendations ──────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            for (var i = 0; i < report.Recommendations.Count; i++)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {i + 1}. ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(report.Recommendations[i]);
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        Console.ForegroundColor = original;
    }

    static string ProphecyTruncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..(maxLen - 1)] + "…";

    static ConsoleColor ProphecySevColor(string severity) => severity switch
    {
        "Critical" => ConsoleColor.DarkRed,
        "High" => ConsoleColor.Red,
        "Medium" => ConsoleColor.Yellow,
        "Low" => ConsoleColor.DarkYellow,
        _ => ConsoleColor.DarkGray
    };
}
