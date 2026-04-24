namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    public static void PrintRhythm(RhythmReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║        🎵 SECURITY RHYTHM — Temporal Analysis           ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Rhythm Score
        Console.Write("  Rhythm Score: ");
        var scoreColor = report.RhythmScore switch
        {
            >= 80 => ConsoleColor.Green,
            >= 60 => ConsoleColor.DarkGreen,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };
        Console.ForegroundColor = scoreColor;
        var filled = report.RhythmScore / 5;
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.RhythmScore}/100");
        Console.ForegroundColor = original;
        Console.Write("  ");
        Console.ForegroundColor = scoreColor;
        Console.WriteLine(report.RhythmVerdict);
        Console.ForegroundColor = original;

        Console.Write("  Analyzed: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{report.AnalyzedRuns} runs over {report.HistoryDays} days  |  {report.FirstRun:MMM dd} – {report.LastRun:MMM dd}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Hourly Activity Chart
        if (report.HourlyProfile.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Hourly Activity Pattern ─────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var maxFindings = report.HourlyProfile.Max(h => h.AvgFindings);
            if (maxFindings == 0) maxFindings = 1;

            for (int h = 0; h < 24; h++)
            {
                var slot = report.HourlyProfile.FirstOrDefault(s => s.Hour == h);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {h:D2}:00 ");
                if (slot != null)
                {
                    var barLen = (int)(slot.AvgFindings / maxFindings * 30);
                    var isQuiet = report.QuietWindows.Any(w => w.StartHour == h);
                    var isHot = report.HotWindows.Any(w => w.StartHour == h);
                    Console.ForegroundColor = isHot ? ConsoleColor.Red : isQuiet ? ConsoleColor.Green : ConsoleColor.DarkCyan;
                    Console.Write(new string('█', Math.Max(1, barLen)));
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($" {slot.AvgFindings:F1}f  s:{slot.AvgScore:F0}  n:{slot.RunCount}");
                    if (isHot) { Console.ForegroundColor = ConsoleColor.Red; Console.Write(" 🔥"); }
                    if (isQuiet) { Console.ForegroundColor = ConsoleColor.Green; Console.Write(" 🌙"); }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("·  no data");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Weekly Profile
        if (report.WeeklyProfile.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Weekly Pattern ──────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            var maxDow = report.WeeklyProfile.Max(d => d.AvgFindings);
            if (maxDow == 0) maxDow = 1;

            foreach (var day in report.WeeklyProfile.OrderBy(d => d.DayIndex))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {day.DayOfWeek,-12}");
                var barLen = (int)(day.AvgFindings / maxDow * 25);
                var isBest = day == report.WeeklyProfile.OrderBy(d => d.AvgFindings).First();
                var isWorst = day == report.WeeklyProfile.OrderByDescending(d => d.AvgFindings).First();
                Console.ForegroundColor = isWorst ? ConsoleColor.Red : isBest ? ConsoleColor.Green : ConsoleColor.DarkCyan;
                Console.Write(new string('█', Math.Max(1, barLen)));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" {day.AvgFindings:F1}f  s:{day.AvgScore:F0}  n:{day.RunCount}");
                if (isWorst) { Console.ForegroundColor = ConsoleColor.Red; Console.Write(" ⚠️ peak"); }
                if (isBest) { Console.ForegroundColor = ConsoleColor.Green; Console.Write(" ✅ calm"); }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Detected Cycles
        if (report.DetectedCycles.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  ── Detected Cycles ─────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var cycle in report.DetectedCycles.OrderByDescending(c => c.Strength).Take(8))
            {
                var strengthBar = (int)(cycle.Strength * 15);
                Console.Write("  ");
                Console.ForegroundColor = cycle.Strength > 0.5 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                Console.Write($"  r={cycle.Strength:F2} ");
                Console.Write(new string('■', Math.Max(1, strengthBar)));
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  {cycle.Label}");
                if (cycle.Strength > 0.5)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write(" ★");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // Quiet & Hot Windows
        if (report.QuietWindows.Count > 0 || report.HotWindows.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Scan Windows ────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            if (report.QuietWindows.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  🌙 Quiet Windows (best for maintenance):");
                Console.ForegroundColor = original;
                foreach (var w in report.QuietWindows)
                {
                    Console.Write("     ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"{w.StartHour:D2}:00-{w.EndHour:D2}:00");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  {w.Reason}");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }

            if (report.HotWindows.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  🔥 Hot Windows (peak threat activity):");
                Console.ForegroundColor = original;
                foreach (var w in report.HotWindows)
                {
                    Console.Write("     ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"{w.StartHour:D2}:00-{w.EndHour:D2}:00");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  {w.Reason}");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ── Proactive Recommendations ───────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var rec in report.Recommendations)
            {
                Console.Write("  💡 ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(rec);
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  Tip: Use --rhythm-days <N> to adjust analysis window (default: 90)");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
