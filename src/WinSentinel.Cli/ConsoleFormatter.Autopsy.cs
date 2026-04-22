using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintAutopsy(SecurityAutopsyService.AutopsyReport report, CliOptions options)
    {
        Console.WriteLine();

        // ── Header ───────────────────────────────────────────────────
        var headerColor = report.Summary.OverallVerdict switch
        {
            "Critical" => ConsoleColor.Red,
            "Declining" => ConsoleColor.Yellow,
            "Recovering" => ConsoleColor.Cyan,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = headerColor;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║            S E C U R I T Y   A U T O P S Y                 ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.ResetColor();
        Console.WriteLine();

        // ── Summary / Verdict ────────────────────────────────────────
        PrintSectionHeader("VERDICT");
        var verdictColor = report.Summary.OverallVerdict switch
        {
            "Critical" => ConsoleColor.Red,
            "Declining" => ConsoleColor.Yellow,
            "Recovering" => ConsoleColor.Cyan,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = verdictColor;
        Console.WriteLine($"  ╔═══════════════════════════╗");
        Console.WriteLine($"  ║   {report.Summary.OverallVerdict.ToUpper(),-24}║");
        Console.WriteLine($"  ╚═══════════════════════════╝");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {report.Summary.VerdictRationale}");
        Console.ResetColor();
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Degradation Events: {report.Summary.TotalDegradations}");
        Console.WriteLine($"  Critical Events:    {report.Summary.CriticalEvents}");
        Console.WriteLine($"  Worst Module:       {report.Summary.WorstModule}");
        Console.WriteLine($"  Largest Drop:       {report.Summary.LargestDrop} points");
        Console.ResetColor();
        Console.WriteLine();

        // ── Degradation Events ───────────────────────────────────────
        if (report.Degradations.Count > 0)
        {
            PrintSectionHeader("DEGRADATION EVENTS");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Date",-12} {"Type",-16} {"Module",-20} {"Drop",5} {"Sev",4}");
            Console.WriteLine($"  {"────────────",-12} {"────────────────",-16} {"────────────────────",-20} {"─────",5} {"────",4}");
            Console.ResetColor();

            foreach (var d in report.Degradations)
            {
                Console.ForegroundColor = d.Severity == 1 ? ConsoleColor.Red
                    : d.Severity == 2 ? ConsoleColor.Yellow
                    : ConsoleColor.DarkGray;
                var drop = d.ScoreBefore - d.ScoreAfter;
                var sevLabel = d.Severity == 1 ? "CRIT" : d.Severity == 2 ? "MAJ" : "MIN";
                Console.WriteLine($"  {d.DetectedAt:yyyy-MM-dd}  {Truncate(d.Type, 16),-16} {Truncate(d.Module, 20),-20} {drop,5} {sevLabel,4}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // ── Root Cause Analysis ──────────────────────────────────────
        if (report.RootCauses.Count > 0)
        {
            PrintSectionHeader("ROOT CAUSE ANALYSIS");
            foreach (var rc in report.RootCauses)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  [{rc.Category}] ");
                Console.ResetColor();
                Console.WriteLine(rc.Description);

                // Confidence bar
                var filled = (int)(rc.Confidence * 20);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    Confidence: ");
                Console.ForegroundColor = rc.Confidence >= 0.8 ? ConsoleColor.Green
                    : rc.Confidence >= 0.5 ? ConsoleColor.Yellow
                    : ConsoleColor.Red;
                Console.Write(new string('█', filled));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(new string('░', 20 - filled));
                Console.WriteLine($" {rc.Confidence:P0}");
                Console.ResetColor();

                // Evidence
                foreach (var ev in rc.Evidence.Take(3))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"    • {ev}");
                    Console.ResetColor();
                }

                // Suggested fix
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"    → {rc.SuggestedFix}");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        // ── Forensic Timeline ────────────────────────────────────────
        if (report.Timeline.Count > 0)
        {
            PrintSectionHeader("FORENSIC TIMELINE");
            // Show last 30 entries max
            var entries = report.Timeline.TakeLast(30);
            foreach (var t in entries)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {t.Timestamp:MM-dd HH:mm} ");
                Console.ResetColor();
                Console.Write($"{t.Icon} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{t.Event,-14} ");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"[{Truncate(t.Module, 18)}] ");
                Console.ResetColor();
                Console.WriteLine(Truncate(t.Detail, 40));
            }
            Console.WriteLine();
        }

        // ── Lessons Learned ──────────────────────────────────────────
        if (report.Lessons.Count > 0)
        {
            PrintSectionHeader("LESSONS LEARNED");
            foreach (var lesson in report.Lessons)
            {
                var prioColor = lesson.Priority switch
                {
                    "High" => ConsoleColor.Red,
                    "Medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Cyan
                };
                Console.ForegroundColor = prioColor;
                Console.Write($"  [{lesson.Priority.ToUpper()}] ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(lesson.Title);
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"         {lesson.Description}");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"         → {lesson.ActionItem}");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        // ── Proactive Recommendations ────────────────────────────────
        if (report.Recommendations.Count > 0)
        {
            PrintSectionHeader("PROACTIVE RECOMMENDATIONS");
            foreach (var rec in report.Recommendations)
            {
                var tagColor = rec.Tag switch
                {
                    "PREVENT" => ConsoleColor.Green,
                    "DETECT" => ConsoleColor.Yellow,
                    "RESPOND" => ConsoleColor.Red,
                    _ => ConsoleColor.Cyan
                };
                Console.ForegroundColor = tagColor;
                Console.Write($"  [{rec.Tag}] ");
                Console.ResetColor();
                Console.WriteLine(rec.Action);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"         {rec.Rationale}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // ── All Clear ────────────────────────────────────────────────
        if (report.Degradations.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No degradation events detected — posture has been stable.");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
