using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintDrift(
        List<DriftEntry> entries,
        int historyRuns,
        int driftDays,
        TimeSpan elapsed)
    {
        var original = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║         📡  Security Drift Monitor                  ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        var newCount = entries.Count(e => e.Type == DriftType.New);
        var resolvedCount = entries.Count(e => e.Type == DriftType.Resolved);
        var escalatedCount = entries.Count(e => e.Type == DriftType.Escalated);
        var deescalatedCount = entries.Count(e => e.Type == DriftType.Deescalated);
        var recurringCount = entries.Count(e => e.Type == DriftType.Recurring);

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  History: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{historyRuns} runs");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($" ({driftDays}d)");
        Console.Write("  │  Drift Events: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(entries.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  │  Time: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{elapsed.TotalSeconds:F1}s");
        Console.ForegroundColor = original;
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  ");
        if (escalatedCount > 0) { Console.ForegroundColor = ConsoleColor.Red; Console.Write($"⬆ {escalatedCount} Escalated"); Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write("  "); }
        if (newCount > 0) { Console.ForegroundColor = ConsoleColor.Yellow; Console.Write($"● {newCount} New"); Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write("  "); }
        if (recurringCount > 0) { Console.ForegroundColor = ConsoleColor.Magenta; Console.Write($"↻ {recurringCount} Recurring"); Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write("  "); }
        if (deescalatedCount > 0) { Console.ForegroundColor = ConsoleColor.Cyan; Console.Write($"⬇ {deescalatedCount} Deescalated"); Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write("  "); }
        if (resolvedCount > 0) { Console.ForegroundColor = ConsoleColor.Green; Console.Write($"✓ {resolvedCount} Resolved"); }
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        if (entries.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✨ No drift detected — configuration is stable!");
            Console.ForegroundColor = original;
            Console.WriteLine();
            return;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌─────────────┬──────────┬────────────────────────────────────────────┐");
        Console.WriteLine("  │ Type        │ Severity │ Finding                                    │");
        Console.WriteLine("  ├─────────────┼──────────┼────────────────────────────────────────────┤");
        Console.ForegroundColor = original;

        foreach (var entry in entries)
        {
            var typeIcon = entry.Type switch
            {
                DriftType.New => "● New      ",
                DriftType.Resolved => "✓ Resolved ",
                DriftType.Escalated => "⬆ Escalat. ",
                DriftType.Deescalated => "⬇ Deescal. ",
                DriftType.Recurring => "↻ Recurr.  ",
                _ => "  Unknown  "
            };

            var typeColor = entry.Type switch
            {
                DriftType.Escalated => ConsoleColor.Red,
                DriftType.New => ConsoleColor.Yellow,
                DriftType.Recurring => ConsoleColor.Magenta,
                DriftType.Deescalated => ConsoleColor.Cyan,
                DriftType.Resolved => ConsoleColor.Green,
                _ => ConsoleColor.Gray
            };

            var severity = entry.NewSeverity ?? entry.OldSeverity ?? Severity.Info;
            var sevStr = severity.ToString().PadRight(8);
            var sevColor = severity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.Warning => ConsoleColor.Yellow,
                Severity.Info => ConsoleColor.DarkGray,
                _ => ConsoleColor.Gray
            };

            var title = entry.Title.Length > 42 ? entry.Title[..39] + "..." : entry.Title.PadRight(42);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = typeColor;
            Console.Write(typeIcon);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = sevColor;
            Console.Write(sevStr);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(title);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(" │");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └─────────────┴──────────┴────────────────────────────────────────────┘");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Severity change details
        var sevChanges = entries.Where(e => e.Type == DriftType.Escalated || e.Type == DriftType.Deescalated).ToList();
        if (sevChanges.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ── Severity Changes ──");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var change in sevChanges)
            {
                var color = change.Type == DriftType.Escalated ? ConsoleColor.Red : ConsoleColor.Cyan;
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    ");
                Console.ForegroundColor = color;
                Console.Write(change.Type == DriftType.Escalated ? "⬆" : "⬇");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($" {change.Title}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  {change.OldSeverity} → ");
                Console.ForegroundColor = color;
                Console.WriteLine(change.NewSeverity?.ToString() ?? "?");
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Proactive recommendations
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ── Proactive Recommendations ──");
        Console.ForegroundColor = original;
        Console.WriteLine();

        if (escalatedCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("    ⚠ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{escalatedCount} finding(s) escalated — investigate configuration changes");
        }
        if (newCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("    ● ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{newCount} new finding(s) appeared — review recent system changes");
        }
        if (recurringCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("    ↻ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{recurringCount} finding(s) recurring — root cause not addressed");
        }
        if (resolvedCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    ✓ ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{resolvedCount} finding(s) resolved — verify fixes are permanent");
        }

        // Module breakdown
        var moduleGroups = entries.GroupBy(e => e.Module).OrderByDescending(g => g.Count()).Take(5).ToList();
        if (moduleGroups.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ── Most Active Modules ──");
            Console.ForegroundColor = original;
            Console.WriteLine();
            foreach (var group in moduleGroups)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(group.Key.PadRight(25));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                var parts = new List<string>();
                var esc = group.Count(e => e.Type == DriftType.Escalated);
                var nf = group.Count(e => e.Type == DriftType.New);
                var res = group.Count(e => e.Type == DriftType.Resolved);
                if (esc > 0) parts.Add($"{esc} escalated");
                if (nf > 0) parts.Add($"{nf} new");
                if (res > 0) parts.Add($"{res} resolved");
                Console.WriteLine(string.Join(", ", parts));
            }
        }

        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
