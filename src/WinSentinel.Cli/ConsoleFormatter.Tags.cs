using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintTagAdded(string title, string category, List<string> tags)
    {
        var orig = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Tagged finding");
        Console.ForegroundColor = orig;

        Console.Write("  Finding:  ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(title);
        Console.ForegroundColor = orig;

        Console.Write("  Category: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(category);
        Console.ForegroundColor = orig;

        Console.Write("  Tags:     ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(string.Join(", ", tags));
        Console.ForegroundColor = orig;

        Console.WriteLine();
    }

    public static void PrintTagRemoved(string title, string category, List<string> tags, bool success)
    {
        var orig = Console.ForegroundColor;

        if (success)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Removed tags from: {title}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ⚠ Finding not found or tags not present: {title}");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Tags: {string.Join(", ", tags)}");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    public static void PrintTagList(
        IReadOnlyList<FindingTagManager.TaggedFinding> findings,
        List<string> filterTags)
    {
        var orig = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  TAGGED FINDINGS");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;

        if (filterTags.Count > 0)
        {
            Console.Write("  Filter: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(string.Join(", ", filterTags));
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        if (findings.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No tagged findings found.");
            Console.ForegroundColor = orig;
            Console.WriteLine();
            return;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Finding",-40} {"Category",-18} {"Tags",-25} {"Notes"}");
        Console.WriteLine($"  {"───────",-40} {"────────",-18} {"────",-25} {"─────"}");
        Console.ForegroundColor = orig;

        foreach (var f in findings)
        {
            var titleTrunc = f.Title.Length > 38 ? f.Title[..35] + "..." : f.Title;
            var catTrunc = f.Category.Length > 16 ? f.Category[..13] + "..." : f.Category;
            var tagStr = string.Join(", ", f.Tags);
            if (tagStr.Length > 23) tagStr = tagStr[..20] + "...";

            Console.Write($"  {titleTrunc,-40} ");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{catTrunc,-18} ");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{tagStr,-25} ");

            Console.ForegroundColor = f.Annotations.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            Console.WriteLine(f.Annotations.Count > 0 ? $"{f.Annotations.Count} note(s)" : "—");

            Console.ForegroundColor = orig;
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Total: {findings.Count} finding(s)");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    public static void PrintTagSearch(
        IReadOnlyList<FindingTagManager.TaggedFinding> results,
        string query)
    {
        var orig = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  TAG SEARCH RESULTS");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;

        Console.Write("  Query: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\"{query}\"");
        Console.ForegroundColor = orig;

        Console.Write("  Matches: ");
        Console.ForegroundColor = results.Count > 0 ? ConsoleColor.Green : ConsoleColor.Yellow;
        Console.WriteLine(results.Count);
        Console.ForegroundColor = orig;
        Console.WriteLine();

        foreach (var f in results)
        {
            Console.Write("  • ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(f.Title);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" [{f.Category}]");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  {string.Join(", ", f.Tags)}");
            Console.ForegroundColor = orig;

            foreach (var ann in f.Annotations.TakeLast(2))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    📝 ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(ann.Text);
                if (ann.Author != null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($" — {ann.Author}");
                }
                Console.WriteLine();
                Console.ForegroundColor = orig;
            }
        }

        Console.WriteLine();
    }

    public static void PrintTagReport(FindingTagManager.TagReport report)
    {
        var orig = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  TAG MANAGEMENT REPORT");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Summary stats
        Console.Write("  Tracked findings:  ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(report.TotalFindings);
        Console.ForegroundColor = orig;

        Console.Write("  Unique tags:       ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(report.TotalTags);
        Console.ForegroundColor = orig;

        Console.Write("  Total annotations: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(report.TotalAnnotations);
        Console.ForegroundColor = orig;

        Console.Write("  Untagged findings: ");
        Console.ForegroundColor = report.UntaggedCount > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.WriteLine(report.UntaggedCount);
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Tag distribution
        if (report.TagCounts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  TAG DISTRIBUTION");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            var maxCount = report.TagCounts.Values.Max();

            foreach (var (tag, count) in report.TagCounts)
            {
                var barLen = maxCount > 0 ? (int)(20.0 * count / maxCount) : 0;
                var bar = new string('█', barLen);

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"  {tag,-20} ");
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write(bar);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" {count}");
                Console.ForegroundColor = orig;
            }

            Console.WriteLine();
        }

        // Recently modified
        if (report.RecentlyModified.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  RECENTLY MODIFIED");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ──────────────────────────────────────────");
            Console.ForegroundColor = orig;
            Console.WriteLine();

            foreach (var f in report.RecentlyModified.Take(5))
            {
                Console.Write("  • ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(f.Title);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($" [{f.Category}]");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"  {string.Join(", ", f.Tags)}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  {f.LastModifiedAt:yyyy-MM-dd HH:mm}");
                Console.ForegroundColor = orig;
            }

            Console.WriteLine();
        }

        if (report.TotalFindings == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No tagged findings yet. Get started:");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  • winsentinel --tag autotag              Auto-tag findings by severity");
            Console.WriteLine("  • winsentinel --tag add --tag-finding \"Open RDP\" --tag-category Firewall --tag-value team-infra");
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }
    }

    public static void PrintTagAutoTagged(int count, int total)
    {
        var orig = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Auto-tagged {count} findings by severity");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Tags applied: urgent (critical), review-needed (warning), low-priority (info)");
        Console.WriteLine($"  Total tracked findings: {total}");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    public static void PrintTagRenamed(string from, string to, int affected)
    {
        var orig = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Renamed tag \"{from}\" → \"{to}\"");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Findings affected: {affected}");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    public static void PrintTagDeleted(List<string> tags, int affected)
    {
        var orig = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Deleted tag(s): {string.Join(", ", tags)}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Findings affected: {affected}");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }
}
