using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintSearchResults(SearchResult result, bool highlight, bool showRemediation)
    {
        var orig = Console.ForegroundColor;

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║         🔍  Finding Search Results          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ForegroundColor = orig;
        Console.WriteLine();

        // Search info
        Console.Write("  Query:    ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"\"{result.Query}\"");
        Console.ForegroundColor = orig;

        Console.Write("  Matches:  ");
        Console.ForegroundColor = result.Matches.Count > 0 ? ConsoleColor.Green : ConsoleColor.Yellow;
        Console.Write(result.Matches.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($" of {result.TotalFindings} total findings");
        Console.ForegroundColor = orig;

        if (result.SeverityFilter != null)
        {
            Console.Write("  Filter:   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"severity={result.SeverityFilter}");
            Console.ForegroundColor = orig;
        }
        if (result.ModuleFilter != null)
        {
            Console.Write("  Filter:   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"module={result.ModuleFilter}");
            Console.ForegroundColor = orig;
        }

        Console.WriteLine();

        if (result.Matches.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No findings matched your search query.");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Try a broader query, or remove filters.");
            Console.ForegroundColor = orig;
            Console.WriteLine();
            return;
        }

        // Severity breakdown
        if (result.SeverityBreakdown.Count > 0)
        {
            Console.Write("  ");
            foreach (var (sev, count) in result.SeverityBreakdown.OrderByDescending(kv => SevRank(kv.Key)))
            {
                Console.ForegroundColor = SevColor(sev);
                Console.Write($"{count} {sev.ToLower()}  ");
            }
            Console.ForegroundColor = orig;
            Console.WriteLine();
            Console.WriteLine();
        }

        // Results
        for (int i = 0; i < result.Matches.Count; i++)
        {
            var match = result.Matches[i];
            var finding = match.Finding;
            var sevColor = SevColor(finding.Severity.ToString());

            // Index + severity badge
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {i + 1,3}. ");
            Console.ForegroundColor = sevColor;
            Console.Write($"[{finding.Severity}]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(" ");

            // Title with highlighting
            if (highlight)
            {
                var segments = FindingSearchService.HighlightMatches(finding.Title ?? "", result.Query);
                foreach (var (text, isMatch) in segments)
                {
                    Console.ForegroundColor = isMatch ? ConsoleColor.Yellow : ConsoleColor.White;
                    Console.Write(text);
                }
            }
            else
            {
                Console.Write(finding.Title);
            }
            Console.WriteLine();

            // Module + matched fields
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"       Module: {match.ModuleCategory}");
            Console.Write($"  |  Matched: {string.Join(", ", match.MatchedFields)}");
            Console.Write($"  |  Score: {match.RelevanceScore}");
            Console.WriteLine();

            // Description with highlighting
            if (!string.IsNullOrEmpty(finding.Description))
            {
                Console.Write("       ");
                if (highlight)
                {
                    var segments = FindingSearchService.HighlightMatches(finding.Description, result.Query);
                    var totalLen = 0;
                    foreach (var (text, isMatch) in segments)
                    {
                        var remaining = 120 - totalLen;
                        if (remaining <= 0) break;
                        var truncated = text.Length > remaining ? text[..remaining] + "..." : text;
                        Console.ForegroundColor = isMatch ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                        Console.Write(truncated);
                        totalLen += truncated.Length;
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    var desc = finding.Description.Length > 120
                        ? finding.Description[..120] + "..."
                        : finding.Description;
                    Console.Write(desc);
                }
                Console.WriteLine();
            }

            // Remediation (optional)
            if (showRemediation && !string.IsNullOrEmpty(finding.Remediation))
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                var rem = finding.Remediation.Length > 120
                    ? finding.Remediation[..120] + "..."
                    : finding.Remediation;
                Console.WriteLine($"       → {rem}");
            }

            // Fix command
            if (!string.IsNullOrEmpty(finding.FixCommand))
            {
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine($"       $ {finding.FixCommand}");
            }

            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        // Module breakdown
        if (result.ModuleBreakdown.Count > 1)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Modules: ");
            foreach (var (mod, count) in result.ModuleBreakdown.OrderByDescending(kv => kv.Value))
            {
                Console.Write($"{mod}({count}) ");
            }
            Console.ForegroundColor = orig;
            Console.WriteLine();
            Console.WriteLine();
        }
    }

    private static ConsoleColor SevColor(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => ConsoleColor.Red,
        "warning" => ConsoleColor.Yellow,
        "info" => ConsoleColor.Cyan,
        "pass" => ConsoleColor.Green,
        _ => ConsoleColor.Gray
    };

    private static int SevRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "warning" => 3,
        "info" => 2,
        "pass" => 1,
        _ => 0
    };
}
