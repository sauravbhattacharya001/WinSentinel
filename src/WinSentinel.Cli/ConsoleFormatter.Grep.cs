using System.Diagnostics;
using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print grep/search results with highlighted matching text.
    /// </summary>
    public static void PrintGrepResults(
        List<(string Module, Finding Finding)> matches,
        string pattern,
        Regex regex,
        int totalFindings,
        bool showContext,
        TimeSpan elapsed)
    {
        Console.WriteLine();
        WriteLineColored("  🔍 Finding Grep Results", ConsoleColor.Cyan);
        Console.WriteLine($"  Pattern: {pattern}");
        Console.WriteLine($"  {matches.Count} match{(matches.Count == 1 ? "" : "es")} found (of {totalFindings} total findings) in {elapsed.TotalSeconds:F1}s");
        Console.WriteLine();

        if (matches.Count == 0)
        {
            WriteLineColored("  No findings match your search pattern.", ConsoleColor.DarkGray);
            Console.WriteLine();
            return;
        }

        // Group by module for cleaner output
        var grouped = matches.GroupBy(m => m.Module).OrderBy(g => g.Key);

        foreach (var group in grouped)
        {
            WriteLineColored($"  ┌─ {group.Key} ({group.Count()} match{(group.Count() == 1 ? "" : "es")})", ConsoleColor.White);

            foreach (var (_, finding) in group)
            {
                var sevColor = GrepSeverityColor(finding.Severity);

                Console.Write("  │ ");
                WriteColored($"[{finding.Severity}]", sevColor);
                Console.Write(" ");

                // Print title with highlighted matches
                PrintHighlighted(finding.Title ?? "(no title)", regex);
                Console.WriteLine();

                if (showContext)
                {
                    if (!string.IsNullOrEmpty(finding.Description) && regex.IsMatch(finding.Description))
                    {
                        Console.Write("  │   ");
                        WriteColored("Desc: ", ConsoleColor.DarkGray);
                        PrintHighlighted(GrepTruncate(finding.Description, 120), regex);
                        Console.WriteLine();
                    }

                    if (!string.IsNullOrEmpty(finding.Remediation) && regex.IsMatch(finding.Remediation))
                    {
                        Console.Write("  │   ");
                        WriteColored("Fix:  ", ConsoleColor.DarkGray);
                        PrintHighlighted(GrepTruncate(finding.Remediation, 120), regex);
                        Console.WriteLine();
                    }
                }
            }

            WriteLineColored("  └─", ConsoleColor.DarkGray);
            Console.WriteLine();
        }

        // Summary by severity
        var bySev = matches.GroupBy(m => m.Finding.Severity)
            .OrderByDescending(g => g.Key)
            .ToList();

        if (bySev.Count > 0)
        {
            Console.Write("  Summary: ");
            for (int i = 0; i < bySev.Count; i++)
            {
                if (i > 0) Console.Write(", ");
                WriteColored($"{bySev[i].Count()} {bySev[i].Key}", GrepSeverityColor(bySev[i].Key));
            }
            Console.WriteLine();
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Print text with regex matches highlighted in yellow.
    /// </summary>
    private static void PrintHighlighted(string text, Regex regex)
    {
        int lastEnd = 0;
        foreach (Match match in regex.Matches(text))
        {
            // Print text before the match
            if (match.Index > lastEnd)
            {
                Console.Write(text[lastEnd..match.Index]);
            }

            // Print the match highlighted
            var prev = Console.BackgroundColor;
            Console.BackgroundColor = ConsoleColor.DarkYellow;
            Console.ForegroundColor = ConsoleColor.Black;
            Console.Write(match.Value);
            Console.ResetColor();

            lastEnd = match.Index + match.Length;
        }

        // Print remaining text
        if (lastEnd < text.Length)
        {
            Console.Write(text[lastEnd..]);
        }
    }

    private static string GrepTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return text;
        // Replace newlines with spaces for single-line display
        text = text.Replace('\n', ' ').Replace('\r', ' ');
        return text.Length <= maxLen ? text : text[..(maxLen - 3)] + "...";
    }

    private static ConsoleColor GrepSeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.Warning => ConsoleColor.Yellow,
        Severity.Info => ConsoleColor.Cyan,
        Severity.Pass => ConsoleColor.Green,
        _ => ConsoleColor.Gray
    };
}
