using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a categorized remediation cookbook with step-by-step fix instructions.
    /// </summary>
    public static void PrintCookbook(
        List<CookbookRecipeGroup> groups,
        int totalFindings,
        TimeSpan elapsed)
    {
        Console.WriteLine();
        WriteLineColored("  📖 Remediation Cookbook", ConsoleColor.Cyan);
        Console.WriteLine($"  {totalFindings} findings across {groups.Count} categories — generated in {elapsed.TotalSeconds:F1}s");
        Console.WriteLine();

        if (groups.Count == 0)
        {
            WriteLineColored("  ✅ No findings to remediate. System is clean!", ConsoleColor.Green);
            Console.WriteLine();
            return;
        }

        // Totals
        int totalAutoFix = groups.Sum(g => g.Recipes.Count(r => !string.IsNullOrEmpty(r.FixCommand)));
        int totalManual = totalFindings - totalAutoFix;

        Console.Write("  ");
        WriteColored($"⚡ {totalAutoFix} auto-fixable", ConsoleColor.Green);
        Console.Write("  │  ");
        WriteColored($"🔧 {totalManual} manual", ConsoleColor.Yellow);
        Console.WriteLine();
        Console.WriteLine();

        int recipeNum = 1;
        foreach (var group in groups)
        {
            var catColor = group.HighestSeverity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.Warning => ConsoleColor.Yellow,
                Severity.Info => ConsoleColor.Cyan,
                _ => ConsoleColor.Gray
            };

            var catEmoji = group.HighestSeverity switch
            {
                Severity.Critical => "🔴",
                Severity.Warning => "🟡",
                Severity.Info => "🔵",
                _ => "⚪"
            };

            WriteLineColored($"  {catEmoji} {group.Category} ({group.Recipes.Count} recipe{(group.Recipes.Count == 1 ? "" : "s")})", catColor);
            Console.WriteLine($"  {"─",1}{new string('─', 70)}");

            foreach (var recipe in group.Recipes)
            {
                var sevColor = recipe.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.Warning => ConsoleColor.Yellow,
                    Severity.Info => ConsoleColor.Cyan,
                    _ => ConsoleColor.Gray
                };

                Console.Write($"  #{recipeNum,3} ");
                WriteColored($"[{recipe.Severity}]", sevColor);
                Console.Write($" {CookbookTruncate(recipe.Title, 50)}");
                Console.WriteLine();

                // Effort estimate
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"       Module: {recipe.Module}  │  Effort: {recipe.Effort}");
                Console.ResetColor();

                // Description
                if (!string.IsNullOrEmpty(recipe.Description))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("       Why: ");
                    Console.ResetColor();
                    Console.WriteLine(CookbookTruncate(recipe.Description.Replace('\n', ' ').Replace('\r', ' '), 60));
                }

                // Remediation steps
                if (!string.IsNullOrEmpty(recipe.Remediation))
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("       How: ");
                    Console.ResetColor();

                    var lines = recipe.Remediation.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length == 1)
                    {
                        Console.WriteLine(CookbookTruncate(lines[0].Trim(), 60));
                    }
                    else
                    {
                        Console.WriteLine();
                        int step = 1;
                        foreach (var line in lines.Take(5))
                        {
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.Write($"             {step}. ");
                            Console.ResetColor();
                            Console.WriteLine(CookbookTruncate(line.Trim(), 55));
                            step++;
                        }
                        if (lines.Length > 5)
                        {
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.WriteLine($"             ... and {lines.Length - 5} more step(s)");
                            Console.ResetColor();
                        }
                    }
                }

                // Auto-fix command
                if (!string.IsNullOrEmpty(recipe.FixCommand))
                {
                    WriteColored("       ⚡ Auto-fix: ", ConsoleColor.Green);
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine(CookbookTruncate(recipe.FixCommand, 55));
                    Console.ResetColor();
                }

                // Verification hint
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"       Verify: Re-run audit and check \"{CookbookTruncate(recipe.Title, 40)}\" is resolved");
                Console.ResetColor();

                Console.WriteLine();
                recipeNum++;
            }
        }

        // Quick-start suggestion
        Console.WriteLine($"  {"─",1}{new string('─', 70)}");
        Console.Write("  💡 Quick start: ");
        if (totalAutoFix > 0)
        {
            WriteColored($"Run 'winsentinel fix' to auto-fix {totalAutoFix} finding{(totalAutoFix == 1 ? "" : "s")}", ConsoleColor.Green);
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("Start with the first recipe in each category");
        }
        Console.Write("  💡 Filter:      ");
        Console.WriteLine("Use --cookbook-severity, --cookbook-module, --cookbook-category, --cookbook-fixable");
        Console.WriteLine();
    }

    private static string CookbookTruncate(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return text.Length <= maxLen ? text : text[..(maxLen - 3)] + "...";
    }
}
