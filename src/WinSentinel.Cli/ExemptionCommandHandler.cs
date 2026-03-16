using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles all exemption-related CLI subcommands (review, expiring, stale, unused, summary).
/// Extracted from Program.cs to reduce file size and improve cohesion.
/// </summary>
public static class ExemptionCommandHandler
{
    public static int Handle(CliOptions options)
    {
        var ignoreService = new IgnoreRuleService();
        var reviewService = new ExemptionReviewService(ignoreService)
        {
            ExpiryWarningDays = options.ExemptionWarningDays,
            StaleDays = options.ExemptionStaleDays
        };

        var result = reviewService.Review();

        if (options.Json)
        {
            var jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() },
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            var json = JsonSerializer.Serialize(new
            {
                summary = result.Summary,
                expiringSoon = result.ExpiringSoon.Select(r => FormatReviewedRuleJson(r)),
                recentlyExpired = result.RecentlyExpired.Select(r => FormatReviewedRuleJson(r)),
                stale = result.Stale.Select(r => FormatReviewedRuleJson(r)),
                unused = result.Unused.Select(r => FormatReviewedRuleJson(r)),
                disabled = result.Disabled.Select(r => FormatReviewedRuleJson(r))
            }, jsonOptions);
            WriteOutput(json, options.OutputFile);
            return 0;
        }

        return options.ExemptionAction switch
        {
            ExemptionAction.Review => HandleReview(result),
            ExemptionAction.Expiring => HandleExpiring(result),
            ExemptionAction.Stale => HandleStale(result),
            ExemptionAction.Unused => HandleUnused(result),
            ExemptionAction.Summary => HandleSummary(result),
            _ => HandleReview(result)
        };
    }

    private static int HandleReview(ExemptionReviewService.ReviewResult result)
    {
        HandleSummary(result);

        if (result.ExpiringSoon.Count > 0)
            PrintSection("EXPIRING SOON", result.ExpiringSoon, ConsoleColor.Yellow);

        if (result.RecentlyExpired.Count > 0)
            PrintSection("RECENTLY EXPIRED", result.RecentlyExpired, ConsoleColor.Red);

        if (result.Stale.Count > 0)
            PrintSection("STALE (needs review)", result.Stale, ConsoleColor.DarkYellow);

        if (result.Unused.Count > 0)
            PrintSection("UNUSED (no current matches)", result.Unused, ConsoleColor.Gray);

        if (result.Disabled.Count > 0)
            PrintSection("DISABLED", result.Disabled, ConsoleColor.DarkGray);

        if (result.ExpiringSoon.Count == 0 && result.RecentlyExpired.Count == 0 &&
            result.Stale.Count == 0 && result.Unused.Count == 0 && result.Disabled.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  All exemptions are current and healthy. No action needed.");
            Console.ResetColor();
            Console.WriteLine();
        }

        return 0;
    }

    private static int HandleExpiring(ExemptionReviewService.ReviewResult result)
    {
        if (result.ExpiringSoon.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  No exemptions expiring soon.");
            Console.ResetColor();
            return 0;
        }
        PrintSection("EXPIRING SOON", result.ExpiringSoon, ConsoleColor.Yellow);
        return 0;
    }

    private static int HandleStale(ExemptionReviewService.ReviewResult result)
    {
        if (result.Stale.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  No stale exemptions found.");
            Console.ResetColor();
            return 0;
        }
        PrintSection("STALE (needs review)", result.Stale, ConsoleColor.DarkYellow);
        return 0;
    }

    private static int HandleUnused(ExemptionReviewService.ReviewResult result)
    {
        if (result.Unused.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  No unused exemptions found. All rules match current findings.");
            Console.ResetColor();
            return 0;
        }
        PrintSection("UNUSED (no current matches)", result.Unused, ConsoleColor.Gray);
        return 0;
    }

    private static int HandleSummary(ExemptionReviewService.ReviewResult result)
    {
        var s = result.Summary;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════╗");
        Console.WriteLine("  ║       EXEMPTION REVIEW DASHBOARD        ║");
        Console.WriteLine("  ╚══════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        var healthColor = s.HealthScore switch
        {
            >= 90 => ConsoleColor.Green,
            >= 70 => ConsoleColor.Yellow,
            >= 50 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        Console.Write("  Health: ");
        Console.ForegroundColor = healthColor;
        Console.Write($"{s.HealthGrade} ({s.HealthScore:F0}%)");
        Console.ResetColor();
        Console.WriteLine($"  |  Total Rules: {s.TotalRules}  |  Active: {s.ActiveRules}");
        Console.WriteLine();

        Console.WriteLine($"  {"Category",-25} {"Count",6}  Status");
        Console.WriteLine($"  {"─────────────────────────",-25} {"──────",6}  ──────────────");

        PrintSummaryRow("Expiring Soon", s.ExpiringSoon, s.ExpiringSoon > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
        PrintSummaryRow("Recently Expired", s.RecentlyExpired, s.RecentlyExpired > 0 ? ConsoleColor.Red : ConsoleColor.Green);
        PrintSummaryRow("Stale (no expiry)", s.StaleRules, s.StaleRules > 0 ? ConsoleColor.DarkYellow : ConsoleColor.Green);
        PrintSummaryRow("Unused (0 matches)", s.UnusedRules, s.UnusedRules > 0 ? ConsoleColor.Gray : ConsoleColor.Green);
        PrintSummaryRow("Disabled", s.DisabledRules, s.DisabledRules > 0 ? ConsoleColor.DarkGray : ConsoleColor.Green);
        Console.WriteLine();

        return 0;
    }

    private static void PrintSummaryRow(string label, int count, ConsoleColor color)
    {
        Console.Write($"  {label,-25} ");
        Console.ForegroundColor = color;
        Console.Write($"{count,6}");
        Console.ResetColor();
        var statusText = count == 0 ? "  OK" : "  Needs attention";
        Console.WriteLine(statusText);
    }

    private static void PrintSection(string title, List<ExemptionReviewService.ReviewedRule> rules, ConsoleColor color)
    {
        Console.WriteLine();
        Console.ForegroundColor = color;
        Console.WriteLine($"  ── {title} ({rules.Count}) ──");
        Console.ResetColor();
        Console.WriteLine();

        foreach (var r in rules)
        {
            var rule = r.Rule;
            Console.ForegroundColor = color;
            Console.Write($"  [{rule.Id}] ");
            Console.ResetColor();
            Console.Write($"\"{rule.Pattern}\"");

            if (rule.Module != null)
                Console.Write($" (module: {rule.Module})");
            if (rule.Severity.HasValue)
                Console.Write($" (severity: {rule.Severity})");

            Console.WriteLine();

            Console.Write("    ");
            if (r.DaysUntilExpiry.HasValue)
            {
                var days = r.DaysUntilExpiry.Value;
                if (days < 0)
                    Console.Write($"Expired {-days}d ago  |  ");
                else if (days == 0)
                    Console.Write("Expires today  |  ");
                else
                    Console.Write($"Expires in {days}d  |  ");
            }
            else
            {
                Console.Write("No expiry  |  ");
            }

            Console.Write($"Age: {r.AgeDays}d  |  Matches: {r.MatchCount}");

            if (rule.Reason != null)
                Console.Write($"  |  Reason: {rule.Reason}");

            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine($"    → {r.Recommendation}");
            Console.ResetColor();
            Console.WriteLine();
        }
    }

    private static object FormatReviewedRuleJson(ExemptionReviewService.ReviewedRule r)
    {
        return new
        {
            id = r.Rule.Id,
            pattern = r.Rule.Pattern,
            matchMode = r.Rule.MatchMode.ToString(),
            module = r.Rule.Module,
            severity = r.Rule.Severity?.ToString(),
            reason = r.Rule.Reason,
            enabled = r.Rule.Enabled,
            createdAt = r.Rule.CreatedAt,
            expiresAt = r.Rule.ExpiresAt,
            status = r.Status.ToString(),
            daysUntilExpiry = r.DaysUntilExpiry,
            ageDays = r.AgeDays,
            matchCount = r.MatchCount,
            recommendation = r.Recommendation
        };
    }

    private static void WriteOutput(string content, string? outputFile)
    {
        if (outputFile != null)
        {
            File.WriteAllText(outputFile, content);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Written to {outputFile}");
            Console.ResetColor();
        }
        else
        {
            Console.WriteLine(content);
        }
    }
}
