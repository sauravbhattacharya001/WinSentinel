using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles all ignore-rule CLI subcommands (add, list, remove, clear, purge).
/// Extracted from Program.cs to reduce file size and improve cohesion.
/// </summary>
internal static class IgnoreCommandHandler
{
    public static int Handle(CliOptions options)
    {
        var service = new IgnoreRuleService();

        return options.IgnoreAction switch
        {
            IgnoreAction.Add => HandleAdd(service, options),
            IgnoreAction.List => HandleList(service, options),
            IgnoreAction.Remove => HandleRemove(service, options),
            IgnoreAction.Clear => HandleClear(service, options),
            IgnoreAction.Purge => HandlePurge(service, options),
            _ => HandleList(service, options)
        };
    }

    private static int HandleAdd(IgnoreRuleService service, CliOptions options)
    {
        var pattern = options.IgnorePattern!;

        // Parse match mode
        var matchMode = IgnoreMatchMode.Contains;
        if (!string.IsNullOrEmpty(options.IgnoreMatchMode))
        {
            matchMode = options.IgnoreMatchMode.ToLowerInvariant() switch
            {
                "exact" => IgnoreMatchMode.Exact,
                "contains" => IgnoreMatchMode.Contains,
                "regex" => IgnoreMatchMode.Regex,
                _ => IgnoreMatchMode.Contains
            };
        }

        // Parse severity
        Severity? severity = null;
        if (!string.IsNullOrEmpty(options.IgnoreSeverity))
        {
            severity = options.IgnoreSeverity.ToLowerInvariant() switch
            {
                "critical" => Severity.Critical,
                "warning" => Severity.Warning,
                "info" => Severity.Info,
                "pass" => Severity.Pass,
                _ => null
            };
            if (severity == null)
            {
                ConsoleFormatter.PrintError($"Unknown severity: {options.IgnoreSeverity}. Use critical, warning, info, or pass.");
                return 3;
            }
        }

        // Parse expiration
        DateTimeOffset? expiresAt = null;
        if (options.IgnoreExpireDays.HasValue)
        {
            expiresAt = DateTimeOffset.UtcNow.AddDays(options.IgnoreExpireDays.Value);
        }

        try
        {
            var rule = service.AddRule(pattern, matchMode, options.IgnoreModule, severity,
                options.IgnoreReason, expiresAt);

            if (options.Json)
            {
                var jsonResult = new
                {
                    action = "added",
                    id = rule.Id,
                    pattern = rule.Pattern,
                    matchMode = rule.MatchMode.ToString(),
                    module = rule.Module,
                    severity = rule.Severity?.ToString(),
                    reason = rule.Reason,
                    expiresAt = rule.ExpiresAt,
                    createdAt = rule.CreatedAt
                };
                var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
                var json = JsonSerializer.Serialize(jsonResult, jsonOptions);
                OutputHelper.WriteOutput(json, options.OutputFile);
            }
            else if (!options.Quiet)
            {
                ConsoleFormatter.PrintIgnoreRuleAdded(rule);
            }

            return 0;
        }
        catch (ArgumentException ex)
        {
            ConsoleFormatter.PrintError(ex.Message);
            return 3;
        }
    }

    private static int HandleList(IgnoreRuleService service, CliOptions options)
    {
        var rules = service.GetAllRules();

        if (rules.Count == 0)
        {
            if (options.Json)
            {
                OutputHelper.WriteOutput("[]", options.OutputFile);
            }
            else if (!options.Quiet)
            {
                var original = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  No ignore rules defined. Add one with: winsentinel --ignore add <pattern>");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            return 0;
        }

        if (options.Json)
        {
            var jsonRules = rules.Select(r => new
            {
                id = r.Id,
                pattern = r.Pattern,
                matchMode = r.MatchMode.ToString(),
                module = r.Module,
                severity = r.Severity?.ToString(),
                reason = r.Reason,
                enabled = r.Enabled,
                isActive = r.IsActive,
                isExpired = r.IsExpired,
                createdAt = r.CreatedAt,
                expiresAt = r.ExpiresAt
            });
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
            var json = JsonSerializer.Serialize(jsonRules, jsonOptions);
            OutputHelper.WriteOutput(json, options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintIgnoreRuleList(rules, options.Quiet);
        }

        return 0;
    }

    private static int HandleRemove(IgnoreRuleService service, CliOptions options)
    {
        var id = options.IgnoreRuleId!;

        if (service.RemoveRule(id))
        {
            if (options.Json)
            {
                OutputHelper.WriteOutput($"{{\"action\": \"removed\", \"id\": \"{id}\"}}", options.OutputFile);
            }
            else if (!options.Quiet)
            {
                var original = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ Ignore rule '{id}' removed.");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            return 0;
        }
        else
        {
            if (options.Json)
            {
                OutputHelper.WriteOutput($"{{\"error\": \"Rule '{id}' not found.\"}}", options.OutputFile);
            }
            else
            {
                ConsoleFormatter.PrintError($"Ignore rule '{id}' not found. Use --ignore list to see rules.");
            }
            return 3;
        }
    }

    private static int HandleClear(IgnoreRuleService service, CliOptions options)
    {
        var count = service.ClearAllRules();

        if (options.Json)
        {
            OutputHelper.WriteOutput($"{{\"action\": \"cleared\", \"removed\": {count}}}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Cleared {count} ignore rule(s).");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        return 0;
    }

    private static int HandlePurge(IgnoreRuleService service, CliOptions options)
    {
        var count = service.PurgeExpiredRules();

        if (options.Json)
        {
            OutputHelper.WriteOutput($"{{\"action\": \"purged\", \"removed\": {count}}}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            if (count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ Purged {count} expired ignore rule(s).");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  No expired rules to purge.");
            }
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        return 0;
    }
}
