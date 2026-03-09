using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

/// <summary>
/// Handles all policy-related CLI subcommands (export, import, validate, diff).
/// Extracted from Program.cs to reduce file size and improve cohesion.
/// </summary>
internal static class PolicyCommandHandler
{
    public static int Handle(CliOptions options)
    {
        var ignoreService = new IgnoreRuleService();
        var complianceService = new ComplianceProfileService();
        var policyManager = new PolicyManager(ignoreService, complianceService);

        switch (options.PolicyAction)
        {
            case PolicyAction.Export:
                return HandleExport(policyManager, options);
            case PolicyAction.Import:
                return HandleImport(policyManager, options);
            case PolicyAction.Validate:
                return HandleValidate(policyManager, options);
            case PolicyAction.Diff:
                return HandleDiff(policyManager, options);
            default:
                PrintUsage();
                return 0;
        }
    }

    private static void PrintUsage()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  Usage: WinSentinel --policy <export|import|validate|diff> [options]");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine("  Actions:");
        Console.WriteLine("    export                Export current config to a policy file");
        Console.WriteLine("    import                Import a policy file (replaces current config)");
        Console.WriteLine("    validate              Validate a policy file without applying");
        Console.WriteLine("    diff                  Compare a policy file against current config");
        Console.WriteLine();
        Console.WriteLine("  Options:");
        Console.WriteLine("    --policy-file <path>  Policy file path (default: winsentinel-policy.json)");
        Console.WriteLine("    --policy-name <name>  Policy name (for export)");
        Console.WriteLine("    --policy-desc <text>  Policy description (for export)");
        Console.WriteLine("    --force               Import even if validation has errors");
        Console.WriteLine("    --json                Output in JSON format");
    }

    private static int HandleExport(PolicyManager pm, CliOptions options)
    {
        var filePath = options.PolicyFile ?? "winsentinel-policy.json";

        try
        {
            pm.ExportToFile(filePath, options.PolicyName, options.PolicyDescription);

            if (options.Json)
            {
                var policy = PolicyManager.LoadFromFile(filePath);
                Console.WriteLine(PolicyManager.Serialize(policy));
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✅ Policy exported to: {filePath}");
                Console.ResetColor();

                var policy = PolicyManager.LoadFromFile(filePath);
                Console.WriteLine($"     Name:          {policy.Name}");
                Console.WriteLine($"     Ignore rules:  {policy.IgnoreRules.Count}");
                Console.WriteLine($"     Alert rules:   {policy.AlertRules.Count}");
                Console.WriteLine($"     Alert groups:  {policy.AlertRuleGroups.Count}");
                if (!string.IsNullOrEmpty(policy.ComplianceProfile))
                    Console.WriteLine($"     Profile:       {policy.ComplianceProfile}");
                if (policy.MinimumScore.HasValue)
                    Console.WriteLine($"     Min score:     {policy.MinimumScore}");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ❌ Export failed: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int HandleImport(PolicyManager pm, CliOptions options)
    {
        var filePath = options.PolicyFile ?? "winsentinel-policy.json";

        try
        {
            var policy = PolicyManager.LoadFromFile(filePath);
            var result = pm.Import(policy, options.Force);

            if (options.Json)
            {
                var jsonOpts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new JsonStringEnumConverter() }
                };
                Console.WriteLine(JsonSerializer.Serialize(result, jsonOpts));
            }
            else if (result.Success)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✅ Policy imported from: {filePath}");
                Console.ResetColor();
                Console.WriteLine($"     Ignore rules:  {result.IgnoreRulesImported}");
                Console.WriteLine($"     Alert rules:   {result.AlertRulesImported}");
                Console.WriteLine($"     Alert groups:  {result.AlertGroupsImported}");
                if (result.ComplianceProfileSet != null)
                    Console.WriteLine($"     Profile set:   {result.ComplianceProfileSet}");
                if (result.Warnings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    foreach (var w in result.Warnings)
                        Console.WriteLine($"     ⚠  {w}");
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ❌ Import failed: {result.Error}");
                Console.ResetColor();
                return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ❌ Import failed: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int HandleValidate(PolicyManager pm, CliOptions options)
    {
        var filePath = options.PolicyFile ?? "winsentinel-policy.json";

        try
        {
            var policy = PolicyManager.LoadFromFile(filePath);
            var result = pm.Validate(policy);

            if (options.Json)
            {
                var jsonOpts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new JsonStringEnumConverter() }
                };
                Console.WriteLine(JsonSerializer.Serialize(result, jsonOpts));
            }
            else
            {
                Console.WriteLine($"  Policy: {policy.Name}");
                Console.WriteLine($"  File:   {filePath}");
                Console.WriteLine();

                if (result.IsValid)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  ✅ Policy is valid");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  ❌ Validation failed ({result.Errors.Count} error(s))");
                    Console.ResetColor();
                    foreach (var err in result.Errors)
                        Console.WriteLine($"     ✗ {err}");
                }

                if (result.Warnings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    foreach (var w in result.Warnings)
                        Console.WriteLine($"     ⚠  {w}");
                    Console.ResetColor();
                }
            }

            return result.IsValid ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ❌ Validate failed: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int HandleDiff(PolicyManager pm, CliOptions options)
    {
        var filePath = options.PolicyFile ?? "winsentinel-policy.json";

        try
        {
            var policy = PolicyManager.LoadFromFile(filePath);
            var diff = pm.Diff(policy);

            if (options.Json)
            {
                var jsonOpts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new JsonStringEnumConverter() }
                };
                Console.WriteLine(JsonSerializer.Serialize(diff, jsonOpts));
            }
            else
            {
                Console.WriteLine($"  Comparing current config vs: {filePath}");
                Console.WriteLine();

                if (!diff.HasChanges)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  ✅ No differences — current config matches the policy file");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("  Changes:");
                    Console.ResetColor();

                    foreach (var detail in diff.Details)
                    {
                        if (detail.StartsWith('+'))
                            Console.ForegroundColor = ConsoleColor.Green;
                        else if (detail.StartsWith('-'))
                            Console.ForegroundColor = ConsoleColor.Red;
                        else
                            Console.ForegroundColor = ConsoleColor.Yellow;

                        Console.WriteLine($"    {detail}");
                        Console.ResetColor();
                    }

                    Console.WriteLine();
                    Console.WriteLine($"  Summary: +{diff.IgnoreRulesAdded}/-{diff.IgnoreRulesRemoved} ignore, " +
                        $"+{diff.AlertRulesAdded}/-{diff.AlertRulesRemoved} alert, " +
                        $"+{diff.SkippedModulesAdded}/-{diff.SkippedModulesRemoved} skipped modules");
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ❌ Diff failed: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }
}
