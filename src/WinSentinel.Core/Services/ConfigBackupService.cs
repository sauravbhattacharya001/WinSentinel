using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Portable configuration bundle for backup/restore of all WinSentinel settings.
/// Includes ignore rules, baselines, and the active policy.
/// </summary>
public class ConfigBundle
{
    /// <summary>Bundle format version for forward-compatibility.</summary>
    public int Version { get; set; } = 1;

    /// <summary>When this bundle was created.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Machine name where the bundle was exported from.</summary>
    public string MachineName { get; set; } = Environment.MachineName;

    /// <summary>OS version of the exporting machine.</summary>
    public string OsVersion { get; set; } = Environment.OSVersion.ToString();

    /// <summary>Username who exported the bundle.</summary>
    public string ExportedBy { get; set; } = Environment.UserName;

    /// <summary>Optional description for this backup.</summary>
    public string? Description { get; set; }

    /// <summary>All ignore rules at time of export.</summary>
    public List<IgnoreRule> IgnoreRules { get; set; } = [];

    /// <summary>All saved baselines at time of export (full snapshots).</summary>
    public List<SecurityBaseline> Baselines { get; set; } = [];

    /// <summary>The active security policy at time of export, if any.</summary>
    public SecurityPolicy? Policy { get; set; }

    /// <summary>Component counts for quick summary.</summary>
    public ConfigBundleSummary Summary { get; set; } = new();
}

/// <summary>
/// Quick summary of what's in a config bundle.
/// </summary>
public class ConfigBundleSummary
{
    public int IgnoreRuleCount { get; set; }
    public int BaselineCount { get; set; }
    public bool HasPolicy { get; set; }
    public int TotalItems => IgnoreRuleCount + BaselineCount + (HasPolicy ? 1 : 0);
}

/// <summary>
/// Result of a config restore/import operation.
/// </summary>
public class ConfigRestoreResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>Source machine name from the bundle.</summary>
    public string? SourceMachine { get; set; }

    /// <summary>When the bundle was originally created.</summary>
    public DateTimeOffset? BundleCreatedAt { get; set; }

    public int IgnoreRulesImported { get; set; }
    public int BaselinesImported { get; set; }
    public bool PolicyImported { get; set; }

    public int IgnoreRulesSkipped { get; set; }
    public int BaselinesSkipped { get; set; }

    public List<string> Warnings { get; set; } = [];

    public int TotalImported => IgnoreRulesImported + BaselinesImported + (PolicyImported ? 1 : 0);
    public int TotalSkipped => IgnoreRulesSkipped + BaselinesSkipped;
}

/// <summary>
/// Service for exporting and importing WinSentinel configuration as a portable JSON bundle.
/// Supports full backup/restore of ignore rules, baselines, and the active policy.
/// </summary>
public class ConfigBackupService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Export all current configuration into a portable bundle.
    /// </summary>
    public ConfigBundle Export(string? description = null)
    {
        var bundle = new ConfigBundle
        {
            Description = description
        };

        // ── Ignore Rules ──
        var ignoreService = new IgnoreRuleService();
        bundle.IgnoreRules = ignoreService.GetAllRules();

        // ── Baselines (load full objects) ──
        var baselineService = new BaselineService();
        var summaries = baselineService.ListBaselines();
        foreach (var summary in summaries)
        {
            var full = baselineService.LoadBaseline(summary.Name);
            if (full != null)
                bundle.Baselines.Add(full);
        }

        // ── Policy (export current active policy) ──
        try
        {
            var policyIgnoreService = new IgnoreRuleService();
            var policyManager = new PolicyManager(policyIgnoreService, new ComplianceProfileService());
            bundle.Policy = policyManager.Export();
        }
        catch
        {
            // No policy configured — that's fine
        }

        // ── Summary ──
        bundle.Summary = new ConfigBundleSummary
        {
            IgnoreRuleCount = bundle.IgnoreRules.Count,
            BaselineCount = bundle.Baselines.Count,
            HasPolicy = bundle.Policy != null
        };

        return bundle;
    }

    /// <summary>
    /// Serialize a bundle to JSON.
    /// </summary>
    public static string ToJson(ConfigBundle bundle)
    {
        return JsonSerializer.Serialize(bundle, JsonOptions);
    }

    /// <summary>
    /// Deserialize a bundle from JSON.
    /// </summary>
    public static ConfigBundle? FromJson(string json)
    {
        return JsonSerializer.Deserialize<ConfigBundle>(json, JsonOptions);
    }

    /// <summary>
    /// Inspect a bundle file without importing it.
    /// </summary>
    public static ConfigBundle? Inspect(string filePath)
    {
        if (!File.Exists(filePath))
            return null;

        var json = File.ReadAllText(filePath);
        return FromJson(json);
    }

    /// <summary>
    /// Import configuration from a bundle, merging with existing config.
    /// Existing items are skipped unless <paramref name="overwrite"/> is true.
    /// </summary>
    public ConfigRestoreResult Import(ConfigBundle bundle, bool overwrite = false)
    {
        var result = new ConfigRestoreResult
        {
            Success = true,
            SourceMachine = bundle.MachineName,
            BundleCreatedAt = bundle.CreatedAt
        };

        // ── Ignore Rules ──
        try
        {
            var ignoreService = new IgnoreRuleService();
            var existingRules = ignoreService.GetAllRules();
            var existingKeys = new HashSet<string>(
                existingRules.Select(r => $"{r.Pattern}|{r.MatchMode}|{r.Module ?? ""}"),
                StringComparer.OrdinalIgnoreCase);

            foreach (var rule in bundle.IgnoreRules)
            {
                var key = $"{rule.Pattern}|{rule.MatchMode}|{rule.Module ?? ""}";

                if (existingKeys.Contains(key) && !overwrite)
                {
                    result.IgnoreRulesSkipped++;
                    continue;
                }

                try
                {
                    ignoreService.AddRule(
                        rule.Pattern,
                        rule.MatchMode,
                        rule.Module,
                        rule.Severity,
                        rule.Reason ?? $"Imported from {bundle.MachineName}",
                        rule.ExpiresAt);
                    result.IgnoreRulesImported++;
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Ignore rule '{rule.Pattern}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Failed to import ignore rules: {ex.Message}");
        }

        // ── Baselines ──
        try
        {
            var baselineService = new BaselineService();
            var existingNames = baselineService.ListBaselines()
                .Select(b => b.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var baseline in bundle.Baselines)
            {
                if (existingNames.Contains(baseline.Name) && !overwrite)
                {
                    result.BaselinesSkipped++;
                    continue;
                }

                try
                {
                    // Write baseline directly to the baselines directory
                    var json = JsonSerializer.Serialize(baseline, JsonOptions);
                    var dir = BaselineService.GetDefaultBaselineDir();
                    Directory.CreateDirectory(dir);
                    File.WriteAllText(Path.Combine(dir, $"{baseline.Name}.json"), json);
                    result.BaselinesImported++;
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Baseline '{baseline.Name}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Failed to import baselines: {ex.Message}");
        }

        // ── Policy ──
        if (bundle.Policy != null)
        {
            try
            {
                var policyManager = new PolicyManager(new IgnoreRuleService(), new ComplianceProfileService());
                policyManager.Import(bundle.Policy, overwrite);
                result.PolicyImported = true;
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"Policy: {ex.Message}");
            }
        }

        if (result.Warnings.Count > 0 && result.TotalImported == 0)
        {
            result.Success = false;
            result.Error = "Import completed with errors; no items were successfully imported.";
        }

        return result;
    }
}
