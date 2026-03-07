using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Portable security policy that bundles ignore rules, compliance profile
/// selection, alert rules, and scan configuration into a single file.
/// Enables "Security Policy as Code" — version-control, share, and
/// reproduce security configurations across machines.
/// </summary>
public class SecurityPolicy
{
    /// <summary>Policy format version for forward-compatibility.</summary>
    public int Version { get; set; } = 1;

    /// <summary>Human-readable name for this policy (e.g. "Acme Corp Standard").</summary>
    public string Name { get; set; } = "";

    /// <summary>Description of what this policy enforces.</summary>
    public string Description { get; set; } = "";

    /// <summary>Who created this policy.</summary>
    public string Author { get; set; } = "";

    /// <summary>When the policy was created or last modified.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Active compliance profile name (e.g. "enterprise", "home").</summary>
    public string? ComplianceProfile { get; set; }

    /// <summary>Minimum acceptable security score. Scans below this fail policy checks.</summary>
    public int? MinimumScore { get; set; }

    /// <summary>Modules to skip during scans.</summary>
    public List<string> SkippedModules { get; set; } = [];

    /// <summary>Ignore rules bundled with this policy.</summary>
    public List<IgnoreRule> IgnoreRules { get; set; } = [];

    /// <summary>Alert rules bundled with this policy.</summary>
    public List<AlertRuleEngine.AlertRule> AlertRules { get; set; } = [];

    /// <summary>Alert rule groups bundled with this policy.</summary>
    public List<AlertRuleEngine.AlertRuleGroup> AlertRuleGroups { get; set; } = [];

    /// <summary>Arbitrary key-value metadata tags.</summary>
    public Dictionary<string, string> Tags { get; set; } = new();
}

/// <summary>
/// Result of validating a <see cref="SecurityPolicy"/>.
/// </summary>
public class PolicyValidationResult
{
    public bool IsValid => Errors.Count == 0;
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

/// <summary>
/// Result of comparing two policies (current vs file).
/// </summary>
public class PolicyDiffResult
{
    public int IgnoreRulesAdded { get; set; }
    public int IgnoreRulesRemoved { get; set; }
    public int AlertRulesAdded { get; set; }
    public int AlertRulesRemoved { get; set; }
    public int AlertGroupsAdded { get; set; }
    public int AlertGroupsRemoved { get; set; }
    public bool ComplianceProfileChanged { get; set; }
    public string? CurrentProfile { get; set; }
    public string? IncomingProfile { get; set; }
    public bool MinimumScoreChanged { get; set; }
    public int? CurrentMinScore { get; set; }
    public int? IncomingMinScore { get; set; }
    public int SkippedModulesAdded { get; set; }
    public int SkippedModulesRemoved { get; set; }
    public List<string> Details { get; set; } = [];

    public bool HasChanges =>
        IgnoreRulesAdded > 0 || IgnoreRulesRemoved > 0 ||
        AlertRulesAdded > 0 || AlertRulesRemoved > 0 ||
        AlertGroupsAdded > 0 || AlertGroupsRemoved > 0 ||
        ComplianceProfileChanged || MinimumScoreChanged ||
        SkippedModulesAdded > 0 || SkippedModulesRemoved > 0;
}

/// <summary>
/// Result of importing a policy.
/// </summary>
public class PolicyImportResult
{
    public bool Success { get; set; }
    public int IgnoreRulesImported { get; set; }
    public int AlertRulesImported { get; set; }
    public int AlertGroupsImported { get; set; }
    public string? ComplianceProfileSet { get; set; }
    public int SkippedModulesSet { get; set; }
    public List<string> Warnings { get; set; } = [];
    public string? Error { get; set; }
}

/// <summary>
/// Manages security policy export, import, validation, and comparison.
/// Reads the current configuration from IgnoreRuleService,
/// and can write imported policies back.
/// </summary>
public class PolicyManager
{
    private readonly IgnoreRuleService _ignoreService;
    private readonly ComplianceProfileService _complianceService;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public PolicyManager(
        IgnoreRuleService ignoreService,
        ComplianceProfileService complianceService)
    {
        _ignoreService = ignoreService;
        _complianceService = complianceService;
    }

    /// <summary>
    /// Export the current configuration as a <see cref="SecurityPolicy"/>.
    /// </summary>
    public SecurityPolicy Export(string? name = null, string? description = null)
    {
        return new SecurityPolicy
        {
            Name = name ?? Environment.MachineName + " Policy",
            Description = description ?? "Exported from WinSentinel on " + DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm"),
            Author = Environment.UserName,
            CreatedAt = DateTimeOffset.Now,
            IgnoreRules = _ignoreService.GetAllRules().ToList(), // defensive copy — GetAllRules may return cached reference
            AlertRules = AlertRuleEngine.DefaultRules(),
        };
    }

    /// <summary>
    /// Export the current policy to a JSON file.
    /// </summary>
    public string ExportToFile(string filePath, string? name = null, string? description = null)
    {
        var policy = Export(name, description);
        var json = JsonSerializer.Serialize(policy, JsonOpts);
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(filePath, json);
        return filePath;
    }

    /// <summary>
    /// Load a policy from a JSON file.
    /// </summary>
    public static SecurityPolicy LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Policy file not found: {filePath}");

        var json = File.ReadAllText(filePath);
        return JsonSerializer.Deserialize<SecurityPolicy>(json, JsonOpts)
            ?? throw new InvalidOperationException("Failed to deserialize policy file");
    }

    /// <summary>
    /// Serialize a policy to JSON.
    /// </summary>
    public static string Serialize(SecurityPolicy policy)
    {
        return JsonSerializer.Serialize(policy, JsonOpts);
    }

    /// <summary>
    /// Validate a policy for correctness without applying it.
    /// </summary>
    public PolicyValidationResult Validate(SecurityPolicy policy)
    {
        var result = new PolicyValidationResult();

        if (policy.Version < 1)
            result.Errors.Add("Policy version must be >= 1");
        if (policy.Version > 1)
            result.Warnings.Add($"Policy version {policy.Version} is newer than supported (v1). Some fields may be ignored.");

        if (string.IsNullOrWhiteSpace(policy.Name))
            result.Warnings.Add("Policy has no name — consider adding one for identification");

        if (!string.IsNullOrEmpty(policy.ComplianceProfile) &&
            !_complianceService.ProfileExists(policy.ComplianceProfile))
        {
            result.Errors.Add($"Unknown compliance profile: '{policy.ComplianceProfile}'. " +
                $"Available: {string.Join(", ", _complianceService.ProfileNames)}");
        }

        if (policy.MinimumScore.HasValue && (policy.MinimumScore < 0 || policy.MinimumScore > 100))
            result.Errors.Add($"MinimumScore must be 0-100 (got {policy.MinimumScore})");

        for (int i = 0; i < policy.IgnoreRules.Count; i++)
        {
            var rule = policy.IgnoreRules[i];
            if (string.IsNullOrWhiteSpace(rule.Pattern))
                result.Errors.Add($"Ignore rule [{i}] has an empty pattern");

            if (rule.MatchMode == IgnoreMatchMode.Regex)
            {
                try { _ = new System.Text.RegularExpressions.Regex(rule.Pattern); }
                catch (System.Text.RegularExpressions.RegexParseException ex)
                {
                    result.Errors.Add($"Ignore rule [{i}] has invalid regex: {ex.Message}");
                }
            }

            if (rule.IsExpired)
                result.Warnings.Add($"Ignore rule [{i}] '{rule.Pattern}' has expired ({rule.ExpiresAt:yyyy-MM-dd})");
        }

        for (int i = 0; i < policy.AlertRules.Count; i++)
        {
            var rule = policy.AlertRules[i];
            if (string.IsNullOrWhiteSpace(rule.Name))
                result.Warnings.Add($"Alert rule [{i}] has no name");
        }

        return result;
    }

    /// <summary>
    /// Compare a policy file against the current configuration.
    /// </summary>
    public PolicyDiffResult Diff(SecurityPolicy incoming)
    {
        var current = Export();
        var result = new PolicyDiffResult();

        // Compare ignore rules by pattern+module+matchMode
        var currentKeys = current.IgnoreRules
            .Select(r => $"{r.Pattern}|{r.Module ?? ""}|{r.MatchMode}")
            .ToHashSet();
        var incomingKeys = incoming.IgnoreRules
            .Select(r => $"{r.Pattern}|{r.Module ?? ""}|{r.MatchMode}")
            .ToHashSet();

        foreach (var key in incomingKeys.Except(currentKeys))
            result.Details.Add($"+ Ignore rule: {key.Split('|')[0]}");
        foreach (var key in currentKeys.Except(incomingKeys))
            result.Details.Add($"- Ignore rule: {key.Split('|')[0]}");
        result.IgnoreRulesAdded = incomingKeys.Except(currentKeys).Count();
        result.IgnoreRulesRemoved = currentKeys.Except(incomingKeys).Count();

        // Compare alert rules by name
        var currentAlerts = current.AlertRules.Select(r => r.Name).ToHashSet();
        var incomingAlerts = incoming.AlertRules.Select(r => r.Name).ToHashSet();
        result.AlertRulesAdded = incomingAlerts.Except(currentAlerts).Count();
        result.AlertRulesRemoved = currentAlerts.Except(incomingAlerts).Count();
        foreach (var n in incomingAlerts.Except(currentAlerts))
            result.Details.Add($"+ Alert rule: {n}");
        foreach (var n in currentAlerts.Except(incomingAlerts))
            result.Details.Add($"- Alert rule: {n}");

        // Compare alert groups
        var currentGroups = current.AlertRuleGroups.Select(g => g.Name).ToHashSet();
        var incomingGroups = incoming.AlertRuleGroups.Select(g => g.Name).ToHashSet();
        result.AlertGroupsAdded = incomingGroups.Except(currentGroups).Count();
        result.AlertGroupsRemoved = currentGroups.Except(incomingGroups).Count();

        // Compliance profile
        if (current.ComplianceProfile != incoming.ComplianceProfile)
        {
            result.ComplianceProfileChanged = true;
            result.CurrentProfile = current.ComplianceProfile ?? "(none)";
            result.IncomingProfile = incoming.ComplianceProfile ?? "(none)";
            result.Details.Add($"~ Compliance profile: {result.CurrentProfile} → {result.IncomingProfile}");
        }

        // Minimum score
        if (current.MinimumScore != incoming.MinimumScore)
        {
            result.MinimumScoreChanged = true;
            result.CurrentMinScore = current.MinimumScore;
            result.IncomingMinScore = incoming.MinimumScore;
            result.Details.Add($"~ Min score: {current.MinimumScore?.ToString() ?? "(none)"} → {incoming.MinimumScore?.ToString() ?? "(none)"}");
        }

        // Skipped modules
        var curSkip = current.SkippedModules.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var incSkip = incoming.SkippedModules.ToHashSet(StringComparer.OrdinalIgnoreCase);
        result.SkippedModulesAdded = incSkip.Except(curSkip).Count();
        result.SkippedModulesRemoved = curSkip.Except(incSkip).Count();
        foreach (var m in incSkip.Except(curSkip))
            result.Details.Add($"+ Skipped module: {m}");
        foreach (var m in curSkip.Except(incSkip))
            result.Details.Add($"- Skipped module: {m}");

        return result;
    }

    /// <summary>
    /// Import a policy, replacing current ignore rules.
    /// Alert rules are stored in the policy file and used at scan time.
    /// </summary>
    public PolicyImportResult Import(SecurityPolicy policy, bool force = false)
    {
        var importResult = new PolicyImportResult();

        if (!force)
        {
            var validation = Validate(policy);
            if (!validation.IsValid)
            {
                importResult.Success = false;
                importResult.Error = "Validation failed: " + string.Join("; ", validation.Errors);
                return importResult;
            }
            importResult.Warnings.AddRange(validation.Warnings);
        }

        try
        {
            // Import ignore rules: clear existing, add all from policy
            _ignoreService.ClearAllRules();
            foreach (var rule in policy.IgnoreRules)
            {
                if (!rule.IsExpired)
                {
                    _ignoreService.AddRule(
                        rule.Pattern,
                        rule.MatchMode,
                        rule.Module,
                        rule.Severity,
                        rule.Reason,
                        rule.ExpiresAt);
                    importResult.IgnoreRulesImported++;
                }
            }

            // Alert rules are stateless — stored in the policy file
            importResult.AlertRulesImported = policy.AlertRules.Count;
            importResult.AlertGroupsImported = policy.AlertRuleGroups.Count;

            if (!string.IsNullOrEmpty(policy.ComplianceProfile))
                importResult.ComplianceProfileSet = policy.ComplianceProfile;

            importResult.SkippedModulesSet = policy.SkippedModules.Count;
            importResult.Success = true;
        }
        catch (Exception ex)
        {
            importResult.Success = false;
            importResult.Error = ex.Message;
        }

        return importResult;
    }
}
