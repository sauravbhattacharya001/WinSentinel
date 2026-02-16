using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Defines what action the agent should take for a given threat.
/// </summary>
public enum ResponseAction
{
    /// <summary>Silently record — no user notification.</summary>
    Log = 0,

    /// <summary>Notify user via IPC + toast notification, suggest fix.</summary>
    Alert = 1,

    /// <summary>Require immediate user attention (popup + sound).</summary>
    Escalate = 2,

    /// <summary>Automatically remediate (kill process, quarantine file, block IP, etc.).</summary>
    AutoFix = 3
}

/// <summary>
/// Threat categories that map to source modules.
/// </summary>
public enum ThreatCategory
{
    Process,
    File,
    Network,
    EventLog,
    Correlation,
    Unknown
}

/// <summary>
/// A single response policy rule.
/// </summary>
public class PolicyRule
{
    /// <summary>Optional: only applies to this threat category. Null = all categories.</summary>
    public ThreatCategory? Category { get; set; }

    /// <summary>Optional: only applies to this severity. Null = all severities.</summary>
    public ThreatSeverity? Severity { get; set; }

    /// <summary>Optional: match threat title pattern (case-insensitive contains).</summary>
    public string? TitlePattern { get; set; }

    /// <summary>The response action to take.</summary>
    public ResponseAction Action { get; set; }

    /// <summary>Whether auto-fix is allowed even if Action=AutoFix (safety gate).</summary>
    public bool AllowAutoFix { get; set; } = true;

    /// <summary>Priority: higher priority rules override lower ones. Default rules are 0.</summary>
    public int Priority { get; set; }
}

/// <summary>
/// User override for a specific threat type.
/// </summary>
public class UserOverride
{
    /// <summary>The threat title (exact match) this override applies to.</summary>
    public string ThreatTitle { get; set; } = "";

    /// <summary>Optional: only match this source module.</summary>
    public string? Source { get; set; }

    /// <summary>The override action.</summary>
    public UserOverrideAction OverrideAction { get; set; }

    /// <summary>When this override was created.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// What the user chose for an override.
/// </summary>
public enum UserOverrideAction
{
    /// <summary>Always ignore this threat type (suppress alerts).</summary>
    AlwaysIgnore,

    /// <summary>Always auto-fix this threat type.</summary>
    AlwaysAutoFix,

    /// <summary>Always alert (never auto-fix, never ignore).</summary>
    AlwaysAlert
}

/// <summary>
/// The result of evaluating a threat against the policy system.
/// </summary>
public class PolicyDecision
{
    /// <summary>What action to take.</summary>
    public ResponseAction Action { get; set; }

    /// <summary>Whether auto-fix is permitted for this threat.</summary>
    public bool AutoFixAllowed { get; set; }

    /// <summary>Which rule matched (for logging/debugging).</summary>
    public string MatchedRule { get; set; } = "";

    /// <summary>Whether a user override was applied.</summary>
    public bool UserOverrideApplied { get; set; }
}

/// <summary>
/// Configurable response policy system.
/// Evaluates threats against rules and user overrides to determine the appropriate response.
/// Persisted as JSON in %LocalAppData%/WinSentinel/response-policy.json.
/// </summary>
public class ResponsePolicy
{
    /// <summary>Custom policy rules (evaluated in priority order).</summary>
    public List<PolicyRule> Rules { get; set; } = new();

    /// <summary>User overrides for specific threat types.</summary>
    public List<UserOverride> UserOverrides { get; set; } = new();

    /// <summary>Global risk tolerance override. When set, adjusts default behavior.</summary>
    public RiskTolerance RiskTolerance { get; set; } = RiskTolerance.Medium;

    // ── Persistence ──

    private static readonly string ConfigDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly string PolicyPath =
        Path.Combine(ConfigDir, "response-policy.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Evaluate a threat event against the policy rules and return a decision.
    /// </summary>
    public PolicyDecision Evaluate(ThreatEvent threat)
    {
        var category = ClassifyCategory(threat.Source);

        // 1. Check user overrides first (highest priority)
        var userOverride = FindUserOverride(threat);
        if (userOverride != null)
        {
            return new PolicyDecision
            {
                Action = userOverride.OverrideAction switch
                {
                    UserOverrideAction.AlwaysIgnore => ResponseAction.Log,
                    UserOverrideAction.AlwaysAutoFix => ResponseAction.AutoFix,
                    UserOverrideAction.AlwaysAlert => ResponseAction.Alert,
                    _ => ResponseAction.Log
                },
                AutoFixAllowed = userOverride.OverrideAction == UserOverrideAction.AlwaysAutoFix,
                MatchedRule = $"UserOverride: {userOverride.OverrideAction} for '{userOverride.ThreatTitle}'",
                UserOverrideApplied = true
            };
        }

        // 2. Check custom rules (sorted by priority descending)
        var matchingRule = Rules
            .OrderByDescending(r => r.Priority)
            .FirstOrDefault(r => RuleMatches(r, threat, category));

        if (matchingRule != null)
        {
            return new PolicyDecision
            {
                Action = matchingRule.Action,
                AutoFixAllowed = matchingRule.AllowAutoFix && threat.AutoFixable,
                MatchedRule = $"CustomRule: {matchingRule.Action} (priority {matchingRule.Priority})"
            };
        }

        // 3. Fall back to default severity-based policy
        return GetDefaultDecision(threat, category);
    }

    /// <summary>
    /// Add a user override for a specific threat type.
    /// </summary>
    public void AddUserOverride(string threatTitle, UserOverrideAction action, string? source = null)
    {
        // Remove any existing override for this title+source
        UserOverrides.RemoveAll(o =>
            o.ThreatTitle.Equals(threatTitle, StringComparison.OrdinalIgnoreCase) &&
            (o.Source == null && source == null || o.Source?.Equals(source, StringComparison.OrdinalIgnoreCase) == true));

        UserOverrides.Add(new UserOverride
        {
            ThreatTitle = threatTitle,
            Source = source,
            OverrideAction = action,
            CreatedAt = DateTimeOffset.UtcNow
        });

        Save();
    }

    /// <summary>
    /// Remove a user override.
    /// </summary>
    public bool RemoveUserOverride(string threatTitle, string? source = null)
    {
        var removed = UserOverrides.RemoveAll(o =>
            o.ThreatTitle.Equals(threatTitle, StringComparison.OrdinalIgnoreCase) &&
            (source == null || o.Source?.Equals(source, StringComparison.OrdinalIgnoreCase) == true));

        if (removed > 0) Save();
        return removed > 0;
    }

    /// <summary>
    /// Get default policy decision based on severity and risk tolerance.
    /// </summary>
    internal PolicyDecision GetDefaultDecision(ThreatEvent threat, ThreatCategory category)
    {
        var action = (threat.Severity, RiskTolerance) switch
        {
            // Critical threats
            (ThreatSeverity.Critical, RiskTolerance.Low) => ResponseAction.AutoFix,
            (ThreatSeverity.Critical, RiskTolerance.Medium) => ResponseAction.Alert,
            (ThreatSeverity.Critical, RiskTolerance.High) => ResponseAction.Alert,

            // High threats
            (ThreatSeverity.High, RiskTolerance.Low) => ResponseAction.Alert,
            (ThreatSeverity.High, RiskTolerance.Medium) => ResponseAction.Alert,
            (ThreatSeverity.High, RiskTolerance.High) => ResponseAction.Log,

            // Medium threats
            (ThreatSeverity.Medium, _) => ResponseAction.Log,

            // Low/Info threats
            (ThreatSeverity.Low, _) => ResponseAction.Log,
            (ThreatSeverity.Info, _) => ResponseAction.Log,

            _ => ResponseAction.Log
        };

        return new PolicyDecision
        {
            Action = action,
            AutoFixAllowed = action == ResponseAction.AutoFix && threat.AutoFixable,
            MatchedRule = $"Default: severity={threat.Severity}, risk={RiskTolerance}"
        };
    }

    /// <summary>
    /// Classify a threat source into a category.
    /// </summary>
    public static ThreatCategory ClassifyCategory(string source)
    {
        if (string.IsNullOrEmpty(source)) return ThreatCategory.Unknown;

        return source.ToLowerInvariant() switch
        {
            "processmonitor" => ThreatCategory.Process,
            "filesystemmonitor" => ThreatCategory.File,
            "eventlogmonitor" => ThreatCategory.EventLog,
            "threatcorrelator" or "correlation" => ThreatCategory.Correlation,
            _ when source.Contains("network", StringComparison.OrdinalIgnoreCase) => ThreatCategory.Network,
            _ => ThreatCategory.Unknown
        };
    }

    private UserOverride? FindUserOverride(ThreatEvent threat)
    {
        return UserOverrides.FirstOrDefault(o =>
            o.ThreatTitle.Equals(threat.Title, StringComparison.OrdinalIgnoreCase) &&
            (o.Source == null || o.Source.Equals(threat.Source, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool RuleMatches(PolicyRule rule, ThreatEvent threat, ThreatCategory category)
    {
        if (rule.Category.HasValue && rule.Category.Value != category)
            return false;

        if (rule.Severity.HasValue && rule.Severity.Value != threat.Severity)
            return false;

        if (!string.IsNullOrEmpty(rule.TitlePattern) &&
            !threat.Title.Contains(rule.TitlePattern, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    // ── Persistence ──

    /// <summary>Load policy from disk or create defaults.</summary>
    public void Load()
    {
        try
        {
            if (File.Exists(PolicyPath))
            {
                var json = File.ReadAllText(PolicyPath);
                var loaded = JsonSerializer.Deserialize<ResponsePolicy>(json, JsonOptions);
                if (loaded != null)
                {
                    Rules = loaded.Rules;
                    UserOverrides = loaded.UserOverrides;
                    RiskTolerance = loaded.RiskTolerance;
                }
            }
        }
        catch
        {
            // Use defaults on failure
        }
    }

    /// <summary>Save current policy to disk.</summary>
    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(PolicyPath, json);
        }
        catch
        {
            // Best-effort save
        }
    }

    /// <summary>
    /// Create a policy with sensible default rules.
    /// </summary>
    public static ResponsePolicy CreateDefault(RiskTolerance riskTolerance = RiskTolerance.Medium)
    {
        var policy = new ResponsePolicy { RiskTolerance = riskTolerance };

        // Correlation-detected threats are always elevated
        policy.Rules.Add(new PolicyRule
        {
            Category = ThreatCategory.Correlation,
            Action = ResponseAction.Escalate,
            Priority = 100
        });

        // Audit log cleared is always critical
        policy.Rules.Add(new PolicyRule
        {
            TitlePattern = "Audit Log Cleared",
            Action = ResponseAction.Escalate,
            Priority = 90
        });

        // Defender disabled is always critical
        policy.Rules.Add(new PolicyRule
        {
            TitlePattern = "Defender Real-Time Protection Disabled",
            Action = ResponseAction.Escalate,
            AllowAutoFix = true,
            Priority = 90
        });

        return policy;
    }
}
