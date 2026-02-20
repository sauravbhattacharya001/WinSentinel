using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>
/// A compliance profile that customizes severity overrides, scoring weights,
/// and module importance based on the deployment context (Home, Developer, Enterprise, Server).
/// Different environments have different security requirements — a home user doesn't need
/// the same controls as a PCI-DSS enterprise environment.
/// </summary>
public class ComplianceProfile
{
    /// <summary>Profile identifier (e.g., "home", "developer", "enterprise", "server").</summary>
    public required string Name { get; set; }

    /// <summary>Human-readable display name.</summary>
    public required string DisplayName { get; set; }

    /// <summary>Description of what this profile is for.</summary>
    public required string Description { get; set; }

    /// <summary>Target audience for this profile.</summary>
    public string TargetAudience { get; set; } = "";

    /// <summary>
    /// Scoring weight multipliers per module category (0.0 to 2.0).
    /// A weight of 0.0 means the module is ignored, 1.0 is default, 2.0 is double importance.
    /// Keys are module category names (e.g., "Firewall & Network Protection", "Encryption").
    /// </summary>
    public Dictionary<string, double> ModuleWeights { get; set; } = new();

    /// <summary>
    /// Severity overrides for specific finding titles.
    /// Allows downgrading enterprise-only findings to Info for home users,
    /// or upgrading important findings to Critical for enterprise environments.
    /// Key: finding title (case-insensitive match), Value: new severity.
    /// </summary>
    public Dictionary<string, SeverityOverride> SeverityOverrides { get; set; } = new();

    /// <summary>
    /// Module categories to skip entirely for this profile.
    /// E.g., a home user might skip "Event Log" module.
    /// </summary>
    public HashSet<string> SkippedModules { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Minimum score threshold for this profile to be considered "compliant".
    /// E.g., Enterprise might require 85, Home might accept 60.
    /// </summary>
    public int ComplianceThreshold { get; set; } = 70;

    /// <summary>
    /// Additional notes or recommendations specific to this profile.
    /// </summary>
    public List<string> Recommendations { get; set; } = [];
}

/// <summary>
/// Defines a severity override for a specific finding within a compliance profile.
/// </summary>
public class SeverityOverride
{
    /// <summary>The new severity to assign.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity NewSeverity { get; set; }

    /// <summary>Reason for the override (shown to user).</summary>
    public string Reason { get; set; } = "";

    public SeverityOverride() { }

    public SeverityOverride(Severity newSeverity, string reason)
    {
        NewSeverity = newSeverity;
        Reason = reason;
    }
}

/// <summary>
/// Result of applying a compliance profile to an audit report.
/// </summary>
public class ComplianceResult
{
    /// <summary>The profile that was applied.</summary>
    public required ComplianceProfile Profile { get; set; }

    /// <summary>Original security score before profile adjustments.</summary>
    public int OriginalScore { get; set; }

    /// <summary>Adjusted security score after applying profile weights.</summary>
    public int AdjustedScore { get; set; }

    /// <summary>Original grade.</summary>
    public string OriginalGrade { get; set; } = "";

    /// <summary>Adjusted grade.</summary>
    public string AdjustedGrade { get; set; } = "";

    /// <summary>Whether the system meets the profile's compliance threshold.</summary>
    public bool IsCompliant => AdjustedScore >= Profile.ComplianceThreshold;

    /// <summary>Compliance threshold from the profile.</summary>
    public int ComplianceThreshold => Profile.ComplianceThreshold;

    /// <summary>Number of severity overrides that were applied.</summary>
    public int OverridesApplied { get; set; }

    /// <summary>Number of modules skipped by the profile.</summary>
    public int ModulesSkipped { get; set; }

    /// <summary>Number of modules with custom weights.</summary>
    public int ModulesWeighted { get; set; }

    /// <summary>Per-module adjusted scores.</summary>
    public List<ModuleComplianceScore> ModuleScores { get; set; } = [];

    /// <summary>Details of severity overrides that were applied.</summary>
    public List<AppliedOverride> AppliedOverrides { get; set; } = [];

    /// <summary>Profile-specific recommendations.</summary>
    public List<string> Recommendations { get; set; } = [];

    /// <summary>Timestamp of the compliance check.</summary>
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Per-module score within a compliance result.
/// </summary>
public class ModuleComplianceScore
{
    /// <summary>Module category name.</summary>
    public string Category { get; set; } = "";

    /// <summary>Original module score (unweighted).</summary>
    public int OriginalScore { get; set; }

    /// <summary>Weight multiplier applied.</summary>
    public double Weight { get; set; } = 1.0;

    /// <summary>Whether this module was skipped.</summary>
    public bool Skipped { get; set; }

    /// <summary>Number of findings in this module.</summary>
    public int FindingCount { get; set; }

    /// <summary>Number of overrides applied to findings in this module.</summary>
    public int OverridesInModule { get; set; }
}

/// <summary>
/// Record of a severity override that was applied during compliance checking.
/// </summary>
public class AppliedOverride
{
    /// <summary>Finding title that was overridden.</summary>
    public string FindingTitle { get; set; } = "";

    /// <summary>Original severity.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity OriginalSeverity { get; set; }

    /// <summary>New severity after override.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity NewSeverity { get; set; }

    /// <summary>Reason for the override.</summary>
    public string Reason { get; set; } = "";

    /// <summary>Module category the finding belongs to.</summary>
    public string ModuleCategory { get; set; } = "";
}
