namespace WinSentinel.Core.Models;

/// <summary>
/// MITRE ATT&amp;CK tactic (kill chain phase).
/// </summary>
public enum AttackTactic
{
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
    CommandAndControl,
    ResourceDevelopment,
    Reconnaissance
}

/// <summary>
/// A MITRE ATT&amp;CK technique definition.
/// </summary>
public class AttackTechnique
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required AttackTactic Tactic { get; set; }
    public string? Description { get; set; }
    public string? MitreUrl => $"https://attack.mitre.org/techniques/{Id.Replace('.', '/')}";
}

/// <summary>
/// A mapping rule from finding patterns to ATT&amp;CK techniques.
/// </summary>
public class AttackMappingRule
{
    public required string TechniqueId { get; set; }
    /// <summary>Category patterns (case-insensitive substring match).</summary>
    public List<string> CategoryPatterns { get; set; } = new();
    /// <summary>Title patterns (case-insensitive substring match).</summary>
    public List<string> TitlePatterns { get; set; } = new();
    /// <summary>Description patterns (case-insensitive substring match).</summary>
    public List<string> DescriptionPatterns { get; set; } = new();
}

/// <summary>
/// A finding mapped to an ATT&amp;CK technique.
/// </summary>
public class TechniqueFinding
{
    public required AttackTechnique Technique { get; set; }
    public required Finding Finding { get; set; }
    public required Severity HighestSeverity { get; set; }
}

/// <summary>
/// Per-tactic exposure summary.
/// </summary>
public class TacticExposure
{
    public required AttackTactic Tactic { get; set; }
    public required string TacticName { get; set; }
    public int TechniqueCount { get; set; }
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    /// <summary>Exposure score 0-100 (higher = more exposed).</summary>
    public double ExposureScore { get; set; }
    public string ExposureLevel { get; set; } = "Low";
    public List<TechniqueSummary> Techniques { get; set; } = new();
}

/// <summary>
/// Per-technique summary within a tactic.
/// </summary>
public class TechniqueSummary
{
    public required string TechniqueId { get; set; }
    public required string TechniqueName { get; set; }
    public Severity HighestSeverity { get; set; }
    public int FindingCount { get; set; }
    public string? MitreUrl { get; set; }
}

/// <summary>
/// Full MITRE ATT&amp;CK mapping report.
/// </summary>
public class AttackReport
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public int TotalFindings { get; set; }
    public int MappedFindings { get; set; }
    public int UnmappedFindings { get; set; }
    public double CoveragePercent { get; set; }
    public int TechniquesExposed { get; set; }
    public int TacticsExposed { get; set; }
    public double OverallExposureScore { get; set; }
    public string OverallExposureLevel { get; set; } = "Low";
    public List<TacticExposure> TacticExposures { get; set; } = new();
    public List<TechniqueSummary> TopTechniques { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    /// <summary>Kill chain coverage: which tactics have critical/warning findings.</summary>
    public Dictionary<string, string> KillChainHeatmap { get; set; } = new();
}
