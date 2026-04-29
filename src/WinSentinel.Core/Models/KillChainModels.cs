namespace WinSentinel.Core.Models;

/// <summary>
/// Kill Chain Reconstructor report — maps security findings to MITRE ATT&amp;CK
/// kill chain phases, detects active attack progressions, and predicts next phases.
/// </summary>
public sealed class KillChainReport
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Overall threat level: None, Low, Moderate, High, Critical.</summary>
    public string ThreatLevel { get; set; } = "None";

    /// <summary>Composite kill chain coverage score (0-100). Higher = more phases active.</summary>
    public int CoverageScore { get; set; }

    /// <summary>Number of kill chain phases with active findings.</summary>
    public int ActivePhaseCount { get; set; }

    /// <summary>Total number of findings mapped to kill chain phases.</summary>
    public int MappedFindingCount { get; set; }

    /// <summary>Findings that could not be mapped to any kill chain phase.</summary>
    public int UnmappedFindingCount { get; set; }

    /// <summary>Detected attack progressions (multi-phase sequences).</summary>
    public List<AttackProgression> Progressions { get; set; } = [];

    /// <summary>Per-phase breakdown.</summary>
    public List<KillChainPhaseResult> Phases { get; set; } = [];

    /// <summary>Predicted next phases based on current state.</summary>
    public List<PhasePrediction> Predictions { get; set; } = [];

    /// <summary>Prioritized response actions.</summary>
    public List<ResponseAction> ResponsePlan { get; set; } = [];

    /// <summary>Summary narrative describing the current attack state.</summary>
    public string Narrative { get; set; } = "";
}

/// <summary>
/// A single kill chain phase and its associated findings.
/// </summary>
public sealed class KillChainPhaseResult
{
    /// <summary>Phase name (e.g., "Initial Access", "Persistence").</summary>
    public string Phase { get; set; } = "";

    /// <summary>Phase index (0-12) for ordering.</summary>
    public int PhaseIndex { get; set; }

    /// <summary>MITRE ATT&amp;CK Tactic ID (e.g., TA0001).</summary>
    public string TacticId { get; set; } = "";

    /// <summary>Whether this phase has active findings.</summary>
    public bool IsActive { get; set; }

    /// <summary>Number of findings mapped to this phase.</summary>
    public int FindingCount { get; set; }

    /// <summary>Maximum severity of findings in this phase.</summary>
    public string MaxSeverity { get; set; } = "None";

    /// <summary>MITRE techniques observed in this phase.</summary>
    public List<string> ObservedTechniques { get; set; } = [];

    /// <summary>Finding titles in this phase.</summary>
    public List<string> FindingTitles { get; set; } = [];
}

/// <summary>
/// A detected multi-phase attack progression.
/// </summary>
public sealed class AttackProgression
{
    /// <summary>Human-readable name for this attack pattern.</summary>
    public string Name { get; set; } = "";

    /// <summary>Description of the attack progression.</summary>
    public string Description { get; set; } = "";

    /// <summary>Kill chain phases involved (ordered).</summary>
    public List<string> Phases { get; set; } = [];

    /// <summary>Confidence score (0-100).</summary>
    public int Confidence { get; set; }

    /// <summary>MITRE ATT&amp;CK techniques involved.</summary>
    public List<string> Techniques { get; set; } = [];

    /// <summary>Severity classification: Low, Medium, High, Critical.</summary>
    public string Severity { get; set; } = "Low";
}

/// <summary>
/// Prediction for a kill chain phase that hasn't been observed yet but is likely next.
/// </summary>
public sealed class PhasePrediction
{
    /// <summary>Predicted phase name.</summary>
    public string Phase { get; set; } = "";

    /// <summary>Probability (0-100) that this phase will become active.</summary>
    public int Probability { get; set; }

    /// <summary>Reasoning for the prediction.</summary>
    public string Rationale { get; set; } = "";

    /// <summary>Typical techniques used in this phase.</summary>
    public List<string> LikelyTechniques { get; set; } = [];

    /// <summary>Preventive actions to block this phase.</summary>
    public List<string> PreventiveActions { get; set; } = [];
}

/// <summary>
/// A prioritized response action.
/// </summary>
public sealed class ResponseAction
{
    /// <summary>Priority rank (1 = highest).</summary>
    public int Priority { get; set; }

    /// <summary>Action to take.</summary>
    public string Action { get; set; } = "";

    /// <summary>Phase this action addresses.</summary>
    public string TargetPhase { get; set; } = "";

    /// <summary>Urgency level.</summary>
    public string Urgency { get; set; } = "Normal";

    /// <summary>Expected impact of taking this action.</summary>
    public string Impact { get; set; } = "";
}
