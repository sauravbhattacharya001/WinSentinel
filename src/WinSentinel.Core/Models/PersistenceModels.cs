namespace WinSentinel.Core.Models;

/// <summary>Full report from persistence mechanism scanning (MITRE TA0003).</summary>
public class PersistMechReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int MechanismsDetected { get; set; }
    public int ActiveMechanisms { get; set; }
    public int DormantMechanisms { get; set; }
    public int CriticalMechanisms { get; set; }
    public int HighMechanisms { get; set; }
    public int MediumMechanisms { get; set; }
    public int LowMechanisms { get; set; }
    public List<PersistMechEntry> Entries { get; set; } = new();
    public List<PersistMechChain> Chains { get; set; } = new();
    public PersistMechStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected persistence mechanism.</summary>
public class PersistMechEntry
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string Location { get; set; } = "";
    public string? AssociatedUser { get; set; }
    public string? ProcessName { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public PersistMechSeverity Severity { get; set; }
    public bool IsActive { get; set; }
    public bool IsDormant { get; set; }
    public List<string> Indicators { get; set; } = new();
    public string Category { get; set; } = "";
}

/// <summary>Severity classification for persistence mechanisms.</summary>
public enum PersistMechSeverity { Low, Medium, High, Critical }

/// <summary>A chain of linked persistence mechanisms indicating defense-in-depth.</summary>
public class PersistMechChain
{
    public List<PersistMechEntry> Mechanisms { get; set; } = new();
    public string PrimaryTechnique { get; set; } = "";
    public int Depth { get; set; }
    public double CompoundConfidence { get; set; }
    public string Verdict { get; set; } = "";
    public string DefenseInDepthLevel { get; set; } = "";
}

/// <summary>Aggregate statistics for persistence scanning.</summary>
public class PersistMechStats
{
    public int UniqueTechniquesUsed { get; set; }
    public int UniqueLocations { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public double DormancyRatio { get; set; }
    public int CrossTechniqueChains { get; set; }
    public double TechniqueDiversity { get; set; }
}
