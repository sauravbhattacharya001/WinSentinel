namespace WinSentinel.Core.Models;

/// <summary>Full report from impact detection analysis.</summary>
public class ImpactReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int ImpactDetectionsCount { get; set; }
    public int HighSeverityImpact { get; set; }
    public int MediumSeverityImpact { get; set; }
    public int LowSeverityImpact { get; set; }
    public List<ImpactEvent> Detections { get; set; } = new();
    public List<ImpactCampaign> Campaigns { get; set; } = new();
    public ImpactStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected impact event.</summary>
public class ImpactEvent
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetAsset { get; set; }
    public string? ImpactType { get; set; }
    public string? KnownTool { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public ImpactSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsDestructive { get; set; }
}

/// <summary>Severity classification for impact events.</summary>
public enum ImpactSeverity { Low, Medium, High, Critical }

/// <summary>A correlated impact campaign with multiple techniques.</summary>
public class ImpactCampaign
{
    public List<ImpactEvent> Events { get; set; } = new();
    public string PrimaryType { get; set; } = "unknown";
    public string TargetSummary { get; set; } = "unknown";
    public int TechniqueCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for impact analysis.</summary>
public class ImpactStats
{
    public int TotalTechniquesUsed { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int DestructiveEvents { get; set; }
    public int NonDestructiveEvents { get; set; }
    public double AttackVelocity { get; set; }
    public int ToolsDetected { get; set; }
}
