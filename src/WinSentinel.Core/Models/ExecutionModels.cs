namespace WinSentinel.Core.Models;

/// <summary>Full report from execution detection analysis.</summary>
public class ExecutionReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int ExecutionsDetected { get; set; }
    public int HighSeverityExecutions { get; set; }
    public int MediumSeverityExecutions { get; set; }
    public int LowSeverityExecutions { get; set; }
    public List<ExecutionEvent> Executions { get; set; } = new();
    public List<ExecutionCampaign> Campaigns { get; set; } = new();
    public ExecutionStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected execution event.</summary>
public class ExecutionEvent
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetAsset { get; set; }
    public string? ExecutionMethod { get; set; }
    public string? SourceTool { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public ExecutionSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
}

/// <summary>Severity classification for execution events.</summary>
public enum ExecutionSeverity { Low, Medium, High, Critical }

/// <summary>A coordinated execution campaign with multiple techniques.</summary>
public class ExecutionCampaign
{
    public List<ExecutionEvent> Steps { get; set; } = new();
    public string PrimaryMethod { get; set; } = "unknown";
    public string TargetSummary { get; set; } = "unknown";
    public int MethodCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for execution analysis.</summary>
public class ExecutionStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueAssetsTargeted { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedExecutions { get; set; }
    public int ManualExecutions { get; set; }
    public double ExecutionVelocity { get; set; }
    public int ExecutionMethodsUsed { get; set; }
}
