namespace WinSentinel.Core.Models;

/// <summary>Full report from initial access detection analysis.</summary>
public class InitialAccessReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int AttemptsDetected { get; set; }
    public int HighSeverityAttempts { get; set; }
    public int MediumSeverityAttempts { get; set; }
    public int LowSeverityAttempts { get; set; }
    public List<InitialAccessAttempt> Attempts { get; set; } = new();
    public List<InitialAccessCampaign> Campaigns { get; set; } = new();
    public InitialAccessStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected initial access attempt.</summary>
public class InitialAccessAttempt
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetAsset { get; set; }
    public string? AccessVector { get; set; }
    public string? SourceTool { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public InitialAccessSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
}

/// <summary>Severity classification for initial access events.</summary>
public enum InitialAccessSeverity { Low, Medium, High, Critical }

/// <summary>A coordinated initial access campaign with multiple vectors.</summary>
public class InitialAccessCampaign
{
    public List<InitialAccessAttempt> Steps { get; set; } = new();
    public string PrimaryVector { get; set; } = "unknown";
    public string TargetSummary { get; set; } = "unknown";
    public int VectorCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for initial access analysis.</summary>
public class InitialAccessStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueAssetsTargeted { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedAttempts { get; set; }
    public int ManualAttempts { get; set; }
    public double AttackVelocity { get; set; }
    public int AccessVectorsUsed { get; set; }
}
