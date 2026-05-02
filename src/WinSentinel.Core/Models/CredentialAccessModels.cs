namespace WinSentinel.Core.Models;

/// <summary>Full report from credential access detection analysis.</summary>
public class CredentialAccessReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int AttemptsDetected { get; set; }
    public int HighSeverityAttempts { get; set; }
    public int MediumSeverityAttempts { get; set; }
    public int LowSeverityAttempts { get; set; }
    public List<CredentialAccessAttempt> Attempts { get; set; } = new();
    public List<CredentialHarvestChain> Chains { get; set; } = new();
    public CredAccessStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected credential access attempt.</summary>
public class CredentialAccessAttempt
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? AccountTargeted { get; set; }
    public string? CredentialType { get; set; }
    public string? SourceTool { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public CredAccessSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
}

/// <summary>Severity classification for credential access events.</summary>
public enum CredAccessSeverity { Low, Medium, High, Critical }

/// <summary>A chain of credential harvesting steps leading to broader access.</summary>
public class CredentialHarvestChain
{
    public List<CredentialAccessAttempt> Steps { get; set; } = new();
    public string InitialVector { get; set; } = "unknown";
    public string FinalAccess { get; set; } = "unknown";
    public int StepCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for credential access analysis.</summary>
public class CredAccessStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueAccountsTargeted { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedAttempts { get; set; }
    public int ManualAttempts { get; set; }
    public double AttackVelocity { get; set; }
    public int CredentialTypesTargeted { get; set; }
}
