namespace WinSentinel.Core.Models;

/// <summary>Full report from privilege escalation detection analysis.</summary>
public class PrivilegeEscalationReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int EscalationsDetected { get; set; }
    public int HighSeverityEscalations { get; set; }
    public int MediumSeverityEscalations { get; set; }
    public int LowSeverityEscalations { get; set; }
    public List<PrivilegeEscalation> Escalations { get; set; } = new();
    public List<EscalationChain> Chains { get; set; } = new();
    public PrivEscStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected privilege escalation event.</summary>
public class PrivilegeEscalation
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? AccountUsed { get; set; }
    public string? TargetPrivilege { get; set; }
    public string? SourcePrivilege { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public PrivEscSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
}

/// <summary>Severity classification for privilege escalation events.</summary>
public enum PrivEscSeverity { Low, Medium, High, Critical }

/// <summary>A chain of escalation steps from low to high privilege.</summary>
public class EscalationChain
{
    public List<PrivilegeEscalation> Steps { get; set; } = new();
    public string StartPrivilege { get; set; } = "standard-user";
    public string EndPrivilege { get; set; } = "unknown";
    public int HopCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for privilege escalation analysis.</summary>
public class PrivEscStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueAccountsInvolved { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedAttempts { get; set; }
    public int ManualAttempts { get; set; }
    public double EscalationVelocity { get; set; }
}
