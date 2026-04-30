namespace WinSentinel.Core.Models;

/// <summary>Full report from defense evasion detection analysis.</summary>
public class DefenseEvasionReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int EvasionsDetected { get; set; }
    public int CriticalEvasions { get; set; }
    public int HighSeverityEvasions { get; set; }
    public int MediumSeverityEvasions { get; set; }
    public int LowSeverityEvasions { get; set; }
    public List<DefenseEvasionEvent> Evasions { get; set; } = new();
    public List<EvasionCampaign> Campaigns { get; set; } = new();
    public DefenseEvasionStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected defense evasion event.</summary>
public class DefenseEvasionEvent
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetDefense { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public EvasionSeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
    public string EvasionCategory { get; set; } = "";
}

/// <summary>Severity classification for defense evasion events.</summary>
public enum EvasionSeverity { Low, Medium, High, Critical }

/// <summary>A campaign of coordinated evasion techniques used together.</summary>
public class EvasionCampaign
{
    public List<DefenseEvasionEvent> Steps { get; set; } = new();
    public int TechniqueCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
    public string CampaignType { get; set; } = "";
}

/// <summary>Aggregate statistics for defense evasion analysis.</summary>
public class DefenseEvasionStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueDefensesTargeted { get; set; }
    public string MostTargetedDefense { get; set; } = "None";
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedAttempts { get; set; }
    public int ManualAttempts { get; set; }
    public double EvasionVelocity { get; set; }
}
