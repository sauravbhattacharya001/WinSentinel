namespace WinSentinel.Core.Models;

/// <summary>Full report from discovery detection analysis.</summary>
public class DiscoveryReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int ActivitiesDetected { get; set; }
    public int HighSeverityActivities { get; set; }
    public int MediumSeverityActivities { get; set; }
    public int LowSeverityActivities { get; set; }
    public List<DiscoveryActivity> Activities { get; set; } = new();
    public List<DiscoveryCampaign> Campaigns { get; set; } = new();
    public DiscoveryStats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected discovery activity.</summary>
public class DiscoveryActivity
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetAsset { get; set; }
    public string? DiscoveryCategory { get; set; }
    public string? SourceTool { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? ProcessName { get; set; }
    public DiscoverySeverity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsAutomated { get; set; }
}

/// <summary>Severity classification for discovery events.</summary>
public enum DiscoverySeverity { Low, Medium, High, Critical }

/// <summary>A coordinated discovery campaign with multiple techniques.</summary>
public class DiscoveryCampaign
{
    public List<DiscoveryActivity> Steps { get; set; } = new();
    public string PrimaryCategory { get; set; } = "unknown";
    public string TargetSummary { get; set; } = "unknown";
    public int CategoryCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for discovery analysis.</summary>
public class DiscoveryStats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueAssetsTargeted { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int AutomatedActivities { get; set; }
    public int ManualActivities { get; set; }
    public double ActivityVelocity { get; set; }
    public int DiscoveryCategoriesUsed { get; set; }
}
