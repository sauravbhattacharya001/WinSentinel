namespace WinSentinel.Core.Models;

/// <summary>Full report from command-and-control detection analysis.</summary>
public class CommandControlReport
{
    public int DaysAnalyzed { get; set; }
    public int EventsProcessed { get; set; }
    public int C2DetectionsCount { get; set; }
    public int HighSeverityC2 { get; set; }
    public int MediumSeverityC2 { get; set; }
    public int LowSeverityC2 { get; set; }
    public List<C2Event> Detections { get; set; } = new();
    public List<C2Campaign> Campaigns { get; set; } = new();
    public C2Stats Stats { get; set; } = new();
    public int ThreatScore { get; set; }
    public string ThreatLevel { get; set; } = "Minimal";
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>A single detected C2 communication event.</summary>
public class C2Event
{
    public string Technique { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string? TargetAsset { get; set; }
    public string? ChannelType { get; set; }
    public string? KnownFramework { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public double Confidence { get; set; }
    public string Evidence { get; set; } = "";
    public string? Protocol { get; set; }
    public C2Severity Severity { get; set; }
    public List<string> Indicators { get; set; } = new();
    public bool IsEncrypted { get; set; }
}

/// <summary>Severity classification for C2 events.</summary>
public enum C2Severity { Low, Medium, High, Critical }

/// <summary>A correlated C2 campaign with multiple channels.</summary>
public class C2Campaign
{
    public List<C2Event> Channels { get; set; } = new();
    public string PrimaryProtocol { get; set; } = "unknown";
    public string TargetSummary { get; set; } = "unknown";
    public int ChannelCount { get; set; }
    public double CompoundConfidence { get; set; }
    public TimeSpan Duration { get; set; }
    public string Verdict { get; set; } = "";
}

/// <summary>Aggregate statistics for C2 analysis.</summary>
public class C2Stats
{
    public int TotalTechniquesUsed { get; set; }
    public int UniqueProtocols { get; set; }
    public string MostCommonTechnique { get; set; } = "None";
    public double AverageConfidence { get; set; }
    public int EncryptedChannels { get; set; }
    public int ClearTextChannels { get; set; }
    public double C2Velocity { get; set; }
    public int FrameworksDetected { get; set; }
}
