namespace WinSentinel.Core.Models;

/// <summary>
/// Result of beacon detection analysis — identifies network connections
/// exhibiting periodic callback patterns typical of C2 communication.
/// </summary>
public class BeaconDetectionReport
{
    public DateTimeOffset AnalysisTimestamp { get; set; } = DateTimeOffset.UtcNow;
    public int ConnectionsAnalyzed { get; set; }
    public int BeaconsDetected { get; set; }
    public int HighConfidenceBeacons { get; set; }
    public int MediumConfidenceBeacons { get; set; }
    public int LowConfidenceBeacons { get; set; }
    public double OverallRiskScore { get; set; }
    public List<BeaconCandidate> Candidates { get; set; } = [];
    public List<BeaconRecommendation> Recommendations { get; set; } = [];
    public BeaconStats Stats { get; set; } = new();
}

/// <summary>
/// A detected beacon candidate — a remote endpoint exhibiting periodic callback behavior.
/// </summary>
public class BeaconCandidate
{
    /// <summary>Remote IP address of the suspected beacon target.</summary>
    public string RemoteIp { get; set; } = "";

    /// <summary>Remote port(s) used.</summary>
    public List<int> RemotePorts { get; set; } = [];

    /// <summary>Process name initiating the connections (if determinable).</summary>
    public string? ProcessName { get; set; }

    /// <summary>Confidence level (0.0 to 1.0).</summary>
    public double Confidence { get; set; }

    /// <summary>Confidence classification.</summary>
    public BeaconConfidence ConfidenceLevel { get; set; }

    /// <summary>Detected beacon interval in seconds.</summary>
    public double IntervalSeconds { get; set; }

    /// <summary>Jitter percentage (lower = more suspicious).</summary>
    public double JitterPercent { get; set; }

    /// <summary>Number of callbacks observed in the analysis window.</summary>
    public int CallbackCount { get; set; }

    /// <summary>Duration of the observation window.</summary>
    public TimeSpan ObservationWindow { get; set; }

    /// <summary>Standard deviation of inter-callback intervals.</summary>
    public double IntervalStdDev { get; set; }

    /// <summary>MITRE ATT&CK technique mapping.</summary>
    public string MitreTechnique { get; set; } = "T1071 — Application Layer Protocol";

    /// <summary>Threat assessment description.</summary>
    public string Assessment { get; set; } = "";

    /// <summary>Suggested remediation action.</summary>
    public string? FixCommand { get; set; }

    /// <summary>Whether this matches known C2 framework timing profiles.</summary>
    public string? MatchedProfile { get; set; }

    /// <summary>Risk score for this individual beacon (0-100).</summary>
    public double RiskScore { get; set; }

    /// <summary>First seen timestamp.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>Last seen timestamp.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Bytes transferred (if available).</summary>
    public long? BytesTransferred { get; set; }
}

/// <summary>Beacon confidence levels.</summary>
public enum BeaconConfidence
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Known C2 framework timing profile for matching.
/// </summary>
public class BeaconProfile
{
    public string Name { get; set; } = "";
    public double TypicalIntervalSeconds { get; set; }
    public double TypicalJitterPercent { get; set; }
    public string Description { get; set; } = "";
}

/// <summary>
/// Remediation recommendation from beacon analysis.
/// </summary>
public class BeaconRecommendation
{
    public int Priority { get; set; }
    public string Action { get; set; } = "";
    public string Rationale { get; set; } = "";
    public string? Command { get; set; }
    public string Impact { get; set; } = "";
}

/// <summary>
/// Statistics from beacon detection analysis.
/// </summary>
public class BeaconStats
{
    public int TotalUniqueEndpoints { get; set; }
    public int EndpointsWithRegularIntervals { get; set; }
    public double MeanInterval { get; set; }
    public double MedianInterval { get; set; }
    public int ShortBeacons { get; set; }  // < 60s interval
    public int MediumBeacons { get; set; } // 60s - 300s
    public int LongBeacons { get; set; }   // > 300s (slow beacons)
    public int ProfileMatches { get; set; }
}
