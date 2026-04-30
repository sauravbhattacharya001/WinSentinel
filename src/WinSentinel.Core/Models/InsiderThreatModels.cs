namespace WinSentinel.Core.Models;

/// <summary>
/// Full insider threat behavioral profiling report.
/// </summary>
public class InsiderThreatReport
{
    /// <summary>When this analysis was generated.</summary>
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Days of behavioral history analyzed.</summary>
    public int DaysAnalyzed { get; set; }

    /// <summary>Total user accounts profiled.</summary>
    public int UsersProfiled { get; set; }

    /// <summary>Total behavioral events processed.</summary>
    public int EventsProcessed { get; set; }

    /// <summary>Individual user risk profiles.</summary>
    public List<UserRiskProfile> Profiles { get; set; } = new();

    /// <summary>Detected insider threat indicators across all users.</summary>
    public List<InsiderThreatIndicator> Indicators { get; set; } = new();

    /// <summary>Overall insider threat posture score (0-100, higher = safer).</summary>
    public int PostureScore { get; set; }

    /// <summary>Risk tier classification.</summary>
    public string RiskTier { get; set; } = "Low";

    /// <summary>Autonomous recommendations.</summary>
    public List<InsiderRecommendation> Recommendations { get; set; } = new();

    /// <summary>Behavioral anomaly timeline.</summary>
    public List<BehavioralAnomaly> AnomalyTimeline { get; set; } = new();

    /// <summary>Summary statistics.</summary>
    public InsiderThreatStats Stats { get; set; } = new();
}

/// <summary>
/// Risk profile for a single user account.
/// </summary>
public class UserRiskProfile
{
    /// <summary>User account name.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Account SID if available.</summary>
    public string? Sid { get; set; }

    /// <summary>Composite risk score (0-100, higher = riskier).</summary>
    public int RiskScore { get; set; }

    /// <summary>Risk classification.</summary>
    public InsiderRiskLevel RiskLevel { get; set; } = InsiderRiskLevel.Low;

    /// <summary>Behavioral baseline summary.</summary>
    public BehavioralBaseline Baseline { get; set; } = new();

    /// <summary>Current behavioral deviations from baseline.</summary>
    public List<BehavioralDeviation> Deviations { get; set; } = new();

    /// <summary>Detected threat patterns for this user.</summary>
    public List<string> ThreatPatterns { get; set; } = new();

    /// <summary>Activity trend direction.</summary>
    public string ActivityTrend { get; set; } = "Stable";

    /// <summary>Days since last normal activity.</summary>
    public int DaysSinceNormalActivity { get; set; }

    /// <summary>Whether this user shows pre-departure behavioral patterns.</summary>
    public bool PreDepartureSignals { get; set; }
}

/// <summary>
/// Behavioral baseline computed from historical activity.
/// </summary>
public class BehavioralBaseline
{
    /// <summary>Typical logon hours (0-23).</summary>
    public List<int> TypicalHours { get; set; } = new();

    /// <summary>Average daily logon count.</summary>
    public double AvgDailyLogons { get; set; }

    /// <summary>Standard deviation of daily logons.</summary>
    public double StdDevDailyLogons { get; set; }

    /// <summary>Average file access operations per day.</summary>
    public double AvgDailyFileOps { get; set; }

    /// <summary>Typical accessed resources/paths.</summary>
    public List<string> TypicalResources { get; set; } = new();

    /// <summary>Average privilege escalation events per week.</summary>
    public double AvgWeeklyPrivEsc { get; set; }

    /// <summary>Typical network destinations.</summary>
    public List<string> TypicalNetworkDests { get; set; } = new();

    /// <summary>Normal working days (0=Sun, 6=Sat).</summary>
    public List<int> WorkingDays { get; set; } = new();

    /// <summary>Baseline computed from this many days of history.</summary>
    public int BaselineDays { get; set; }
}

/// <summary>
/// A single deviation from established behavioral baseline.
/// </summary>
public class BehavioralDeviation
{
    /// <summary>Type of deviation detected.</summary>
    public DeviationType Type { get; set; }

    /// <summary>Human-readable description.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>How far from normal (in standard deviations).</summary>
    public double ZScore { get; set; }

    /// <summary>Severity of this deviation.</summary>
    public Severity Severity { get; set; } = Severity.Info;

    /// <summary>When this deviation was detected.</summary>
    public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Expected value.</summary>
    public string Expected { get; set; } = string.Empty;

    /// <summary>Actual observed value.</summary>
    public string Actual { get; set; } = string.Empty;
}

/// <summary>
/// An insider threat indicator detected across the environment.
/// </summary>
public class InsiderThreatIndicator
{
    /// <summary>Indicator category.</summary>
    public InsiderIndicatorCategory Category { get; set; }

    /// <summary>Affected user account.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Detailed description of the indicator.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Confidence level (0-100).</summary>
    public int Confidence { get; set; }

    /// <summary>MITRE ATT&CK technique if applicable.</summary>
    public string? MitreTechnique { get; set; }

    /// <summary>Evidence supporting this indicator.</summary>
    public List<string> Evidence { get; set; } = new();

    /// <summary>When the indicator was first observed.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>When the indicator was last observed.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Severity level.</summary>
    public Severity Severity { get; set; } = Severity.Warning;
}

/// <summary>
/// An anomaly event in the behavioral timeline.
/// </summary>
public class BehavioralAnomaly
{
    /// <summary>When the anomaly occurred.</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>User involved.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Type of anomaly.</summary>
    public string AnomalyType { get; set; } = string.Empty;

    /// <summary>Description of what happened.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Risk impact score (1-10).</summary>
    public int ImpactScore { get; set; }
}

/// <summary>
/// Autonomous recommendation for insider threat mitigation.
/// </summary>
public class InsiderRecommendation
{
    /// <summary>Priority level (1 = most urgent).</summary>
    public int Priority { get; set; }

    /// <summary>Recommendation text.</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>Rationale for this recommendation.</summary>
    public string Rationale { get; set; } = string.Empty;

    /// <summary>Target user or "All" for environment-wide.</summary>
    public string Target { get; set; } = "All";

    /// <summary>Expected risk reduction if implemented.</summary>
    public string ExpectedImpact { get; set; } = string.Empty;
}

/// <summary>
/// Aggregate statistics for the insider threat report.
/// </summary>
public class InsiderThreatStats
{
    /// <summary>Number of high-risk users.</summary>
    public int HighRiskUsers { get; set; }

    /// <summary>Number of medium-risk users.</summary>
    public int MediumRiskUsers { get; set; }

    /// <summary>Number of low-risk users.</summary>
    public int LowRiskUsers { get; set; }

    /// <summary>Total off-hours activity events detected.</summary>
    public int OffHoursEvents { get; set; }

    /// <summary>Total data exfiltration indicators.</summary>
    public int ExfiltrationIndicators { get; set; }

    /// <summary>Total privilege abuse indicators.</summary>
    public int PrivilegeAbuseIndicators { get; set; }

    /// <summary>Total account anomalies.</summary>
    public int AccountAnomalies { get; set; }

    /// <summary>Users showing pre-departure signals.</summary>
    public int PreDepartureUsers { get; set; }
}

/// <summary>Insider threat risk level classification.</summary>
public enum InsiderRiskLevel
{
    /// <summary>No significant risk indicators.</summary>
    Low,
    /// <summary>Some deviations detected, monitor closely.</summary>
    Medium,
    /// <summary>Multiple threat indicators, investigation recommended.</summary>
    High,
    /// <summary>Active threat indicators, immediate action required.</summary>
    Critical
}

/// <summary>Types of behavioral deviations.</summary>
public enum DeviationType
{
    /// <summary>Activity outside established working hours.</summary>
    OffHoursActivity,
    /// <summary>Significantly more logon events than normal.</summary>
    ExcessiveLogons,
    /// <summary>Accessing resources outside typical patterns.</summary>
    UnusualResourceAccess,
    /// <summary>Spike in file copy/move/delete operations.</summary>
    BulkDataOperations,
    /// <summary>Attempts to access elevated privileges.</summary>
    PrivilegeEscalation,
    /// <summary>Multiple failed authentication attempts.</summary>
    AuthenticationAnomalies,
    /// <summary>Network connections to unusual destinations.</summary>
    UnusualNetworkActivity,
    /// <summary>Activity on non-working days.</summary>
    WeekendActivity,
    /// <summary>Clearing of audit logs or security events.</summary>
    LogTampering,
    /// <summary>Use of removable media or cloud storage.</summary>
    DataStagingActivity
}

/// <summary>Categories of insider threat indicators.</summary>
public enum InsiderIndicatorCategory
{
    /// <summary>Potential data theft or exfiltration.</summary>
    DataExfiltration,
    /// <summary>Privilege abuse or unauthorized access.</summary>
    PrivilegeAbuse,
    /// <summary>Account misuse or sharing.</summary>
    AccountMisuse,
    /// <summary>Sabotage or destructive behavior.</summary>
    Sabotage,
    /// <summary>Policy violations.</summary>
    PolicyViolation,
    /// <summary>Behavioral patterns suggesting planned departure.</summary>
    PreDeparture,
    /// <summary>Attempts to evade security monitoring.</summary>
    Evasion,
    /// <summary>Unauthorized system modifications.</summary>
    SystemTampering
}
