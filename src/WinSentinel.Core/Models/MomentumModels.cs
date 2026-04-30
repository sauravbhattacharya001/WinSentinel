namespace WinSentinel.Core.Models;

/// <summary>Momentum analysis phases describing security posture trajectory.</summary>
public enum MomentumPhase
{
    /// <summary>Not enough data points to analyze.</summary>
    InsufficientData,
    /// <summary>Score rising with increasing velocity.</summary>
    Surging,
    /// <summary>Score rising with positive acceleration.</summary>
    Accelerating,
    /// <summary>Score rising at steady rate.</summary>
    Cruising,
    /// <summary>Near-zero velocity — no meaningful change.</summary>
    Stalled,
    /// <summary>Score appears stable but hidden risks are growing.</summary>
    FalsePlateau,
    /// <summary>Positive velocity but slowing down.</summary>
    Decelerating,
    /// <summary>Score is declining.</summary>
    Regressing,
    /// <summary>Rapid decline with negative acceleration.</summary>
    FreeFall
}

/// <summary>A single data point in the posture time series.</summary>
public class PostureDataPoint
{
    public DateTimeOffset Timestamp { get; set; }
    public int Score { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int TotalFindings { get; set; }
}

/// <summary>Kinematic state of the security posture.</summary>
public class KinematicState
{
    /// <summary>Current score (position).</summary>
    public int Position { get; set; }
    /// <summary>Weighted velocity in points/day.</summary>
    public double Velocity { get; set; }
    /// <summary>Recent velocity (last 3 intervals).</summary>
    public double RecentVelocity { get; set; }
    /// <summary>Change in velocity over time.</summary>
    public double Acceleration { get; set; }
    /// <summary>Change in acceleration (3rd derivative).</summary>
    public double Jerk { get; set; }
    /// <summary>Score variance (stability indicator).</summary>
    public double Variance { get; set; }
    /// <summary>Linear regression slope of score over time.</summary>
    public double TrendSlope { get; set; }
    /// <summary>Trend slope of critical findings (positive = growing risk).</summary>
    public double RiskMomentum { get; set; }
}

/// <summary>Detected momentum pattern.</summary>
public class MomentumPattern
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Severity { get; set; } = "";
    public int Occurrences { get; set; }
    public string Emoji { get; set; } = "";
}

/// <summary>Per-module momentum information.</summary>
public class ModuleMomentumInfo
{
    public string ModuleName { get; set; } = "";
    public int CurrentScore { get; set; }
    public double Velocity { get; set; }
    public double RecentVelocity { get; set; }
    public string Direction { get; set; } = "";
    public int DataPoints { get; set; }
}

/// <summary>Recommended intervention based on momentum analysis.</summary>
public class MomentumIntervention
{
    public string Priority { get; set; } = "";
    public string Action { get; set; } = "";
    public string Rationale { get; set; } = "";
    public List<string> Steps { get; set; } = [];
    public string ExpectedImpact { get; set; } = "";
}

/// <summary>Complete momentum analysis report.</summary>
public class MomentumReport
{
    public int AnalyzedDays { get; set; }
    public int DataPointCount { get; set; }
    public DateTimeOffset AnalyzedAt { get; set; }
    public MomentumPhase Phase { get; set; }
    public int MomentumScore { get; set; }
    public string Summary { get; set; } = "";
    public KinematicState Kinematics { get; set; } = new();
    public List<MomentumPattern> Patterns { get; set; } = [];
    public List<ModuleMomentumInfo> ModuleMomentum { get; set; } = [];
    public List<MomentumIntervention> Interventions { get; set; } = [];
}
