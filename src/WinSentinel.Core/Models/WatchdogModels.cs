namespace WinSentinel.Core.Models;

/// <summary>
/// Models for the Security Anomaly Watchdog — proactive detection of
/// score drops, finding spikes, and module regressions.
/// </summary>

public class WatchdogReport
{
    public DateTimeOffset AnalyzedAt { get; set; } = DateTimeOffset.UtcNow;
    public int RunsAnalyzed { get; set; }
    public int DaysAnalyzed { get; set; }
    public string OverallStatus { get; set; } = "OK"; // OK, WARN, ALERT
    public int TotalAnomalies { get; set; }
    public List<ScoreAnomaly> ScoreAnomalies { get; set; } = [];
    public List<FindingSpike> FindingSpikes { get; set; } = [];
    public List<ModuleRegression> ModuleRegressions { get; set; } = [];
    public WatchdogStats Stats { get; set; } = new();
    public List<string> Recommendations { get; set; } = [];
}

public class WatchdogStats
{
    public double MeanScore { get; set; }
    public double StdDevScore { get; set; }
    public double MeanFindings { get; set; }
    public double StdDevFindings { get; set; }
    public int? LatestScore { get; set; }
    public int? LatestFindings { get; set; }
    public double ScoreZScore { get; set; }
    public double FindingsZScore { get; set; }
}

public class ScoreAnomaly
{
    public DateTimeOffset Timestamp { get; set; }
    public int Score { get; set; }
    public int? PreviousScore { get; set; }
    public int Drop { get; set; }
    public double ZScore { get; set; }
    public string Severity { get; set; } = "Warning"; // Warning, Critical
    public string Reason { get; set; } = "";
}

public class FindingSpike
{
    public DateTimeOffset Timestamp { get; set; }
    public int TotalFindings { get; set; }
    public int? PreviousFindings { get; set; }
    public int Increase { get; set; }
    public double ZScore { get; set; }
    public int CriticalCount { get; set; }
    public string Severity { get; set; } = "Warning";
}

public class ModuleRegression
{
    public string ModuleName { get; set; } = "";
    public int CurrentScore { get; set; }
    public int PreviousScore { get; set; }
    public int ScoreDrop { get; set; }
    public int ConsecutiveDrops { get; set; }
    public string Trend { get; set; } = "Declining"; // Declining, Volatile, Collapsed
}
