namespace WinSentinel.Core.Models;

/// <summary>
/// Represents a single audit run stored in the history database.
/// </summary>
public class AuditRunRecord
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public int OverallScore { get; set; }
    public string Grade { get; set; } = "";
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
    public bool IsScheduled { get; set; }

    public List<ModuleScoreRecord> ModuleScores { get; set; } = [];
    public List<FindingRecord> Findings { get; set; } = [];
}

/// <summary>
/// Score for a single module in a specific audit run.
/// </summary>
public class ModuleScoreRecord
{
    public long Id { get; set; }
    public long RunId { get; set; }
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
}

/// <summary>
/// A single finding stored in the history database.
/// </summary>
public class FindingRecord
{
    public long Id { get; set; }
    public long RunId { get; set; }
    public string ModuleName { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Remediation { get; set; }
}

/// <summary>
/// Represents a score trend data point.
/// </summary>
public class ScoreTrendPoint
{
    public DateTimeOffset Timestamp { get; set; }
    public int Score { get; set; }
    public string Grade { get; set; } = "";
}

/// <summary>
/// Summary of score trends over time.
/// </summary>
public class ScoreTrendSummary
{
    public List<ScoreTrendPoint> Points { get; set; } = [];
    public int CurrentScore { get; set; }
    public int? PreviousScore { get; set; }
    public int ScoreChange => PreviousScore.HasValue ? CurrentScore - PreviousScore.Value : 0;
    public string ChangeDirection => ScoreChange > 0 ? "↑" : ScoreChange < 0 ? "↓" : "→";

    public int? BestScore { get; set; }
    public DateTimeOffset? BestScoreDate { get; set; }
    public string? BestScoreGrade { get; set; }

    public int? WorstScore { get; set; }
    public DateTimeOffset? WorstScoreDate { get; set; }
    public string? WorstScoreGrade { get; set; }

    public int TotalScans { get; set; }
    public double AverageScore { get; set; }
}

/// <summary>
/// Trend info for a single module.
/// </summary>
public class ModuleTrendInfo
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int CurrentScore { get; set; }
    public int? PreviousScore { get; set; }
    public string TrendIndicator => (PreviousScore.HasValue)
        ? (CurrentScore > PreviousScore.Value ? "↑" : CurrentScore < PreviousScore.Value ? "↓" : "→")
        : "—";
    public int ScoreChange => PreviousScore.HasValue ? CurrentScore - PreviousScore.Value : 0;
}
