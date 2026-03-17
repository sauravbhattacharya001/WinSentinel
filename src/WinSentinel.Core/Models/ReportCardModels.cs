using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>
/// A graded report card showing per-module letter grades, GPA,
/// trend indicators, improvements/regressions, and actionable next steps.
/// </summary>
public class ReportCard
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;

    /// <summary>Overall security score (0-100).</summary>
    public int OverallScore { get; set; }

    /// <summary>Overall letter grade (A–F).</summary>
    public string OverallGrade { get; set; } = "";

    /// <summary>Weighted GPA on a 4.0 scale.</summary>
    public double Gpa { get; set; }

    /// <summary>GPA trend arrow: ↑ ↓ → or — (no history).</summary>
    public string GpaTrend { get; set; } = "—";

    /// <summary>Previous GPA (null if no history).</summary>
    public double? PreviousGpa { get; set; }

    /// <summary>Per-module grade cards, ordered by score ascending (worst first).</summary>
    public List<ModuleGrade> Modules { get; set; } = [];

    /// <summary>Modules that improved since last scan.</summary>
    public List<ModuleChange> Improvements { get; set; } = [];

    /// <summary>Modules that regressed since last scan.</summary>
    public List<ModuleChange> Regressions { get; set; } = [];

    /// <summary>Top prioritized next steps to raise the GPA.</summary>
    public List<string> NextSteps { get; set; } = [];

    /// <summary>Total modules graded.</summary>
    public int TotalModules { get; set; }

    /// <summary>Count of modules at each grade.</summary>
    public Dictionary<string, int> GradeDistribution { get; set; } = new();
}

/// <summary>Grade for a single audit module.</summary>
public class ModuleGrade
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public string Grade { get; set; } = "";
    public double GradePoints { get; set; }

    /// <summary>Trend arrow vs previous scan: ↑ ↓ → or — (no history).</summary>
    public string Trend { get; set; } = "—";

    public int? PreviousScore { get; set; }
    public int ScoreChange { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
}

/// <summary>A module that changed between scans.</summary>
public class ModuleChange
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int PreviousScore { get; set; }
    public int CurrentScore { get; set; }
    public int ScoreChange { get; set; }
    public string PreviousGrade { get; set; } = "";
    public string CurrentGrade { get; set; } = "";
}
