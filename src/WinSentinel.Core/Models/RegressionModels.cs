namespace WinSentinel.Core.Models;

/// <summary>Result from regression prediction analysis.</summary>
public sealed class RegressionReport
{
    public int AnalyzedRuns { get; set; }
    public int AnalyzedDays { get; set; }
    public int TotalRegressionsFound { get; set; }
    public double OverallRegressionRate { get; set; }
    public string RiskLevel { get; set; } = "Low";
    public int RegressionScore { get; set; }
    public List<RegressionFinding> YoYoFindings { get; set; } = [];
    public List<RegressionPrediction> AtRiskFixes { get; set; } = [];
    public List<ModuleRegressionProfile> ModuleProfiles { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>A finding that has regressed (was fixed then returned) multiple times.</summary>
public sealed class RegressionFinding
{
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public string Severity { get; set; } = "";
    public int RegressionCount { get; set; }
    public int TotalAppearances { get; set; }
    public double RegressionRate { get; set; }
    public double AverageFixDuration { get; set; }
    public string Pattern { get; set; } = "";
    public string RootCauseHint { get; set; } = "";
}

/// <summary>A recently-fixed finding with predicted regression probability.</summary>
public sealed class RegressionPrediction
{
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public string Severity { get; set; } = "";
    public double RegressionProbability { get; set; }
    public string Confidence { get; set; } = "";
    public int RunsSinceFix { get; set; }
    public int PastRegressions { get; set; }
    public string RecommendedAction { get; set; } = "";
}

/// <summary>Per-module regression profile.</summary>
public sealed class ModuleRegressionProfile
{
    public string ModuleName { get; set; } = "";
    public int TotalFindings { get; set; }
    public int RegressionCount { get; set; }
    public double RegressionRate { get; set; }
    public string Stability { get; set; } = "";
    public string TopYoYoFinding { get; set; } = "";
}
