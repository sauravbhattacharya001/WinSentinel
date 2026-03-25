namespace WinSentinel.Core.Models;

/// <summary>
/// Result of noise analysis — identifies the noisiest finding sources
/// across audit history to help users tune their configuration.
/// </summary>
public class NoiseAnalysisResult
{
    public int RunsAnalyzed { get; set; }
    public int DaysSpan { get; set; }
    public int TotalFindingOccurrences { get; set; }
    public int UniqueFindingTitles { get; set; }
    public List<NoisyFinding> TopNoisyFindings { get; set; } = [];
    public List<NoisyModule> TopNoisyModules { get; set; } = [];
    public NoiseStats Stats { get; set; } = new();
}

/// <summary>
/// A finding title that appears frequently across scans.
/// </summary>
public class NoisyFinding
{
    public string Title { get; set; } = "";
    public string ModuleName { get; set; } = "";
    public string Severity { get; set; } = "";
    public int Occurrences { get; set; }
    public double OccurrenceRate { get; set; } // percentage of scans containing this finding
    public bool IsPerennial { get; set; } // appears in every single scan
    public string? SuggestedAction { get; set; }
}

/// <summary>
/// A module that generates the most findings across scans.
/// </summary>
public class NoisyModule
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int TotalFindings { get; set; }
    public double AvgFindingsPerScan { get; set; }
    public int UniqueFindingTitles { get; set; }
    public double NoiseShare { get; set; } // percentage of all findings from this module
}

/// <summary>
/// Aggregate noise statistics.
/// </summary>
public class NoiseStats
{
    public int PerennialFindings { get; set; } // findings that appear in 100% of scans
    public int HighFrequencyFindings { get; set; } // appear in >80% of scans
    public int LowFrequencyFindings { get; set; } // appear in <20% of scans
    public double AvgFindingsPerScan { get; set; }
    public int EstimatedSuppressibleFindings { get; set; } // perennial + high-frequency info-level
    public string NoiseLevelRating { get; set; } = ""; // Low / Moderate / High / Excessive
}
