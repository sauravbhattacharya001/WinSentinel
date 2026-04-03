using WinSentinel.Core.Models;

namespace WinSentinel.Cli;

/// <summary>
/// A cluster of similar security findings grouped by shared characteristics
/// (e.g., root cause, category, or textual similarity).
/// </summary>
public record FindingCluster
{
    /// <summary>Descriptive label for this cluster.</summary>
    public string Label { get; set; } = "";

    /// <summary>Findings in this cluster, each paired with its source module name.</summary>
    public List<(string Module, Finding Finding)> Items { get; set; } = [];

    /// <summary>Distinct modules contributing findings to this cluster.</summary>
    public List<string> Modules { get; set; } = [];

    /// <summary>Highest severity among all findings in the cluster.</summary>
    public Severity HighestSeverity { get; set; }
}
