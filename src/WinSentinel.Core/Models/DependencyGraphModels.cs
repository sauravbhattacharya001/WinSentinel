namespace WinSentinel.Core.Models;

/// <summary>
/// Result of finding dependency/cascade analysis.
/// </summary>
public class FindingDependencyResult
{
    /// <summary>Total findings analyzed.</summary>
    public int TotalFindings { get; set; }

    /// <summary>Number of root findings (no upstream dependencies).</summary>
    public int RootFindings { get; set; }

    /// <summary>Number of dependent findings (would be resolved by fixing a root).</summary>
    public int DependentFindings { get; set; }

    /// <summary>Maximum cascade depth found.</summary>
    public int MaxCascadeDepth { get; set; }

    /// <summary>Findings grouped into dependency clusters.</summary>
    public List<DependencyCluster> Clusters { get; set; } = new();

    /// <summary>Top root findings ranked by cascade impact.</summary>
    public List<CascadeImpact> TopCascadeImpacts { get; set; } = new();

    /// <summary>Estimated findings that would auto-resolve if all roots are fixed.</summary>
    public int EstimatedAutoResolve { get; set; }
}

/// <summary>
/// A cluster of related findings with a root cause.
/// </summary>
public class DependencyCluster
{
    /// <summary>Cluster identifier.</summary>
    public int ClusterId { get; set; }

    /// <summary>Root finding title.</summary>
    public string RootTitle { get; set; } = string.Empty;

    /// <summary>Root finding module.</summary>
    public string RootModule { get; set; } = string.Empty;

    /// <summary>Root finding severity.</summary>
    public Severity RootSeverity { get; set; }

    /// <summary>Dependent findings in this cluster.</summary>
    public List<DependentFinding> Dependents { get; set; } = new();

    /// <summary>Total cascade impact (number of findings resolved by fixing root).</summary>
    public int CascadeCount => Dependents.Count;

    /// <summary>Relationship type that links the cluster.</summary>
    public string RelationshipType { get; set; } = string.Empty;
}

/// <summary>
/// A finding that depends on (would be resolved by) another finding.
/// </summary>
public class DependentFinding
{
    /// <summary>Finding title.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Module that reported this finding.</summary>
    public string Module { get; set; } = string.Empty;

    /// <summary>Severity level.</summary>
    public Severity Severity { get; set; }

    /// <summary>Why this finding depends on the root.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>Cascade depth (1 = direct, 2+ = transitive).</summary>
    public int Depth { get; set; } = 1;
}

/// <summary>
/// Root finding ranked by its cascade impact.
/// </summary>
public class CascadeImpact
{
    /// <summary>Root finding title.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Module that reported this finding.</summary>
    public string Module { get; set; } = string.Empty;

    /// <summary>Severity level.</summary>
    public Severity Severity { get; set; }

    /// <summary>Number of findings that would be resolved by fixing this.</summary>
    public int CascadeCount { get; set; }

    /// <summary>Category of the finding.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Whether a FixCommand is available.</summary>
    public bool HasAutoFix { get; set; }

    /// <summary>Score impact estimate (points gained by fixing this cluster).</summary>
    public double ScoreImpact { get; set; }
}
