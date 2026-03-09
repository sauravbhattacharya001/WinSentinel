namespace WinSentinel.Core.Models;

/// <summary>
/// A single data point in the finding burndown chart.
/// </summary>
public class BurndownDataPoint
{
    /// <summary>Date of the audit run.</summary>
    public DateTimeOffset Date { get; set; }

    /// <summary>Total open findings at this point.</summary>
    public int OpenFindings { get; set; }

    /// <summary>Critical findings open.</summary>
    public int CriticalOpen { get; set; }

    /// <summary>Warning findings open.</summary>
    public int WarningOpen { get; set; }

    /// <summary>Info findings open.</summary>
    public int InfoOpen { get; set; }

    /// <summary>New findings introduced since previous point.</summary>
    public int NewFindings { get; set; }

    /// <summary>Findings resolved since previous point.</summary>
    public int ResolvedFindings { get; set; }

    /// <summary>Net change (negative = improving).</summary>
    public int NetChange => NewFindings - ResolvedFindings;

    /// <summary>Cumulative resolved count.</summary>
    public int CumulativeResolved { get; set; }

    /// <summary>Cumulative introduced count.</summary>
    public int CumulativeIntroduced { get; set; }
}

/// <summary>
/// A sprint-style period aggregating burndown metrics.
/// </summary>
public class BurndownPeriod
{
    /// <summary>Period start date.</summary>
    public DateTimeOffset Start { get; set; }

    /// <summary>Period end date.</summary>
    public DateTimeOffset End { get; set; }

    /// <summary>Label (e.g. "Week 1", "Mar 1-7").</summary>
    public string Label { get; set; } = "";

    /// <summary>Open findings at period start.</summary>
    public int StartCount { get; set; }

    /// <summary>Open findings at period end.</summary>
    public int EndCount { get; set; }

    /// <summary>Total introduced during period.</summary>
    public int Introduced { get; set; }

    /// <summary>Total resolved during period.</summary>
    public int Resolved { get; set; }

    /// <summary>Net change.</summary>
    public int NetChange => Introduced - Resolved;

    /// <summary>Resolution velocity (resolved per day).</summary>
    public double VelocityPerDay { get; set; }

    /// <summary>Number of audit runs in this period.</summary>
    public int RunCount { get; set; }
}

/// <summary>
/// Velocity projection for when findings will reach zero.
/// </summary>
public class BurndownProjection
{
    /// <summary>Average findings resolved per day across the analysis window.</summary>
    public double AvgResolvedPerDay { get; set; }

    /// <summary>Average new findings introduced per day.</summary>
    public double AvgIntroducedPerDay { get; set; }

    /// <summary>Net resolution velocity (positive = improving).</summary>
    public double NetVelocityPerDay { get; set; }

    /// <summary>Estimated date when open findings will reach zero, or null if velocity is non-positive.</summary>
    public DateTimeOffset? ProjectedZeroDate { get; set; }

    /// <summary>Estimated days to reach zero open findings, or null if velocity is non-positive.</summary>
    public int? DaysToZero { get; set; }

    /// <summary>Current open findings count.</summary>
    public int CurrentOpen { get; set; }

    /// <summary>Confidence level based on data consistency (0-100).</summary>
    public int ConfidencePercent { get; set; }

    /// <summary>Human-readable projection summary.</summary>
    public string Summary { get; set; } = "";
}

/// <summary>
/// Per-severity burndown breakdown.
/// </summary>
public class SeverityBurndown
{
    /// <summary>Severity level.</summary>
    public string Severity { get; set; } = "";

    /// <summary>Current open count.</summary>
    public int CurrentOpen { get; set; }

    /// <summary>Peak open count during window.</summary>
    public int PeakOpen { get; set; }

    /// <summary>Total resolved during window.</summary>
    public int TotalResolved { get; set; }

    /// <summary>Total introduced during window.</summary>
    public int TotalIntroduced { get; set; }

    /// <summary>Average days to resolve findings of this severity.</summary>
    public double AvgDaysToResolve { get; set; }
}

/// <summary>
/// Complete burndown report.
/// </summary>
public class BurndownReport
{
    /// <summary>Burndown data points (one per audit run).</summary>
    public List<BurndownDataPoint> DataPoints { get; set; } = [];

    /// <summary>Sprint-style period summaries.</summary>
    public List<BurndownPeriod> Periods { get; set; } = [];

    /// <summary>Zero-date projection.</summary>
    public BurndownProjection Projection { get; set; } = new();

    /// <summary>Per-severity breakdown.</summary>
    public List<SeverityBurndown> SeverityBreakdown { get; set; } = [];

    /// <summary>Overall performance grade (A+ through F).</summary>
    public string Grade { get; set; } = "N/A";

    /// <summary>Grade explanation.</summary>
    public string GradeReason { get; set; } = "";

    /// <summary>Total audit runs analyzed.</summary>
    public int TotalRuns { get; set; }

    /// <summary>Analysis window start.</summary>
    public DateTimeOffset WindowStart { get; set; }

    /// <summary>Analysis window end.</summary>
    public DateTimeOffset WindowEnd { get; set; }

    /// <summary>Total unique findings seen across all runs.</summary>
    public int TotalUniqueFindingsSeen { get; set; }

    /// <summary>Total findings resolved during window.</summary>
    public int TotalResolved { get; set; }

    /// <summary>Total findings introduced during window.</summary>
    public int TotalIntroduced { get; set; }
}
