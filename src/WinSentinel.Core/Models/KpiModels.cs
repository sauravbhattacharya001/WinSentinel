namespace WinSentinel.Core.Models;

/// <summary>
/// Security KPI (Key Performance Indicator) metrics computed from audit history.
/// </summary>
public class SecurityKpiReport
{
    /// <summary>Number of audit runs analyzed.</summary>
    public int RunsAnalyzed { get; set; }

    /// <summary>Days of history covered.</summary>
    public int DaysSpan { get; set; }

    /// <summary>Period start date.</summary>
    public DateTimeOffset PeriodStart { get; set; }

    /// <summary>Period end date.</summary>
    public DateTimeOffset PeriodEnd { get; set; }

    // ── Score KPIs ─────────────────────────────────────────

    /// <summary>Current security score.</summary>
    public int CurrentScore { get; set; }

    /// <summary>Average score across the period.</summary>
    public double AverageScore { get; set; }

    /// <summary>Standard deviation of scores (volatility).</summary>
    public double ScoreVolatility { get; set; }

    /// <summary>Score trend direction over the period.</summary>
    public string ScoreTrend { get; set; } = "Stable";

    /// <summary>Net score change over the period.</summary>
    public int ScoreChange { get; set; }

    // ── Finding KPIs ───────────────────────────────────────

    /// <summary>Current total open findings.</summary>
    public int CurrentFindings { get; set; }

    /// <summary>Average findings per scan.</summary>
    public double AverageFindingsPerScan { get; set; }

    /// <summary>New findings introduced during the period.</summary>
    public int NewFindings { get; set; }

    /// <summary>Findings resolved during the period.</summary>
    public int ResolvedFindings { get; set; }

    /// <summary>Net change in findings (negative = improvement).</summary>
    public int FindingNetChange { get; set; }

    /// <summary>Findings that appeared, were resolved, then reappeared.</summary>
    public int RecurringFindings { get; set; }

    /// <summary>Recurrence rate as a percentage.</summary>
    public double RecurrenceRate { get; set; }

    // ── Severity KPIs ──────────────────────────────────────

    /// <summary>Current critical finding count.</summary>
    public int CurrentCritical { get; set; }

    /// <summary>Current warning finding count.</summary>
    public int CurrentWarnings { get; set; }

    /// <summary>Peak critical count during the period.</summary>
    public int PeakCritical { get; set; }

    /// <summary>Average critical findings per scan.</summary>
    public double AvgCriticalPerScan { get; set; }

    /// <summary>Average time (in days) a critical finding persists before resolution.</summary>
    public double? MeanTimeToRemediateCritical { get; set; }

    /// <summary>Average time (in days) a warning finding persists before resolution.</summary>
    public double? MeanTimeToRemediateWarning { get; set; }

    // ── Security Debt ──────────────────────────────────────

    /// <summary>Estimated security debt (weighted sum of open findings by severity).</summary>
    public double SecurityDebt { get; set; }

    /// <summary>Security debt trend (increasing/decreasing/stable).</summary>
    public string DebtTrend { get; set; } = "Stable";

    /// <summary>Debt change over the period.</summary>
    public double DebtChange { get; set; }

    // ── Scan Cadence KPIs ──────────────────────────────────

    /// <summary>Average days between scans.</summary>
    public double AvgDaysBetweenScans { get; set; }

    /// <summary>Longest gap between scans (days).</summary>
    public double MaxScanGap { get; set; }

    /// <summary>Total scans in the period.</summary>
    public int TotalScans { get; set; }

    /// <summary>Scans per week average.</summary>
    public double ScansPerWeek { get; set; }

    // ── Module KPIs ────────────────────────────────────────

    /// <summary>Module with the lowest current score.</summary>
    public string? WeakestModule { get; set; }

    /// <summary>Weakest module's score.</summary>
    public int? WeakestModuleScore { get; set; }

    /// <summary>Module with the most improvement over the period.</summary>
    public string? MostImprovedModule { get; set; }

    /// <summary>Most improved module's score change.</summary>
    public int? MostImprovedChange { get; set; }

    /// <summary>Module with the most regression over the period.</summary>
    public string? MostRegressedModule { get; set; }

    /// <summary>Most regressed module's score change.</summary>
    public int? MostRegressedChange { get; set; }

    // ── Overall Health ─────────────────────────────────────

    /// <summary>Overall health rating: Excellent, Good, Fair, Poor, Critical.</summary>
    public string HealthRating { get; set; } = "Unknown";

    /// <summary>Health score (0-100) combining all KPIs.</summary>
    public int HealthScore { get; set; }

    /// <summary>Top recommendations based on KPIs.</summary>
    public List<string> Recommendations { get; set; } = [];
}
