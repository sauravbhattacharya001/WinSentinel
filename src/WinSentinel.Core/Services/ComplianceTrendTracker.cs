using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Tracks compliance posture over time across multiple audit runs and
/// regulatory frameworks. Unlike <see cref="ComplianceMapper"/> (which
/// evaluates a single snapshot), this service analyzes how compliance
/// evolves — identifying improving frameworks, persistent gaps, and
/// control state transitions across runs.
/// </summary>
public class ComplianceTrendTracker
{
    private readonly ComplianceMapper _mapper = new();

    // ── Result types ─────────────────────────────────────────────────

    /// <summary>Overall compliance trend analysis across all frameworks.</summary>
    public class ComplianceTrendReport
    {
        /// <summary>When this analysis was generated.</summary>
        public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

        /// <summary>Number of audit snapshots analyzed.</summary>
        public int SnapshotCount { get; init; }

        /// <summary>Time span covered by the snapshots.</summary>
        public TimeSpan TimeSpan { get; init; }

        /// <summary>Per-framework trend data.</summary>
        public List<FrameworkTrend> Frameworks { get; init; } = [];

        /// <summary>Controls that changed status across the most recent two runs.</summary>
        public List<ControlTransition> RecentTransitions { get; init; } = [];

        /// <summary>Controls that have been failing across all analyzed runs.</summary>
        public List<PersistentGap> PersistentGaps { get; init; } = [];

        /// <summary>Overall compliance direction.</summary>
        public TrendDirection OverallDirection { get; init; }

        /// <summary>Human-readable summary.</summary>
        public string Summary { get; init; } = "";
    }

    /// <summary>Trend data for a single compliance framework.</summary>
    public class FrameworkTrend
    {
        /// <summary>Framework identifier (e.g., "CIS", "NIST-800-53").</summary>
        public string FrameworkId { get; init; } = "";

        /// <summary>Framework display name.</summary>
        public string FrameworkName { get; init; } = "";

        /// <summary>Compliance percentage at each snapshot (chronological).</summary>
        public List<ComplianceDataPoint> DataPoints { get; init; } = [];

        /// <summary>Current compliance percentage.</summary>
        public double CurrentPercentage { get; init; }

        /// <summary>Change from first to last snapshot.</summary>
        public double ChangeOverPeriod { get; init; }

        /// <summary>Trend direction.</summary>
        public TrendDirection Direction { get; init; }

        /// <summary>Current verdict.</summary>
        public string CurrentVerdict { get; init; } = "";

        /// <summary>Total controls in this framework.</summary>
        public int TotalControls { get; init; }

        /// <summary>Currently passing controls.</summary>
        public int PassingControls { get; init; }

        /// <summary>Currently failing controls.</summary>
        public int FailingControls { get; init; }
    }

    /// <summary>A single compliance measurement at a point in time.</summary>
    public class ComplianceDataPoint
    {
        /// <summary>When this snapshot was taken.</summary>
        public DateTimeOffset Timestamp { get; init; }

        /// <summary>Compliance percentage (0-100).</summary>
        public double Percentage { get; init; }

        /// <summary>Pass/Fail/Partial/NotAssessed counts.</summary>
        public int PassCount { get; init; }
        public int FailCount { get; init; }
        public int PartialCount { get; init; }
        public int NotAssessedCount { get; init; }

        /// <summary>Verdict at this point.</summary>
        public string Verdict { get; init; } = "";
    }

    /// <summary>A control that changed status between two runs.</summary>
    public class ControlTransition
    {
        /// <summary>Framework this control belongs to.</summary>
        public string FrameworkId { get; init; } = "";

        /// <summary>Control identifier.</summary>
        public string ControlId { get; init; } = "";

        /// <summary>Control title.</summary>
        public string ControlTitle { get; init; } = "";

        /// <summary>Previous status.</summary>
        public string PreviousStatus { get; init; } = "";

        /// <summary>New status.</summary>
        public string NewStatus { get; init; } = "";

        /// <summary>Whether this was an improvement (e.g., Fail → Pass).</summary>
        public bool IsImprovement { get; init; }
    }

    /// <summary>A control that has been failing across all analyzed runs.</summary>
    public class PersistentGap
    {
        /// <summary>Framework this control belongs to.</summary>
        public string FrameworkId { get; init; } = "";

        /// <summary>Control identifier.</summary>
        public string ControlId { get; init; } = "";

        /// <summary>Control title.</summary>
        public string ControlTitle { get; init; } = "";

        /// <summary>Number of consecutive runs this has been failing.</summary>
        public int FailingRunCount { get; init; }

        /// <summary>Remediation suggestions from associated findings.</summary>
        public List<string> RemediationHints { get; init; } = [];
    }

    /// <summary>Overall direction of compliance trend.</summary>
    public enum TrendDirection
    {
        /// <summary>Compliance is improving.</summary>
        Improving,

        /// <summary>Compliance is stable (within ±2%).</summary>
        Stable,

        /// <summary>Compliance is degrading.</summary>
        Degrading,

        /// <summary>Not enough data to determine.</summary>
        Insufficient
    }

    // ── Core analysis ────────────────────────────────────────────────

    /// <summary>
    /// Analyze compliance trends across multiple audit snapshots.
    /// Snapshots should be provided in chronological order (oldest first).
    /// </summary>
    /// <param name="snapshots">Audit snapshots to analyze (oldest first).</param>
    /// <returns>Compliance trend report.</returns>
    public ComplianceTrendReport Analyze(IReadOnlyList<SecurityReport> snapshots)
    {
        if (snapshots == null) throw new ArgumentNullException(nameof(snapshots));

        if (snapshots.Count == 0)
        {
            return new ComplianceTrendReport
            {
                SnapshotCount = 0,
                OverallDirection = TrendDirection.Insufficient,
                Summary = "No audit snapshots provided."
            };
        }

        // Sort chronologically
        var sorted = snapshots.OrderBy(s => s.GeneratedAt).ToList();

        var frameworkIds = _mapper.FrameworkIds;

        // Evaluate each snapshot against all frameworks
        var evaluations = new List<Dictionary<string, ComplianceReport>>();
        foreach (var snapshot in sorted)
        {
            var eval = new Dictionary<string, ComplianceReport>(StringComparer.OrdinalIgnoreCase);
            foreach (var fwId in frameworkIds)
            {
                eval[fwId] = _mapper.Evaluate(snapshot, fwId);
            }
            evaluations.Add(eval);
        }

        // Build per-framework trends
        var frameworkTrends = new List<FrameworkTrend>();
        foreach (var fwId in frameworkIds)
        {
            var framework = _mapper.GetFramework(fwId);
            var dataPoints = new List<ComplianceDataPoint>();

            for (int i = 0; i < sorted.Count; i++)
            {
                var cr = evaluations[i][fwId];
                dataPoints.Add(new ComplianceDataPoint
                {
                    Timestamp = sorted[i].GeneratedAt,
                    Percentage = cr.Summary.CompliancePercentage,
                    PassCount = cr.Summary.PassCount,
                    FailCount = cr.Summary.FailCount,
                    PartialCount = cr.Summary.PartialCount,
                    NotAssessedCount = cr.Summary.NotAssessedCount,
                    Verdict = cr.Summary.OverallVerdict.ToString()
                });
            }

            var latest = evaluations[^1][fwId];
            var first = evaluations[0][fwId];
            var change = latest.Summary.CompliancePercentage - first.Summary.CompliancePercentage;

            frameworkTrends.Add(new FrameworkTrend
            {
                FrameworkId = fwId,
                FrameworkName = framework?.Name ?? fwId,
                DataPoints = dataPoints,
                CurrentPercentage = latest.Summary.CompliancePercentage,
                ChangeOverPeriod = Math.Round(change, 1),
                Direction = ClassifyDirection(change, sorted.Count),
                CurrentVerdict = latest.Summary.OverallVerdict.ToString(),
                TotalControls = latest.Summary.TotalControls,
                PassingControls = latest.Summary.PassCount,
                FailingControls = latest.Summary.FailCount
            });
        }

        // Identify recent control transitions (between last two runs)
        var recentTransitions = new List<ControlTransition>();
        if (sorted.Count >= 2)
        {
            var previous = evaluations[^2];
            var current = evaluations[^1];

            foreach (var fwId in frameworkIds)
            {
                var prevControls = previous[fwId].Controls
                    .ToDictionary(c => c.ControlId, c => c.Status.ToString());
                var currControls = current[fwId].Controls
                    .ToDictionary(c => c.ControlId, c => c);

                foreach (var (controlId, currControl) in currControls)
                {
                    var currStatus = currControl.Status.ToString();
                    if (prevControls.TryGetValue(controlId, out var prevStatus) &&
                        prevStatus != currStatus)
                    {
                        recentTransitions.Add(new ControlTransition
                        {
                            FrameworkId = fwId,
                            ControlId = controlId,
                            ControlTitle = currControl.ControlTitle,
                            PreviousStatus = prevStatus,
                            NewStatus = currStatus,
                            IsImprovement = IsStatusImprovement(prevStatus, currStatus)
                        });
                    }
                }
            }
        }

        // Identify persistent gaps (controls failing in ALL runs)
        var persistentGaps = new List<PersistentGap>();
        if (sorted.Count >= 2)
        {
            foreach (var fwId in frameworkIds)
            {
                var latestReport = evaluations[^1][fwId];
                foreach (var control in latestReport.Controls)
                {
                    if (control.Status != ControlStatus.Fail &&
                        control.Status != ControlStatus.Partial)
                        continue;

                    int failCount = 0;
                    for (int i = 0; i < evaluations.Count; i++)
                    {
                        var status = evaluations[i][fwId].Controls
                            .FirstOrDefault(c => c.ControlId == control.ControlId)?.Status;
                        if (status == ControlStatus.Fail || status == ControlStatus.Partial)
                            failCount++;
                        else
                            break; // only count consecutive from latest
                    }

                    // Count from most recent backward
                    int consecutiveFromEnd = 0;
                    for (int i = evaluations.Count - 1; i >= 0; i--)
                    {
                        var status = evaluations[i][fwId].Controls
                            .FirstOrDefault(c => c.ControlId == control.ControlId)?.Status;
                        if (status == ControlStatus.Fail || status == ControlStatus.Partial)
                            consecutiveFromEnd++;
                        else
                            break;
                    }

                    if (consecutiveFromEnd >= evaluations.Count)
                    {
                        persistentGaps.Add(new PersistentGap
                        {
                            FrameworkId = fwId,
                            ControlId = control.ControlId,
                            ControlTitle = control.ControlTitle,
                            FailingRunCount = consecutiveFromEnd,
                            RemediationHints = control.Remediation.Take(3).ToList()
                        });
                    }
                }
            }
        }

        // Overall direction
        var avgChange = frameworkTrends.Count > 0
            ? frameworkTrends.Average(f => f.ChangeOverPeriod)
            : 0;
        var overallDirection = ClassifyDirection(avgChange, sorted.Count);

        // Build summary
        var summary = BuildSummary(frameworkTrends, recentTransitions,
            persistentGaps, sorted.Count, overallDirection);

        var timeSpan = sorted.Count >= 2
            ? sorted[^1].GeneratedAt - sorted[0].GeneratedAt
            : TimeSpan.Zero;

        return new ComplianceTrendReport
        {
            SnapshotCount = sorted.Count,
            TimeSpan = timeSpan,
            Frameworks = frameworkTrends,
            RecentTransitions = recentTransitions,
            PersistentGaps = persistentGaps,
            OverallDirection = overallDirection,
            Summary = summary
        };
    }

    /// <summary>
    /// Analyze trends for a single framework.
    /// </summary>
    public FrameworkTrend AnalyzeFramework(
        IReadOnlyList<SecurityReport> snapshots,
        string frameworkId)
    {
        if (snapshots == null) throw new ArgumentNullException(nameof(snapshots));

        var framework = _mapper.GetFramework(frameworkId)
            ?? throw new ArgumentException($"Unknown framework: '{frameworkId}'");

        var sorted = snapshots.OrderBy(s => s.GeneratedAt).ToList();

        var dataPoints = sorted.Select(s =>
        {
            var cr = _mapper.Evaluate(s, frameworkId);
            return new ComplianceDataPoint
            {
                Timestamp = s.GeneratedAt,
                Percentage = cr.Summary.CompliancePercentage,
                PassCount = cr.Summary.PassCount,
                FailCount = cr.Summary.FailCount,
                PartialCount = cr.Summary.PartialCount,
                NotAssessedCount = cr.Summary.NotAssessedCount,
                Verdict = cr.Summary.OverallVerdict.ToString()
            };
        }).ToList();

        var latest = _mapper.Evaluate(sorted[^1], frameworkId);
        var first = _mapper.Evaluate(sorted[0], frameworkId);
        var change = latest.Summary.CompliancePercentage - first.Summary.CompliancePercentage;

        return new FrameworkTrend
        {
            FrameworkId = frameworkId,
            FrameworkName = framework.Name,
            DataPoints = dataPoints,
            CurrentPercentage = latest.Summary.CompliancePercentage,
            ChangeOverPeriod = Math.Round(change, 1),
            Direction = ClassifyDirection(change, sorted.Count),
            CurrentVerdict = latest.Summary.OverallVerdict.ToString(),
            TotalControls = latest.Summary.TotalControls,
            PassingControls = latest.Summary.PassCount,
            FailingControls = latest.Summary.FailCount
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private static TrendDirection ClassifyDirection(double change, int snapshotCount)
    {
        if (snapshotCount < 2) return TrendDirection.Insufficient;
        return change switch
        {
            > 2.0 => TrendDirection.Improving,
            < -2.0 => TrendDirection.Degrading,
            _ => TrendDirection.Stable
        };
    }

    private static bool IsStatusImprovement(string previous, string current)
    {
        var rank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["Fail"] = 0,
            ["Partial"] = 1,
            ["NotAssessed"] = 2,
            ["Pass"] = 3
        };

        rank.TryGetValue(previous, out var prevRank);
        rank.TryGetValue(current, out var currRank);
        return currRank > prevRank;
    }

    private static string BuildSummary(
        List<FrameworkTrend> frameworks,
        List<ControlTransition> transitions,
        List<PersistentGap> gaps,
        int snapshotCount,
        TrendDirection direction)
    {
        var parts = new List<string>();

        parts.Add($"Analyzed {snapshotCount} audit snapshot(s) across {frameworks.Count} compliance framework(s).");

        var directionLabel = direction switch
        {
            TrendDirection.Improving => "improving",
            TrendDirection.Degrading => "degrading",
            TrendDirection.Stable => "stable",
            _ => "undetermined"
        };
        parts.Add($"Overall compliance trend: {directionLabel}.");

        var improving = frameworks.Where(f => f.Direction == TrendDirection.Improving).ToList();
        var degrading = frameworks.Where(f => f.Direction == TrendDirection.Degrading).ToList();

        if (improving.Count > 0)
            parts.Add($"Improving: {string.Join(", ", improving.Select(f => $"{f.FrameworkName} (+{f.ChangeOverPeriod}%)"))}.");

        if (degrading.Count > 0)
            parts.Add($"Degrading: {string.Join(", ", degrading.Select(f => $"{f.FrameworkName} ({f.ChangeOverPeriod}%)"))}.");

        if (transitions.Count > 0)
        {
            var improvements = transitions.Count(t => t.IsImprovement);
            var regressions = transitions.Count - improvements;
            parts.Add($"Recent changes: {improvements} improvement(s), {regressions} regression(s).");
        }

        if (gaps.Count > 0)
            parts.Add($"Persistent gaps: {gaps.Count} control(s) failing across all analyzed runs.");

        return string.Join(" ", parts);
    }
}
