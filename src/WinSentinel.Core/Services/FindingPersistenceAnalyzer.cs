using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes finding persistence across multiple audit runs.
/// Classifies each unique finding as Chronic (present in every run),
/// Recurring (intermittent), Transient (appeared once), or Resolved
/// (present in older runs but not the latest). Helps security teams
/// distinguish systemic issues from one-off detections.
/// </summary>
public class FindingPersistenceAnalyzer
{
    /// <summary>Minimum number of runs required for meaningful analysis.</summary>
    public const int MinRunsForAnalysis = 2;

    /// <summary>Maximum number of runs to analyze (performance guard).</summary>
    public const int MaxRunsToAnalyze = 500;

    // ── Classification thresholds ────────────────────────────────────

    /// <summary>
    /// Minimum presence ratio (appearances / totalRuns) to classify as Chronic.
    /// A finding that appears in ≥90% of runs is chronic.
    /// </summary>
    public double ChronicThreshold { get; set; } = 0.9;

    /// <summary>
    /// Minimum presence ratio to classify as Recurring (if not Chronic).
    /// A finding that appears in ≥30% of runs but &lt;90% is recurring.
    /// </summary>
    public double RecurringThreshold { get; set; } = 0.3;

    // ── Core analysis ────────────────────────────────────────────────

    /// <summary>
    /// Analyze finding persistence across multiple audit runs.
    /// Runs should include <see cref="AuditRunRecord.Findings"/> populated.
    /// </summary>
    /// <param name="runs">Audit run records, in any order (will be sorted internally).</param>
    /// <returns>A persistence report classifying each unique finding.</returns>
    /// <exception cref="ArgumentNullException">If runs is null.</exception>
    public PersistenceReport Analyze(List<AuditRunRecord> runs)
    {
        ArgumentNullException.ThrowIfNull(runs);

        if (runs.Count < MinRunsForAnalysis)
        {
            return new PersistenceReport
            {
                HasSufficientData = false,
                TotalRunsAnalyzed = runs.Count,
                Message = $"Need at least {MinRunsForAnalysis} runs for persistence analysis."
            };
        }

        // Sort chronologically and cap at MaxRunsToAnalyze
        var sorted = runs
            .OrderBy(r => r.Timestamp)
            .TakeLast(MaxRunsToAnalyze)
            .ToList();

        var totalRuns = sorted.Count;
        var latestRunFindings = new HashSet<string>(
            sorted.Last().Findings.Select(f => NormalizeKey(f)),
            StringComparer.OrdinalIgnoreCase);

        // Track each unique finding across runs
        var findingTracker = new Dictionary<string, FindingTrackingInfo>(
            StringComparer.OrdinalIgnoreCase);

        for (int runIndex = 0; runIndex < sorted.Count; runIndex++)
        {
            var run = sorted[runIndex];
            var seenInThisRun = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var finding in run.Findings)
            {
                var key = NormalizeKey(finding);
                if (!seenInThisRun.Add(key)) continue; // Skip duplicates within same run

                if (!findingTracker.TryGetValue(key, out var info))
                {
                    info = new FindingTrackingInfo
                    {
                        Key = key,
                        Title = finding.Title,
                        Module = finding.ModuleName,
                        Severity = finding.Severity,
                        Description = finding.Description,
                        Remediation = finding.Remediation,
                        FirstSeenIndex = runIndex,
                        FirstSeenTimestamp = run.Timestamp
                    };
                    findingTracker[key] = info;
                }

                info.AppearanceCount++;
                info.LastSeenIndex = runIndex;
                info.LastSeenTimestamp = run.Timestamp;

                // Track consecutive appearances ending at latest run
                if (runIndex == sorted.Count - 1)
                    info.PresentInLatest = true;
            }
        }

        // Compute consecutive run count (from latest backwards)
        foreach (var info in findingTracker.Values.Where(i => i.PresentInLatest))
        {
            info.ConsecutiveFromLatest = CountConsecutiveFromEnd(sorted, info.Key);
        }

        // Classify findings
        var entries = new List<PersistenceEntry>();
        foreach (var info in findingTracker.Values)
        {
            var ratio = (double)info.AppearanceCount / totalRuns;
            var classification = ClassifyFinding(ratio, info, totalRuns);

            entries.Add(new PersistenceEntry
            {
                Title = info.Title,
                Module = info.Module,
                Severity = ParseSeverity(info.Severity),
                Description = info.Description,
                Remediation = info.Remediation,
                Classification = classification,
                AppearanceCount = info.AppearanceCount,
                TotalRuns = totalRuns,
                PresenceRatio = Math.Round(ratio, 3),
                FirstSeen = info.FirstSeenTimestamp,
                LastSeen = info.LastSeenTimestamp,
                PresentInLatest = info.PresentInLatest,
                ConsecutiveFromLatest = info.ConsecutiveFromLatest
            });
        }

        // Sort: Chronic first, then by severity, then by presence ratio
        entries.Sort((a, b) =>
        {
            var classOrder = ClassificationOrder(a.Classification)
                .CompareTo(ClassificationOrder(b.Classification));
            if (classOrder != 0) return classOrder;

            var sevOrder = b.Severity.CompareTo(a.Severity);
            if (sevOrder != 0) return sevOrder;

            return b.PresenceRatio.CompareTo(a.PresenceRatio);
        });

        return new PersistenceReport
        {
            HasSufficientData = true,
            TotalRunsAnalyzed = totalRuns,
            AnalysisWindow = sorted.Last().Timestamp - sorted.First().Timestamp,
            FirstRunDate = sorted.First().Timestamp,
            LastRunDate = sorted.Last().Timestamp,
            TotalUniqueFindings = entries.Count,
            ChronicCount = entries.Count(e => e.Classification == PersistenceClass.Chronic),
            RecurringCount = entries.Count(e => e.Classification == PersistenceClass.Recurring),
            TransientCount = entries.Count(e => e.Classification == PersistenceClass.Transient),
            ResolvedCount = entries.Count(e => e.Classification == PersistenceClass.Resolved),
            Entries = entries,
            ChronicThresholdUsed = ChronicThreshold,
            RecurringThresholdUsed = RecurringThreshold
        };
    }

    /// <summary>
    /// Generate a plain-text summary of the persistence report.
    /// </summary>
    public static string FormatSummary(PersistenceReport report)
    {
        if (!report.HasSufficientData)
            return report.Message ?? "Insufficient data for persistence analysis.";

        var lines = new List<string>
        {
            "═══════════════════════════════════════════════════",
            "  FINDING PERSISTENCE ANALYSIS",
            "═══════════════════════════════════════════════════",
            "",
            $"  Analysis window:  {report.AnalysisWindow.Days} days ({report.TotalRunsAnalyzed} runs)",
            $"  Unique findings:  {report.TotalUniqueFindings}",
            "",
            $"  ● Chronic:    {report.ChronicCount,-4} (present in ≥{report.ChronicThresholdUsed * 100:0}% of runs)",
            $"  ◐ Recurring:  {report.RecurringCount,-4} (intermittent, ≥{report.RecurringThresholdUsed * 100:0}%)",
            $"  ○ Transient:  {report.TransientCount,-4} (appeared briefly)",
            $"  ✓ Resolved:   {report.ResolvedCount,-4} (no longer present)"
        };

        // Chronic findings detail
        var chronicEntries = report.Entries
            .Where(e => e.Classification == PersistenceClass.Chronic)
            .ToList();
        if (chronicEntries.Count > 0)
        {
            lines.Add("");
            lines.Add("───────────────────────────────────────────────────");
            lines.Add("  CHRONIC FINDINGS (require systemic remediation)");
            lines.Add("───────────────────────────────────────────────────");
            foreach (var entry in chronicEntries)
            {
                var sevLabel = entry.Severity == Severity.Critical ? "CRIT" : "WARN";
                lines.Add($"  [{sevLabel}] {entry.Title}");
                lines.Add($"         Module: {entry.Module} | " +
                           $"Present: {entry.AppearanceCount}/{entry.TotalRuns} runs ({entry.PresenceRatio * 100:0}%) | " +
                           $"Consecutive: {entry.ConsecutiveFromLatest}");
            }
        }

        // Recently resolved
        var resolved = report.Entries
            .Where(e => e.Classification == PersistenceClass.Resolved)
            .OrderByDescending(e => e.LastSeen)
            .Take(10)
            .ToList();
        if (resolved.Count > 0)
        {
            lines.Add("");
            lines.Add("───────────────────────────────────────────────────");
            lines.Add("  RECENTLY RESOLVED");
            lines.Add("───────────────────────────────────────────────────");
            foreach (var entry in resolved)
            {
                lines.Add($"  ✓ {entry.Title}");
                lines.Add($"         Last seen: {entry.LastSeen.LocalDateTime:yyyy-MM-dd HH:mm} | " +
                           $"Was present: {entry.AppearanceCount}/{entry.TotalRuns} runs");
            }
        }

        lines.Add("");
        lines.Add("═══════════════════════════════════════════════════");
        return string.Join(Environment.NewLine, lines);
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// <summary>
    /// Build a normalized key for a finding: "module|title" (case-insensitive).
    /// </summary>
    private static string NormalizeKey(FindingRecord finding)
    {
        return $"{finding.ModuleName}|{finding.Title}".ToLowerInvariant();
    }

    /// <summary>
    /// Classify a finding based on its presence ratio and latest-run status.
    /// </summary>
    private PersistenceClass ClassifyFinding(
        double presenceRatio, FindingTrackingInfo info, int totalRuns)
    {
        // If not present in the latest run, it's resolved
        if (!info.PresentInLatest)
            return PersistenceClass.Resolved;

        // Chronic: present in ≥90% of runs
        if (presenceRatio >= ChronicThreshold)
            return PersistenceClass.Chronic;

        // Recurring: present in ≥30% of runs
        if (presenceRatio >= RecurringThreshold)
            return PersistenceClass.Recurring;

        // Transient: appeared infrequently
        return PersistenceClass.Transient;
    }

    /// <summary>
    /// Count how many consecutive runs (from the latest backwards) contain this finding.
    /// </summary>
    private static int CountConsecutiveFromEnd(
        List<AuditRunRecord> sortedRuns, string findingKey)
    {
        int count = 0;
        for (int i = sortedRuns.Count - 1; i >= 0; i--)
        {
            var hasIt = sortedRuns[i].Findings
                .Any(f => NormalizeKey(f).Equals(findingKey, StringComparison.OrdinalIgnoreCase));
            if (hasIt)
                count++;
            else
                break;
        }
        return count;
    }

    /// <summary>
    /// Parse a severity string to the enum. Defaults to Info if unrecognized.
    /// </summary>
    private static Severity ParseSeverity(string severity)
    {
        return Enum.TryParse<Severity>(severity, ignoreCase: true, out var result)
            ? result
            : Severity.Info;
    }

    /// <summary>
    /// Sort order for classifications (lower = first).
    /// </summary>
    private static int ClassificationOrder(PersistenceClass c) => c switch
    {
        PersistenceClass.Chronic => 0,
        PersistenceClass.Recurring => 1,
        PersistenceClass.Transient => 2,
        PersistenceClass.Resolved => 3,
        _ => 4
    };

    /// <summary>
    /// Internal tracking during analysis.
    /// </summary>
    private class FindingTrackingInfo
    {
        public string Key { get; set; } = "";
        public string Title { get; set; } = "";
        public string Module { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Description { get; set; } = "";
        public string? Remediation { get; set; }
        public int AppearanceCount { get; set; }
        public int FirstSeenIndex { get; set; }
        public int LastSeenIndex { get; set; }
        public DateTimeOffset FirstSeenTimestamp { get; set; }
        public DateTimeOffset LastSeenTimestamp { get; set; }
        public bool PresentInLatest { get; set; }
        public int ConsecutiveFromLatest { get; set; }
    }
}

// ── Result models ────────────────────────────────────────────────────

/// <summary>
/// How a finding persists across audit runs.
/// </summary>
public enum PersistenceClass
{
    /// <summary>Present in ≥90% of runs — systemic issue.</summary>
    Chronic,
    /// <summary>Present intermittently (≥30% but &lt;90%) — comes and goes.</summary>
    Recurring,
    /// <summary>Present infrequently (&lt;30%) — sporadic appearance.</summary>
    Transient,
    /// <summary>Was present in older runs but not the latest — fixed.</summary>
    Resolved
}

/// <summary>
/// Complete persistence analysis report.
/// </summary>
public class PersistenceReport
{
    /// <summary>Whether there were enough runs for meaningful analysis.</summary>
    public bool HasSufficientData { get; set; }

    /// <summary>Message when data is insufficient.</summary>
    public string? Message { get; set; }

    /// <summary>Number of audit runs analyzed.</summary>
    public int TotalRunsAnalyzed { get; set; }

    /// <summary>Time span covered by the analyzed runs.</summary>
    public TimeSpan AnalysisWindow { get; set; }

    /// <summary>Date of the earliest run analyzed.</summary>
    public DateTimeOffset FirstRunDate { get; set; }

    /// <summary>Date of the latest run analyzed.</summary>
    public DateTimeOffset LastRunDate { get; set; }

    /// <summary>Total unique findings seen across all runs.</summary>
    public int TotalUniqueFindings { get; set; }

    /// <summary>Count of chronic findings.</summary>
    public int ChronicCount { get; set; }

    /// <summary>Count of recurring findings.</summary>
    public int RecurringCount { get; set; }

    /// <summary>Count of transient findings.</summary>
    public int TransientCount { get; set; }

    /// <summary>Count of resolved findings.</summary>
    public int ResolvedCount { get; set; }

    /// <summary>The chronic threshold used for classification.</summary>
    public double ChronicThresholdUsed { get; set; }

    /// <summary>The recurring threshold used for classification.</summary>
    public double RecurringThresholdUsed { get; set; }

    /// <summary>All classified finding entries, sorted by priority.</summary>
    public List<PersistenceEntry> Entries { get; set; } = [];

    /// <summary>True if no findings have ever been observed.</summary>
    public bool IsClean => TotalUniqueFindings == 0;
}

/// <summary>
/// A single finding's persistence profile.
/// </summary>
public class PersistenceEntry
{
    /// <summary>Finding title.</summary>
    public string Title { get; set; } = "";

    /// <summary>Audit module that produced this finding.</summary>
    public string Module { get; set; } = "";

    /// <summary>Severity level.</summary>
    public Severity Severity { get; set; }

    /// <summary>Finding description.</summary>
    public string Description { get; set; } = "";

    /// <summary>Remediation guidance, if available.</summary>
    public string? Remediation { get; set; }

    /// <summary>Persistence classification.</summary>
    public PersistenceClass Classification { get; set; }

    /// <summary>Number of runs this finding appeared in.</summary>
    public int AppearanceCount { get; set; }

    /// <summary>Total runs analyzed.</summary>
    public int TotalRuns { get; set; }

    /// <summary>Ratio of runs containing this finding (0.0 – 1.0).</summary>
    public double PresenceRatio { get; set; }

    /// <summary>When this finding was first observed.</summary>
    public DateTimeOffset FirstSeen { get; set; }

    /// <summary>When this finding was last observed.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Whether this finding is present in the most recent run.</summary>
    public bool PresentInLatest { get; set; }

    /// <summary>How many consecutive runs (from latest) contain this finding.</summary>
    public int ConsecutiveFromLatest { get; set; }

    /// <summary>
    /// Human-readable classification label with icon.
    /// </summary>
    public string ClassificationLabel => Classification switch
    {
        PersistenceClass.Chronic => "● Chronic",
        PersistenceClass.Recurring => "◐ Recurring",
        PersistenceClass.Transient => "○ Transient",
        PersistenceClass.Resolved => "✓ Resolved",
        _ => "? Unknown"
    };
}
