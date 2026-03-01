using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Compares two <see cref="SecurityReport"/> snapshots and produces a
/// structured diff showing new findings, resolved findings, severity
/// changes, and per-module score deltas. Useful for understanding exactly
/// what changed between consecutive audit runs.
/// </summary>
public class AuditDiffService
{
    // ── Result types ─────────────────────────────────────────────────

    /// <summary>A finding that appeared in the newer report but not the older one.</summary>
    public record NewFinding(string Module, string Category, Finding Finding);

    /// <summary>A finding that existed in the older report but no longer appears.</summary>
    public record ResolvedFinding(string Module, string Category, Finding Finding);

    /// <summary>A finding whose severity changed between the two reports.</summary>
    public record SeverityChange(
        string Module,
        string Category,
        string Title,
        Severity OldSeverity,
        Severity NewSeverity,
        string Description);

    /// <summary>Score delta for a single audit module.</summary>
    public record ModuleScoreDelta(
        string Module,
        string Category,
        int OldScore,
        int NewScore,
        int Delta,
        int OldFindingCount,
        int NewFindingCount);

    /// <summary>A module that was added or removed between reports.</summary>
    public record ModuleChange(string Module, string Category, ChangeKind Kind);

    /// <summary>Whether a module was added or removed.</summary>
    public enum ChangeKind { Added, Removed }

    /// <summary>
    /// Complete diff result between two audit reports.
    /// </summary>
    public class AuditDiffResult
    {
        /// <summary>Timestamp of the older (baseline) report.</summary>
        public DateTimeOffset OlderTimestamp { get; init; }

        /// <summary>Timestamp of the newer report.</summary>
        public DateTimeOffset NewerTimestamp { get; init; }

        /// <summary>Time elapsed between the two reports.</summary>
        public TimeSpan Elapsed => NewerTimestamp - OlderTimestamp;

        /// <summary>Overall score in the older report.</summary>
        public int OldScore { get; init; }

        /// <summary>Overall score in the newer report.</summary>
        public int NewScore { get; init; }

        /// <summary>Overall score change (positive = improved).</summary>
        public int ScoreDelta => NewScore - OldScore;

        /// <summary>Grade in the older report.</summary>
        public string OldGrade { get; init; } = "";

        /// <summary>Grade in the newer report.</summary>
        public string NewGrade { get; init; } = "";

        /// <summary>Whether the grade changed.</summary>
        public bool GradeChanged => OldGrade != NewGrade;

        /// <summary>Findings present in the newer report but absent from the older.</summary>
        public List<NewFinding> NewFindings { get; init; } = [];

        /// <summary>Findings present in the older report but absent from the newer.</summary>
        public List<ResolvedFinding> ResolvedFindings { get; init; } = [];

        /// <summary>Findings whose severity changed between reports.</summary>
        public List<SeverityChange> SeverityChanges { get; init; } = [];

        /// <summary>Per-module score changes.</summary>
        public List<ModuleScoreDelta> ModuleDeltas { get; init; } = [];

        /// <summary>Modules added or removed between reports.</summary>
        public List<ModuleChange> ModuleChanges { get; init; } = [];

        /// <summary>Net change in critical findings count.</summary>
        public int CriticalDelta { get; init; }

        /// <summary>Net change in warning findings count.</summary>
        public int WarningDelta { get; init; }

        /// <summary>True if there are no differences at all.</summary>
        public bool IsIdentical =>
            NewFindings.Count == 0
            && ResolvedFindings.Count == 0
            && SeverityChanges.Count == 0
            && ModuleChanges.Count == 0
            && ScoreDelta == 0;

        /// <summary>Total number of individual changes detected.</summary>
        public int TotalChanges =>
            NewFindings.Count + ResolvedFindings.Count
            + SeverityChanges.Count + ModuleChanges.Count;

        /// <summary>
        /// Generate a human-readable summary of the diff.
        /// </summary>
        public string Summary()
        {
            if (IsIdentical)
                return "No changes between the two audit reports.";

            var lines = new List<string>();

            // Score headline
            if (ScoreDelta != 0)
            {
                var direction = ScoreDelta > 0 ? "improved" : "declined";
                var gradeNote = GradeChanged ? $" (grade: {OldGrade} → {NewGrade})" : "";
                lines.Add($"Score {direction} by {Math.Abs(ScoreDelta)} points: {OldScore} → {NewScore}{gradeNote}");
            }
            else
            {
                lines.Add($"Score unchanged at {NewScore} ({NewGrade})");
            }

            // Finding counts
            if (NewFindings.Count > 0)
                lines.Add($"  +{NewFindings.Count} new finding(s)");
            if (ResolvedFindings.Count > 0)
                lines.Add($"  -{ResolvedFindings.Count} resolved finding(s)");
            if (SeverityChanges.Count > 0)
                lines.Add($"  ~{SeverityChanges.Count} severity change(s)");

            // Critical/warning deltas
            if (CriticalDelta != 0)
            {
                var label = CriticalDelta > 0 ? $"+{CriticalDelta}" : CriticalDelta.ToString();
                lines.Add($"  Critical findings: {label}");
            }
            if (WarningDelta != 0)
            {
                var label = WarningDelta > 0 ? $"+{WarningDelta}" : WarningDelta.ToString();
                lines.Add($"  Warning findings: {label}");
            }

            // Module changes
            foreach (var mc in ModuleChanges)
            {
                var verb = mc.Kind == ChangeKind.Added ? "Added" : "Removed";
                lines.Add($"  {verb} module: {mc.Module}");
            }

            // Module score changes (only significant ones)
            foreach (var md in ModuleDeltas.Where(d => d.Delta != 0).OrderBy(d => d.Delta))
            {
                var arrow = md.Delta > 0 ? "↑" : "↓";
                lines.Add($"  {md.Module}: {md.OldScore} → {md.NewScore} ({arrow}{Math.Abs(md.Delta)})");
            }

            return string.Join(Environment.NewLine, lines);
        }
    }

    // ── Core diff logic ──────────────────────────────────────────────

    /// <summary>
    /// Compare two security reports and produce a structured diff.
    /// </summary>
    /// <param name="older">The baseline (earlier) report.</param>
    /// <param name="newer">The newer report to compare against the baseline.</param>
    /// <returns>A detailed diff result.</returns>
    /// <exception cref="ArgumentNullException">If either report is null.</exception>
    public AuditDiffResult Compare(SecurityReport older, SecurityReport newer)
    {
        ArgumentNullException.ThrowIfNull(older);
        ArgumentNullException.ThrowIfNull(newer);

        var newFindings = new List<NewFinding>();
        var resolvedFindings = new List<ResolvedFinding>();
        var severityChanges = new List<SeverityChange>();
        var moduleDeltas = new List<ModuleScoreDelta>();
        var moduleChanges = new List<ModuleChange>();

        // Index modules by name for fast lookup
        var oldModules = older.Results.ToDictionary(r => r.ModuleName, StringComparer.OrdinalIgnoreCase);
        var newModules = newer.Results.ToDictionary(r => r.ModuleName, StringComparer.OrdinalIgnoreCase);

        var allModuleNames = oldModules.Keys
            .Union(newModules.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var moduleName in allModuleNames)
        {
            var hasOld = oldModules.TryGetValue(moduleName, out var oldResult);
            var hasNew = newModules.TryGetValue(moduleName, out var newResult);

            // Module added
            if (!hasOld && hasNew)
            {
                moduleChanges.Add(new ModuleChange(moduleName, newResult!.Category, ChangeKind.Added));
                foreach (var f in newResult.Findings)
                    newFindings.Add(new NewFinding(moduleName, newResult.Category, f));
                continue;
            }

            // Module removed
            if (hasOld && !hasNew)
            {
                moduleChanges.Add(new ModuleChange(moduleName, oldResult!.Category, ChangeKind.Removed));
                foreach (var f in oldResult.Findings)
                    resolvedFindings.Add(new ResolvedFinding(moduleName, oldResult.Category, f));
                continue;
            }

            // Both modules must exist at this point
            var oldMod = oldResult!;
            var newMod = newResult!;

            // Module exists in both — diff findings
            DiffModuleFindings(
                moduleName,
                oldMod,
                newMod,
                newFindings,
                resolvedFindings,
                severityChanges);

            // Module score delta
            var oldScore = SecurityScorer.CalculateCategoryScore(oldMod);
            var newScore = SecurityScorer.CalculateCategoryScore(newMod);
            moduleDeltas.Add(new ModuleScoreDelta(
                moduleName,
                newMod.Category,
                oldScore,
                newScore,
                newScore - oldScore,
                oldMod.Findings.Count,
                newMod.Findings.Count));
        }

        return new AuditDiffResult
        {
            OlderTimestamp = older.GeneratedAt,
            NewerTimestamp = newer.GeneratedAt,
            OldScore = older.SecurityScore,
            NewScore = newer.SecurityScore,
            OldGrade = SecurityScorer.GetGrade(older.SecurityScore),
            NewGrade = SecurityScorer.GetGrade(newer.SecurityScore),
            NewFindings = newFindings,
            ResolvedFindings = resolvedFindings,
            SeverityChanges = severityChanges,
            ModuleDeltas = moduleDeltas,
            ModuleChanges = moduleChanges,
            CriticalDelta = newer.TotalCritical - older.TotalCritical,
            WarningDelta = newer.TotalWarnings - older.TotalWarnings,
        };
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// <summary>
    /// Diff findings within a single module. Findings are matched by title
    /// (case-insensitive). A matched pair with different severities becomes
    /// a <see cref="SeverityChange"/>; unmatched findings become new or resolved.
    /// </summary>
    private static void DiffModuleFindings(
        string moduleName,
        AuditResult oldResult,
        AuditResult newResult,
        List<NewFinding> newFindings,
        List<ResolvedFinding> resolvedFindings,
        List<SeverityChange> severityChanges)
    {
        // Group findings by title for matching. If multiple findings share
        // a title (unlikely but possible), compare count-wise.
        var oldByTitle = GroupByTitle(oldResult.Findings);
        var newByTitle = GroupByTitle(newResult.Findings);

        var allTitles = oldByTitle.Keys
            .Union(newByTitle.Keys, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var title in allTitles)
        {
            var hasOldGroup = oldByTitle.TryGetValue(title, out var oldGroup);
            var hasNewGroup = newByTitle.TryGetValue(title, out var newGroup);

            if (!hasOldGroup && hasNewGroup)
            {
                // Entirely new finding(s)
                foreach (var f in newGroup!)
                    newFindings.Add(new NewFinding(moduleName, newResult.Category, f));
            }
            else if (hasOldGroup && !hasNewGroup)
            {
                // Resolved finding(s)
                foreach (var f in oldGroup!)
                    resolvedFindings.Add(new ResolvedFinding(moduleName, oldResult.Category, f));
            }
            else
            {
                // Present in both — check severity changes
                var oldFinding = oldGroup!.First();
                var newFinding = newGroup!.First();

                if (oldFinding.Severity != newFinding.Severity)
                {
                    severityChanges.Add(new SeverityChange(
                        moduleName,
                        newResult.Category,
                        title,
                        oldFinding.Severity,
                        newFinding.Severity,
                        newFinding.Description));
                }

                // Handle count differences (e.g., 2 findings with same title → 1)
                if (newGroup.Count > oldGroup.Count)
                {
                    for (int i = oldGroup.Count; i < newGroup.Count; i++)
                        newFindings.Add(new NewFinding(moduleName, newResult.Category, newGroup[i]));
                }
                else if (oldGroup.Count > newGroup.Count)
                {
                    for (int i = newGroup.Count; i < oldGroup.Count; i++)
                        resolvedFindings.Add(new ResolvedFinding(moduleName, oldResult.Category, oldGroup[i]));
                }
            }
        }
    }

    /// <summary>
    /// Group findings by title (case-insensitive) while preserving order.
    /// </summary>
    private static Dictionary<string, List<Finding>> GroupByTitle(List<Finding> findings)
    {
        var result = new Dictionary<string, List<Finding>>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            if (!result.TryGetValue(f.Title, out var list))
            {
                list = [];
                result[f.Title] = list;
            }
            list.Add(f);
        }
        return result;
    }
}
