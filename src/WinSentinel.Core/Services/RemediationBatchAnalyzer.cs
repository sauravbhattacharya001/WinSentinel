using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes findings to discover batched remediation opportunities —
/// single fix actions that resolve multiple findings at once.
/// Groups findings by shared remediation text or fix command,
/// ranks batches by aggregate severity impact, and produces an
/// optimised remediation order that maximises findings-resolved-per-action.
/// </summary>
public class RemediationBatchAnalyzer
{
    // -- Public types --

    /// <summary>A group of findings that share the same remediation action.</summary>
    public class RemediationBatch
    {
        /// <summary>Canonical action key (normalised remediation or fix command text).</summary>
        public string ActionKey { get; init; } = "";

        /// <summary>Human-readable action description.</summary>
        public string Action { get; init; } = "";

        /// <summary>Whether this batch has an automated fix command.</summary>
        public bool HasFixCommand { get; init; }

        /// <summary>The shared fix command, if any.</summary>
        public string? FixCommand { get; init; }

        /// <summary>Findings resolved by this single action.</summary>
        public List<BatchedFinding> Findings { get; init; } = [];

        /// <summary>Total number of findings resolved.</summary>
        public int FindingCount => Findings.Count;

        /// <summary>Distinct categories affected.</summary>
        public List<string> Categories => Findings.Select(f => f.Category).Distinct().OrderBy(c => c).ToList();

        /// <summary>Number of distinct categories this action touches.</summary>
        public int CategoryCount => Categories.Count;

        /// <summary>Highest severity among grouped findings.</summary>
        public Severity MaxSeverity => Findings.Count > 0
            ? Findings.Max(f => f.Severity)
            : Severity.Pass;

        /// <summary>Total severity weight (Critical=10, Warning=5, Info=1).</summary>
        public int TotalImpact => Findings.Sum(f => SeverityWeight(f.Severity));

        /// <summary>Average severity weight per finding.</summary>
        public double AverageImpact => FindingCount > 0 ? (double)TotalImpact / FindingCount : 0;

        /// <summary>Efficiency score: impact × log2(count+1). Higher = more valuable to fix.</summary>
        public double EfficiencyScore => TotalImpact * Math.Log2(FindingCount + 1);
    }

    /// <summary>A finding within a batch, with its source category.</summary>
    public record BatchedFinding(
        string Title,
        string Description,
        Severity Severity,
        string Category,
        string? Remediation,
        string? FixCommand);

    /// <summary>Strategy for grouping findings into batches.</summary>
    public enum GroupingStrategy
    {
        /// <summary>Group by normalised remediation text.</summary>
        ByRemediation,
        /// <summary>Group by normalised fix command.</summary>
        ByFixCommand,
        /// <summary>Group by both (prefer fix command, fall back to remediation).</summary>
        Combined
    }

    /// <summary>Overall batch analysis result.</summary>
    public class BatchAnalysisResult
    {
        /// <summary>Strategy used for grouping.</summary>
        public GroupingStrategy Strategy { get; init; }

        /// <summary>All batches, ordered by efficiency score descending.</summary>
        public List<RemediationBatch> Batches { get; init; } = [];

        /// <summary>Total unique findings analysed.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Number of findings that appear in multi-finding batches.</summary>
        public int BatchableFindings => Batches.Where(b => b.FindingCount > 1).Sum(b => b.FindingCount);

        /// <summary>Percentage of findings that can be batch-resolved.</summary>
        public double BatchablePercent => TotalFindings > 0
            ? 100.0 * BatchableFindings / TotalFindings : 0;

        /// <summary>Number of batches with more than one finding.</summary>
        public int MultiFindingBatchCount => Batches.Count(b => b.FindingCount > 1);

        /// <summary>Number of batches with automated fix commands.</summary>
        public int AutomatableBatchCount => Batches.Count(b => b.HasFixCommand);

        /// <summary>Top N batches by efficiency score.</summary>
        public List<RemediationBatch> TopOpportunities(int n = 5) =>
            Batches.Where(b => b.FindingCount > 1).Take(n).ToList();

        /// <summary>Estimated minimum actions to resolve all findings.</summary>
        public int MinimumActions => Batches.Count;

        /// <summary>Actions saved by batching vs fixing each finding individually.</summary>
        public int ActionsSaved => TotalFindings - MinimumActions;

        /// <summary>Generate a human-readable text summary.</summary>
        public string ToSummary()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"=== Remediation Batch Analysis ({Strategy}) ===");
            sb.AppendLine();
            sb.AppendLine($"Total findings:          {TotalFindings}");
            sb.AppendLine($"Unique actions needed:   {MinimumActions}");
            sb.AppendLine($"Actions saved by batch:  {ActionsSaved}");
            sb.AppendLine($"Batchable findings:      {BatchableFindings} ({BatchablePercent:F0}%)");
            sb.AppendLine($"Multi-finding batches:   {MultiFindingBatchCount}");
            sb.AppendLine($"Automatable batches:     {AutomatableBatchCount}");
            sb.AppendLine();

            var topOps = TopOpportunities(10);
            if (topOps.Count > 0)
            {
                sb.AppendLine("-- Top Batch Opportunities (fix once, resolve many) --");
                for (int i = 0; i < topOps.Count; i++)
                {
                    var b = topOps[i];
                    var auto = b.HasFixCommand ? " [AUTO]" : "";
                    sb.AppendLine($"  {i + 1}. {b.Action}{auto}");
                    sb.AppendLine($"     Resolves {b.FindingCount} findings across {b.CategoryCount} categories (impact: {b.TotalImpact})");
                    foreach (var f in b.Findings.Take(5))
                        sb.AppendLine($"       • [{f.Severity}] {f.Title} ({f.Category})");
                    if (b.FindingCount > 5)
                        sb.AppendLine($"       ... and {b.FindingCount - 5} more");
                }
            }

            return sb.ToString();
        }
    }

    // -- Public API --

    /// <summary>Analyse a security report for batch remediation opportunities.</summary>
    public BatchAnalysisResult Analyze(SecurityReport report, GroupingStrategy strategy = GroupingStrategy.Combined)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var actionable = report.Results
            .SelectMany(r => r.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning or Severity.Info)
                .Select(f => new BatchedFinding(f.Title, f.Description, f.Severity, r.Category, f.Remediation, f.FixCommand)))
            .ToList();

        var groups = GroupFindings(actionable, strategy);

        var batches = groups
            .Select(g => new RemediationBatch
            {
                ActionKey = g.Key,
                Action = g.Action,
                HasFixCommand = g.FixCommand != null,
                FixCommand = g.FixCommand,
                Findings = g.Findings
            })
            .OrderByDescending(b => b.EfficiencyScore)
            .ThenByDescending(b => b.TotalImpact)
            .ToList();

        return new BatchAnalysisResult
        {
            Strategy = strategy,
            Batches = batches,
            TotalFindings = actionable.Count
        };
    }

    /// <summary>Analyse findings from multiple reports for persistent batch patterns.</summary>
    public BatchAnalysisResult AnalyzeMultiple(IEnumerable<SecurityReport> reports, GroupingStrategy strategy = GroupingStrategy.Combined)
    {
        if (reports == null) throw new ArgumentNullException(nameof(reports));

        var allFindings = reports
            .SelectMany(r => r.Results
                .SelectMany(ar => ar.Findings
                    .Where(f => f.Severity is Severity.Critical or Severity.Warning or Severity.Info)
                    .Select(f => new BatchedFinding(f.Title, f.Description, f.Severity, ar.Category, f.Remediation, f.FixCommand))))
            .GroupBy(f => (f.Title, f.Category))
            .Select(g => g.First())
            .ToList();

        var groups = GroupFindings(allFindings, strategy);

        var batches = groups
            .Select(g => new RemediationBatch
            {
                ActionKey = g.Key,
                Action = g.Action,
                HasFixCommand = g.FixCommand != null,
                FixCommand = g.FixCommand,
                Findings = g.Findings
            })
            .OrderByDescending(b => b.EfficiencyScore)
            .ThenByDescending(b => b.TotalImpact)
            .ToList();

        return new BatchAnalysisResult
        {
            Strategy = strategy,
            Batches = batches,
            TotalFindings = allFindings.Count
        };
    }

    /// <summary>Get findings with no remediation or fix command.</summary>
    public List<BatchedFinding> FindOrphans(SecurityReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        return report.Results
            .SelectMany(r => r.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning or Severity.Info)
                .Where(f => string.IsNullOrWhiteSpace(f.Remediation) && string.IsNullOrWhiteSpace(f.FixCommand))
                .Select(f => new BatchedFinding(f.Title, f.Description, f.Severity, r.Category, f.Remediation, f.FixCommand)))
            .ToList();
    }

    /// <summary>Compute an optimal fix ordering: automated high-impact batches first.</summary>
    public List<RemediationBatch> OptimalFixOrder(BatchAnalysisResult analysis)
    {
        if (analysis == null) throw new ArgumentNullException(nameof(analysis));

        return analysis.Batches
            .OrderByDescending(b => b.HasFixCommand)
            .ThenByDescending(b => b.MaxSeverity)
            .ThenByDescending(b => b.EfficiencyScore)
            .ToList();
    }

    // -- Private helpers --

    private record GroupResult(string Key, string Action, string? FixCommand, List<BatchedFinding> Findings);

    private static List<GroupResult> GroupFindings(List<BatchedFinding> findings, GroupingStrategy strategy)
    {
        return strategy switch
        {
            GroupingStrategy.ByRemediation => GroupByRemediation(findings),
            GroupingStrategy.ByFixCommand => GroupByFixCommand(findings),
            GroupingStrategy.Combined => GroupCombined(findings),
            _ => GroupCombined(findings)
        };
    }

    private static List<GroupResult> GroupByRemediation(List<BatchedFinding> findings)
    {
        return findings
            .Where(f => !string.IsNullOrWhiteSpace(f.Remediation))
            .GroupBy(f => NormalizeKey(f.Remediation!))
            .Select(g => new GroupResult(
                g.Key,
                g.First().Remediation!,
                g.FirstOrDefault(f => f.FixCommand != null)?.FixCommand,
                g.ToList()))
            .Concat(findings
                .Where(f => string.IsNullOrWhiteSpace(f.Remediation))
                .Select(f => new GroupResult(
                    $"orphan:{f.Title}:{f.Category}",
                    f.Title,
                    f.FixCommand,
                    [f])))
            .ToList();
    }

    private static List<GroupResult> GroupByFixCommand(List<BatchedFinding> findings)
    {
        return findings
            .Where(f => !string.IsNullOrWhiteSpace(f.FixCommand))
            .GroupBy(f => NormalizeKey(f.FixCommand!))
            .Select(g => new GroupResult(
                g.Key,
                g.First().Remediation ?? g.First().FixCommand!,
                g.First().FixCommand,
                g.ToList()))
            .Concat(findings
                .Where(f => string.IsNullOrWhiteSpace(f.FixCommand))
                .Select(f => new GroupResult(
                    $"nofix:{f.Title}:{f.Category}",
                    f.Remediation ?? f.Title,
                    null,
                    [f])))
            .ToList();
    }

    private static List<GroupResult> GroupCombined(List<BatchedFinding> findings)
    {
        return findings
            .GroupBy(f => !string.IsNullOrWhiteSpace(f.FixCommand)
                ? $"fix:{NormalizeKey(f.FixCommand!)}"
                : !string.IsNullOrWhiteSpace(f.Remediation)
                    ? $"rem:{NormalizeKey(f.Remediation!)}"
                    : $"orphan:{f.Title}:{f.Category}")
            .Select(g =>
            {
                var first = g.First();
                return new GroupResult(
                    g.Key,
                    first.Remediation ?? first.FixCommand ?? first.Title,
                    g.FirstOrDefault(f => f.FixCommand != null)?.FixCommand,
                    g.ToList());
            })
            .ToList();
    }

    private static string NormalizeKey(string text)
    {
        return System.Text.RegularExpressions.Regex.Replace(text.Trim().ToLowerInvariant(), @"\s+", " ");
    }

    public static int SeverityWeight(Severity severity) => severity switch
    {
        Severity.Critical => 10,
        Severity.Warning => 5,
        Severity.Info => 1,
        _ => 0
    };
}
