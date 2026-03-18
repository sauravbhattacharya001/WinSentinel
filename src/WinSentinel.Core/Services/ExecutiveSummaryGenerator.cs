using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a plain-English executive security summary suitable for
/// non-technical stakeholders — posture grade, top risks, category
/// breakdown, and priority actions.
/// </summary>
public class ExecutiveSummaryGenerator
{
    private readonly AuditHistoryService? _historyService;

    public ExecutiveSummaryGenerator(AuditHistoryService? historyService = null)
    {
        _historyService = historyService;
    }

    /// <summary>
    /// Generate an executive summary from the current report.
    /// </summary>
    public ExecutiveSummary Generate(SecurityReport report, int trendDays = 30)
    {
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);

        // Build category breakdown
        var categories = report.Results
            .GroupBy(r => r.Category)
            .Select(g => new CategoryBrief
            {
                Category = g.Key,
                Score = (int)Math.Round(g.Average(r => (double)r.Score)),
                Critical = g.Sum(r => r.CriticalCount),
                Warnings = g.Sum(r => r.WarningCount),
                ModuleCount = g.Count()
            })
            .OrderBy(c => c.Score)
            .ToList();

        // Top risks: critical findings first, then warnings, limited to 5
        var topRisks = report.Results
            .SelectMany(r => r.Findings.Select(f => new { Finding = f, Module = r.ModuleName }))
            .Where(x => x.Finding.Severity is Severity.Critical or Severity.Warning)
            .OrderByDescending(x => x.Finding.Severity)
            .ThenBy(x => x.Finding.Title)
            .Take(5)
            .Select(x => new SummaryRiskItem
            {
                Title = x.Finding.Title,
                Module = x.Module,
                Severity = x.Finding.Severity,
                Remediation = x.Finding.Remediation
            })
            .ToList();

        // Priority actions: unique remediation steps from critical findings
        var priorityActions = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity == Severity.Critical && !string.IsNullOrWhiteSpace(f.Remediation))
            .Select(f => f.Remediation!)
            .Distinct()
            .Take(5)
            .ToList();

        // If fewer than 3 actions, add from warnings
        if (priorityActions.Count < 3)
        {
            var warningActions = report.Results
                .SelectMany(r => r.Findings)
                .Where(f => f.Severity == Severity.Warning && !string.IsNullOrWhiteSpace(f.Remediation))
                .Select(f => f.Remediation!)
                .Distinct()
                .Where(a => !priorityActions.Contains(a))
                .Take(5 - priorityActions.Count);
            priorityActions.AddRange(warningActions);
        }

        // Trend context (if history is available)
        string? trendNote = null;
        if (_historyService != null)
        {
            try
            {
                var trend = _historyService.GetTrend(trendDays);
                if (trend != null && trend.TotalScans > 1)
                {
                    var dir = trend.ScoreChange > 0 ? "improved" : trend.ScoreChange < 0 ? "declined" : "stable";
                    trendNote = $"Score has {dir} by {Math.Abs(trend.ScoreChange)} points over the last {trendDays} days " +
                                $"(best: {trend.BestScore}, worst: {trend.WorstScore}, avg: {trend.AverageScore:F0}, " +
                                $"{trend.TotalScans} scans).";
                }
            }
            catch
            {
                // History unavailable — skip trend
            }
        }

        // Posture narrative
        var posture = score switch
        {
            >= 90 => "Your system is well-secured with minimal exposure. Continue routine monitoring.",
            >= 75 => "Security posture is reasonable but has notable gaps. Address the critical findings below to strengthen defenses.",
            >= 50 => "Several significant vulnerabilities exist. Immediate attention to the top risks is recommended before an incident occurs.",
            _ => "Security posture is critically weak. Multiple high-severity issues require urgent remediation to prevent compromise."
        };

        return new ExecutiveSummary
        {
            Machine = Environment.MachineName,
            GeneratedAt = DateTimeOffset.Now,
            Score = score,
            Grade = grade,
            PostureNarrative = posture,
            TotalFindings = report.TotalFindings,
            CriticalCount = report.TotalCritical,
            WarningCount = report.TotalWarnings,
            InfoCount = report.TotalInfo,
            PassCount = report.TotalPass,
            ModulesScanned = report.Results.Count,
            Categories = categories,
            TopRisks = topRisks,
            PriorityActions = priorityActions,
            TrendNote = trendNote
        };
    }

    /// <summary>Render summary as plain text for console display.</summary>
    public static string RenderText(ExecutiveSummary summary)
    {
        var sb = new System.Text.StringBuilder();
        var bar = new string('─', 60);

        sb.AppendLine();
        sb.AppendLine($"  ╔{'═'.Repeat(58)}╗");
        sb.AppendLine($"  ║{"EXECUTIVE SECURITY SUMMARY",42}{"",16}║");
        sb.AppendLine($"  ╚{'═'.Repeat(58)}╝");
        sb.AppendLine();
        sb.AppendLine($"  Machine:    {summary.Machine}");
        sb.AppendLine($"  Generated:  {summary.GeneratedAt:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine();
        sb.AppendLine($"  ┌{bar}┐");
        sb.AppendLine($"  │  SECURITY GRADE: {summary.Grade}   SCORE: {summary.Score}/100{"",-20}│");
        sb.AppendLine($"  └{bar}┘");
        sb.AppendLine();
        sb.AppendLine($"  {summary.PostureNarrative}");
        sb.AppendLine();

        // Findings overview
        sb.AppendLine($"  FINDINGS OVERVIEW ({summary.TotalFindings} total across {summary.ModulesScanned} modules)");
        sb.AppendLine($"  {"",2}🔴 Critical: {summary.CriticalCount,-6} 🟡 Warning: {summary.WarningCount,-6} ℹ️  Info: {summary.InfoCount,-6} ✅ Pass: {summary.PassCount}");
        sb.AppendLine();

        if (summary.TrendNote != null)
        {
            sb.AppendLine($"  TREND: {summary.TrendNote}");
            sb.AppendLine();
        }

        // Category breakdown
        if (summary.Categories.Count > 0)
        {
            sb.AppendLine($"  CATEGORY BREAKDOWN");
            sb.AppendLine($"  {"Category",-22} {"Score",5}  {"Crit",4}  {"Warn",4}  {"Modules",7}");
            sb.AppendLine($"  {new string('─', 52)}");
            foreach (var cat in summary.Categories)
            {
                var indicator = cat.Critical > 0 ? "🔴" : cat.Warnings > 0 ? "🟡" : "✅";
                sb.AppendLine($"  {indicator} {cat.Category,-20} {cat.Score,5}  {cat.Critical,4}  {cat.Warnings,4}  {cat.ModuleCount,7}");
            }
            sb.AppendLine();
        }

        // Top risks
        if (summary.TopRisks.Count > 0)
        {
            sb.AppendLine($"  TOP RISKS");
            for (int i = 0; i < summary.TopRisks.Count; i++)
            {
                var risk = summary.TopRisks[i];
                var icon = risk.Severity == Severity.Critical ? "🔴" : "🟡";
                sb.AppendLine($"  {i + 1}. {icon} [{risk.Module}] {risk.Title}");
                if (!string.IsNullOrWhiteSpace(risk.Remediation))
                    sb.AppendLine($"     → {risk.Remediation}");
            }
            sb.AppendLine();
        }

        // Priority actions
        if (summary.PriorityActions.Count > 0)
        {
            sb.AppendLine($"  RECOMMENDED ACTIONS");
            for (int i = 0; i < summary.PriorityActions.Count; i++)
            {
                sb.AppendLine($"  {i + 1}. {summary.PriorityActions[i]}");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>Render summary as JSON.</summary>
    public static string RenderJson(ExecutiveSummary summary)
    {
        var options = new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        };
        return System.Text.Json.JsonSerializer.Serialize(summary, options);
    }

    /// <summary>Render summary as Markdown.</summary>
    public static string RenderMarkdown(ExecutiveSummary summary)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("# Executive Security Summary");
        sb.AppendLine();
        sb.AppendLine($"**Machine:** {summary.Machine}  ");
        sb.AppendLine($"**Date:** {summary.GeneratedAt:yyyy-MM-dd HH:mm}  ");
        sb.AppendLine($"**Grade:** {summary.Grade} ({summary.Score}/100)");
        sb.AppendLine();
        sb.AppendLine($"> {summary.PostureNarrative}");
        sb.AppendLine();
        sb.AppendLine("## Findings");
        sb.AppendLine();
        sb.AppendLine($"| Severity | Count |");
        sb.AppendLine($"|----------|-------|");
        sb.AppendLine($"| Critical | {summary.CriticalCount} |");
        sb.AppendLine($"| Warning  | {summary.WarningCount} |");
        sb.AppendLine($"| Info     | {summary.InfoCount} |");
        sb.AppendLine($"| Pass     | {summary.PassCount} |");
        sb.AppendLine($"| **Total** | **{summary.TotalFindings}** |");
        sb.AppendLine();

        if (summary.TrendNote != null)
        {
            sb.AppendLine($"**Trend:** {summary.TrendNote}");
            sb.AppendLine();
        }

        if (summary.Categories.Count > 0)
        {
            sb.AppendLine("## Category Breakdown");
            sb.AppendLine();
            sb.AppendLine("| Category | Score | Critical | Warnings |");
            sb.AppendLine("|----------|-------|----------|----------|");
            foreach (var cat in summary.Categories)
            {
                sb.AppendLine($"| {cat.Category} | {cat.Score} | {cat.Critical} | {cat.Warnings} |");
            }
            sb.AppendLine();
        }

        if (summary.TopRisks.Count > 0)
        {
            sb.AppendLine("## Top Risks");
            sb.AppendLine();
            foreach (var risk in summary.TopRisks)
            {
                var sev = risk.Severity == Severity.Critical ? "🔴" : "🟡";
                sb.AppendLine($"- {sev} **[{risk.Module}]** {risk.Title}");
                if (!string.IsNullOrWhiteSpace(risk.Remediation))
                    sb.AppendLine($"  - *{risk.Remediation}*");
            }
            sb.AppendLine();
        }

        if (summary.PriorityActions.Count > 0)
        {
            sb.AppendLine("## Recommended Actions");
            sb.AppendLine();
            for (int i = 0; i < summary.PriorityActions.Count; i++)
            {
                sb.AppendLine($"{i + 1}. {summary.PriorityActions[i]}");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }
}

/// <summary>Helper extension for char repeating.</summary>
internal static class CharExtensions
{
    public static string Repeat(this char c, int count) => new(c, count);
}

/// <summary>Executive summary data model.</summary>
public class ExecutiveSummary
{
    public string Machine { get; set; } = "";
    public DateTimeOffset GeneratedAt { get; set; }
    public int Score { get; set; }
    public string Grade { get; set; } = "";
    public string PostureNarrative { get; set; } = "";
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
    public int ModulesScanned { get; set; }
    public List<CategoryBrief> Categories { get; set; } = new();
    public List<SummaryRiskItem> TopRisks { get; set; } = new();
    public List<string> PriorityActions { get; set; } = new();
    public string? TrendNote { get; set; }
}

/// <summary>Category-level score summary.</summary>
public class CategoryBrief
{
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public int Critical { get; set; }
    public int Warnings { get; set; }
    public int ModuleCount { get; set; }
}

/// <summary>A single top-risk item for executive summary.</summary>
public class SummaryRiskItem
{
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public Severity Severity { get; set; }
    public string? Remediation { get; set; }
}
