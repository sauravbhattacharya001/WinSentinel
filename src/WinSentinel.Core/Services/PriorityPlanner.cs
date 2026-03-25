using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a prioritized action plan from audit findings.
/// Ranks findings by impact-effort ratio and produces a clear
/// "fix these first" list with estimated time-to-fix and
/// expected score improvement for each action.
/// </summary>
public class PriorityPlanner
{
    /// <summary>
    /// Analyze findings and produce a prioritized action plan.
    /// </summary>
    public PriorityPlan Generate(SecurityReport report, int maxActions = 10)
    {
        var plan = new PriorityPlan
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            MachineName = Environment.MachineName,
            CurrentScore = report.SecurityScore,
            CurrentGrade = SecurityScorer.GetGrade(report.SecurityScore),
            TotalFindings = report.TotalFindings
        };

        var actions = new List<PriorityAction>();

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                if (finding.Severity == Severity.Pass || finding.Severity == Severity.Info)
                    continue;

                var impact = ComputeImpact(finding);
                var effort = EstimateEffort(finding);
                var ratio = effort > 0 ? impact / effort : impact;

                actions.Add(new PriorityAction
                {
                    Module = result.ModuleName,
                    FindingId = finding.Title,
                    Title = finding.Title,
                    Description = finding.Description,
                    Severity = finding.Severity,
                    Impact = Math.Round(impact, 1),
                    Effort = Math.Round(effort, 1),
                    PriorityScore = Math.Round(ratio, 2),
                    EstimatedMinutes = EstimateMinutes(finding),
                    ExpectedScoreGain = EstimateScoreGain(finding, report),
                    Category = CategorizeAction(finding),
                    QuickWin = effort <= 2.0 && impact >= 5.0
                });
            }
        }

        // Sort by priority score descending (highest impact/effort ratio first)
        actions.Sort((a, b) => b.PriorityScore.CompareTo(a.PriorityScore));

        plan.Actions = actions.Take(maxActions).ToList();
        plan.TotalActionsAvailable = actions.Count;

        // Calculate totals
        plan.EstimatedTotalMinutes = plan.Actions.Sum(a => a.EstimatedMinutes);
        plan.ExpectedScoreAfter = Math.Min(100, plan.CurrentScore +
            plan.Actions.Sum(a => a.ExpectedScoreGain));
        plan.QuickWinCount = plan.Actions.Count(a => a.QuickWin);

        // Group by category
        plan.CategoryBreakdown = plan.Actions
            .GroupBy(a => a.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        return plan;
    }

    private static double ComputeImpact(Finding finding)
    {
        return finding.Severity switch
        {
            Severity.Critical => 10.0,
            Severity.Warning => 5.0,
            _ => 1.0
        };
    }

    private static double EstimateEffort(Finding finding)
    {
        var title = finding.Title.ToLowerInvariant();

        // Quick configuration changes
        if (title.Contains("enable") || title.Contains("disable") ||
            title.Contains("policy") || title.Contains("setting"))
            return 1.0;

        // Registry/group policy changes
        if (title.Contains("registry") || title.Contains("group policy"))
            return 2.0;

        // Firewall rules
        if (title.Contains("firewall") || title.Contains("port"))
            return 3.0;

        // Service configuration
        if (title.Contains("service") || title.Contains("update"))
            return 3.0;

        // Account/permission changes
        if (title.Contains("account") || title.Contains("permission") ||
            title.Contains("privilege"))
            return 4.0;

        // Network/infrastructure changes
        if (title.Contains("network") || title.Contains("encryption") ||
            title.Contains("certificate"))
            return 6.0;

        // Software install/uninstall
        if (title.Contains("install") || title.Contains("remove") ||
            title.Contains("uninstall"))
            return 5.0;

        // Default moderate effort
        return finding.Severity == Severity.Critical ? 4.0 : 3.0;
    }

    private static int EstimateMinutes(Finding finding)
    {
        var effort = EstimateEffort(finding);
        return effort switch
        {
            <= 1.0 => 5,
            <= 2.0 => 10,
            <= 3.0 => 15,
            <= 4.0 => 30,
            <= 5.0 => 45,
            _ => 60
        };
    }

    private static double EstimateScoreGain(Finding finding, SecurityReport report)
    {
        if (report.TotalFindings == 0) return 0;

        // Rough estimation: each critical finding is ~2-3 score points, warnings ~0.5-1
        return finding.Severity switch
        {
            Severity.Critical => Math.Round(2.5 * (100.0 / Math.Max(report.TotalFindings, 1)), 1),
            Severity.Warning => Math.Round(0.8 * (100.0 / Math.Max(report.TotalFindings, 1)), 1),
            _ => 0.1
        };
    }

    private static string CategorizeAction(Finding finding)
    {
        var title = finding.Title.ToLowerInvariant();

        if (title.Contains("firewall") || title.Contains("network") || title.Contains("port"))
            return "Network";
        if (title.Contains("account") || title.Contains("password") || title.Contains("user") ||
            title.Contains("privilege") || title.Contains("admin"))
            return "Identity";
        if (title.Contains("update") || title.Contains("patch") || title.Contains("version"))
            return "Patching";
        if (title.Contains("encrypt") || title.Contains("tls") || title.Contains("ssl") ||
            title.Contains("certificate") || title.Contains("bitlocker"))
            return "Encryption";
        if (title.Contains("service") || title.Contains("startup") || title.Contains("process"))
            return "Services";
        if (title.Contains("policy") || title.Contains("audit") || title.Contains("log"))
            return "Policy";
        if (title.Contains("registry") || title.Contains("setting") || title.Contains("config"))
            return "Configuration";

        return "General";
    }

    /// <summary>Render the plan as plain text.</summary>
    public static string RenderText(PriorityPlan plan)
    {
        var sb = new StringBuilder();

        sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║              🎯 SECURITY PRIORITY PLAN                      ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Machine:    {plan.MachineName}");
        sb.AppendLine($"  Generated:  {plan.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"  Score:      {plan.CurrentScore}/100 ({plan.CurrentGrade})");
        sb.AppendLine($"  Findings:   {plan.TotalFindings} total, {plan.TotalActionsAvailable} actionable");
        sb.AppendLine();

        if (plan.QuickWinCount > 0)
        {
            sb.AppendLine($"  ⚡ {plan.QuickWinCount} quick win{(plan.QuickWinCount != 1 ? "s" : "")} identified (high impact, low effort)");
            sb.AppendLine();
        }

        sb.AppendLine("  ─── Top Priority Actions ────────────────────────────────────");
        sb.AppendLine();

        for (int i = 0; i < plan.Actions.Count; i++)
        {
            var a = plan.Actions[i];
            var marker = a.QuickWin ? " ⚡" : "";
            var severity = a.Severity == Severity.Critical ? "🔴" : "🟡";

            sb.AppendLine($"  {i + 1,2}. {severity} [{a.Category}] {a.Title}{marker}");
            sb.AppendLine($"      Module: {a.Module} | ~{a.EstimatedMinutes} min | +{a.ExpectedScoreGain:F1} pts");

            if (!string.IsNullOrEmpty(a.Description))
            {
                var desc = a.Description.Length > 80 ? a.Description[..77] + "..." : a.Description;
                sb.AppendLine($"      {desc}");
            }

            sb.AppendLine();
        }

        sb.AppendLine("  ─── Summary ─────────────────────────────────────────────────");
        sb.AppendLine();
        sb.AppendLine($"  Estimated time: ~{plan.EstimatedTotalMinutes} minutes");
        sb.AppendLine($"  Projected score: {plan.ExpectedScoreAfter:F0}/100 (from {plan.CurrentScore})");
        sb.AppendLine();

        if (plan.CategoryBreakdown.Count > 0)
        {
            sb.AppendLine("  By category:");
            foreach (var kv in plan.CategoryBreakdown.OrderByDescending(x => x.Value))
            {
                sb.AppendLine($"    {kv.Key,-16} {kv.Value} action{(kv.Value != 1 ? "s" : "")}");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>Render the plan as JSON.</summary>
    public static string RenderJson(PriorityPlan plan)
    {
        return JsonSerializer.Serialize(plan, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }
}

/// <summary>The full priority plan.</summary>
public class PriorityPlan
{
    public DateTimeOffset GeneratedAt { get; set; }
    public string MachineName { get; set; } = "";
    public int CurrentScore { get; set; }
    public string CurrentGrade { get; set; } = "";
    public int TotalFindings { get; set; }
    public int TotalActionsAvailable { get; set; }
    public List<PriorityAction> Actions { get; set; } = new();
    public int EstimatedTotalMinutes { get; set; }
    public double ExpectedScoreAfter { get; set; }
    public int QuickWinCount { get; set; }
    public Dictionary<string, int> CategoryBreakdown { get; set; } = new();
}

/// <summary>A single prioritized action item.</summary>
public class PriorityAction
{
    public string Module { get; set; } = "";
    public string FindingId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public Severity Severity { get; set; }
    public double Impact { get; set; }
    public double Effort { get; set; }
    public double PriorityScore { get; set; }
    public int EstimatedMinutes { get; set; }
    public double ExpectedScoreGain { get; set; }
    public string Category { get; set; } = "";
    public bool QuickWin { get; set; }
}
