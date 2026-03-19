using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Estimates remediation cost (time, effort, hourly rate) for each finding,
/// calculates ROI (score-points per hour), and generates prioritised sprint plans.
/// </summary>
public class RemediationCostEstimator
{
    // ── Cost model constants ─────────────────────────────────────────

    private static readonly Dictionary<string, double> CategoryBaseHours = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Firewall"] = 0.25,
        ["Windows Update"] = 0.50,
        ["Defender"] = 0.15,
        ["User Accounts"] = 0.30,
        ["Network"] = 0.40,
        ["Processes"] = 0.20,
        ["Startup"] = 0.15,
        ["System"] = 0.35,
        ["Privacy"] = 0.25,
        ["Browser Security"] = 0.30,
        ["App Security"] = 0.35,
        ["Encryption"] = 0.50,
        ["Event Log"] = 0.20,
        ["Software Inventory"] = 0.25,
        ["Certificates"] = 0.40,
        ["PowerShell"] = 0.20,
        ["DNS"] = 0.25,
        ["Scheduled Tasks"] = 0.20,
        ["Services"] = 0.25,
        ["Registry"] = 0.30,
    };

    private const double DefaultBaseHours = 0.30;
    private const double AutoFixDiscount = 0.7;   // auto-fixable takes 30% of manual time
    private const int DefaultHourlyRate = 85;      // USD per hour (mid-level sysadmin)

    // ── Public API ───────────────────────────────────────────────────

    public CostReport Estimate(SecurityReport report, CostOptions? options = null)
    {
        options ??= new CostOptions();
        var hourlyRate = options.HourlyRate > 0 ? options.HourlyRate : DefaultHourlyRate;

        var items = new List<CostItem>();
        int itemId = 0;

        foreach (var moduleResult in report.Results)
        {
            foreach (var finding in moduleResult.Findings)
            {
                if (finding.Severity is Severity.Pass) continue;

                itemId++;
                var baseHours = GetBaseHours(finding.Category);
                var severityMultiplier = finding.Severity switch
                {
                    Severity.Critical => 1.8,
                    Severity.Warning => 1.0,
                    Severity.Info => 0.5,
                    _ => 0.3
                };

                var hours = baseHours * severityMultiplier;
                if (!string.IsNullOrWhiteSpace(finding.FixCommand))
                    hours *= AutoFixDiscount;

                hours = Math.Round(hours, 2);

                var impactPoints = finding.Severity switch
                {
                    Severity.Critical => 5,
                    Severity.Warning => 2,
                    Severity.Info => 1,
                    _ => 0
                };

                var cost = Math.Round(hours * hourlyRate, 2);
                var roi = hours > 0 ? Math.Round(impactPoints / hours, 2) : 0;

                items.Add(new CostItem
                {
                    Id = itemId,
                    Title = finding.Title,
                    Category = finding.Category,
                    Severity = finding.Severity,
                    EstimatedHours = hours,
                    EstimatedCost = cost,
                    ImpactPoints = impactPoints,
                    Roi = roi,
                    HasAutoFix = !string.IsNullOrWhiteSpace(finding.FixCommand),
                    Remediation = finding.Remediation,
                    FixCommand = finding.FixCommand,
                });
            }
        }

        // Sort by ROI descending (best bang for buck first)
        items = items.OrderByDescending(i => i.Roi)
                     .ThenByDescending(i => i.Severity)
                     .ToList();

        // Renumber
        for (int i = 0; i < items.Count; i++)
            items[i].Id = i + 1;

        var totalHours = items.Sum(i => i.EstimatedHours);
        var totalCost = items.Sum(i => i.EstimatedCost);
        var totalImpact = items.Sum(i => i.ImpactPoints);

        // Generate sprint plan
        var sprints = BuildSprints(items, options.SprintHours);

        return new CostReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            HourlyRate = hourlyRate,
            CurrentScore = report.SecurityScore,
            Items = items,
            TotalHours = Math.Round(totalHours, 1),
            TotalCost = Math.Round(totalCost, 2),
            TotalImpactPoints = totalImpact,
            OverallRoi = totalHours > 0 ? Math.Round(totalImpact / totalHours, 2) : 0,
            Sprints = sprints,
            CriticalCount = items.Count(i => i.Severity == Severity.Critical),
            WarningCount = items.Count(i => i.Severity == Severity.Warning),
            InfoCount = items.Count(i => i.Severity == Severity.Info),
            AutoFixCount = items.Count(i => i.HasAutoFix),
            CategoryBreakdown = items
                .GroupBy(i => i.Category)
                .Select(g => new CategoryCost
                {
                    Category = g.Key,
                    ItemCount = g.Count(),
                    TotalHours = Math.Round(g.Sum(i => i.EstimatedHours), 2),
                    TotalCost = Math.Round(g.Sum(i => i.EstimatedCost), 2),
                    TotalImpact = g.Sum(i => i.ImpactPoints),
                    AverageRoi = g.Average(i => i.Roi),
                })
                .OrderByDescending(c => c.AverageRoi)
                .ToList(),
        };
    }

    // ── Sprint planner ───────────────────────────────────────────────

    private static List<SprintPlan> BuildSprints(List<CostItem> items, double sprintHours)
    {
        if (items.Count == 0) return [];

        var sprints = new List<SprintPlan>();
        var remaining = new Queue<CostItem>(items); // already sorted by ROI
        int sprintNum = 0;

        while (remaining.Count > 0)
        {
            sprintNum++;
            double budget = sprintHours;
            var sprintItems = new List<CostItem>();

            // Greedy fill
            var skipped = new List<CostItem>();
            while (remaining.Count > 0)
            {
                var item = remaining.Dequeue();
                if (item.EstimatedHours <= budget)
                {
                    sprintItems.Add(item);
                    budget -= item.EstimatedHours;
                }
                else
                {
                    skipped.Add(item);
                }
            }

            // Put skipped items back
            foreach (var s in skipped)
                remaining.Enqueue(s);

            if (sprintItems.Count == 0 && remaining.Count > 0)
            {
                // Single item too large for one sprint — include it anyway
                var big = remaining.Dequeue();
                sprintItems.Add(big);
            }

            sprints.Add(new SprintPlan
            {
                SprintNumber = sprintNum,
                Items = sprintItems,
                TotalHours = Math.Round(sprintItems.Sum(i => i.EstimatedHours), 2),
                TotalCost = Math.Round(sprintItems.Sum(i => i.EstimatedCost), 2),
                TotalImpact = sprintItems.Sum(i => i.ImpactPoints),
                ItemCount = sprintItems.Count,
            });
        }

        return sprints;
    }

    // ── Formatters ───────────────────────────────────────────────────

    public static string RenderText(CostReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════════╗");
        sb.AppendLine("  ║     💰  Remediation Cost Estimator              ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════════╝");
        sb.AppendLine();

        // Overview
        sb.AppendLine("  OVERVIEW");
        sb.AppendLine("  ──────────────────────────────────────────────────");
        sb.AppendLine($"  Current Score:     {report.CurrentScore}/100");
        sb.AppendLine($"  Findings:          {report.Items.Count} ({report.CriticalCount} critical, {report.WarningCount} warning, {report.InfoCount} info)");
        sb.AppendLine($"  Auto-fixable:      {report.AutoFixCount}");
        sb.AppendLine($"  Total Est. Hours:  {report.TotalHours:F1}h");
        sb.AppendLine($"  Total Est. Cost:   ${report.TotalCost:N2} (@ ${report.HourlyRate}/hr)");
        sb.AppendLine($"  Overall ROI:       {report.OverallRoi:F1} pts/hr");
        sb.AppendLine();

        // Category breakdown
        sb.AppendLine("  COST BY CATEGORY");
        sb.AppendLine("  ──────────────────────────────────────────────────");
        sb.AppendLine($"  {"Category",-22} {"Items",5} {"Hours",7} {"Cost",10} {"ROI",6}");
        sb.AppendLine($"  {new string('─', 22)} {new string('─', 5)} {new string('─', 7)} {new string('─', 10)} {new string('─', 6)}");
        foreach (var cat in report.CategoryBreakdown)
        {
            sb.AppendLine($"  {cat.Category,-22} {cat.ItemCount,5} {cat.TotalHours,6:F1}h ${cat.TotalCost,8:N2} {cat.AverageRoi,5:F1}");
        }
        sb.AppendLine();

        // Top 10 by ROI
        sb.AppendLine("  TOP 10 BY ROI (best bang for buck)");
        sb.AppendLine("  ──────────────────────────────────────────────────");
        var top = report.Items.Take(10).ToList();
        for (int i = 0; i < top.Count; i++)
        {
            var item = top[i];
            var autoTag = item.HasAutoFix ? " ⚡" : "";
            var sevTag = item.Severity switch
            {
                Severity.Critical => "[CRT]",
                Severity.Warning => "[WRN]",
                Severity.Info => "[INF]",
                _ => "[---]"
            };
            sb.AppendLine($"  {i + 1,3}. {sevTag} {item.Title}{autoTag}");
            sb.AppendLine($"       {item.EstimatedHours:F2}h | ${item.EstimatedCost:N2} | +{item.ImpactPoints}pts | ROI {item.Roi:F1}");
        }
        sb.AppendLine();

        // Sprint plan
        if (report.Sprints.Count > 0)
        {
            sb.AppendLine("  SPRINT PLAN");
            sb.AppendLine("  ──────────────────────────────────────────────────");
            foreach (var sprint in report.Sprints)
            {
                sb.AppendLine($"  Sprint {sprint.SprintNumber}: {sprint.ItemCount} items | {sprint.TotalHours:F1}h | ${sprint.TotalCost:N2} | +{sprint.TotalImpact}pts");
                foreach (var item in sprint.Items)
                {
                    var autoTag = item.HasAutoFix ? " ⚡" : "";
                    sb.AppendLine($"    • {item.Title}{autoTag} ({item.EstimatedHours:F2}h)");
                }
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    public static string RenderJson(CostReport report)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(report, jsonOptions);
    }

    public static string RenderCsv(CostReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Id,Title,Category,Severity,Hours,Cost,ImpactPts,ROI,AutoFix");
        foreach (var item in report.Items)
        {
            var title = item.Title.Contains(',') ? $"\"{item.Title}\"" : item.Title;
            sb.AppendLine($"{item.Id},{title},{item.Category},{item.Severity},{item.EstimatedHours:F2},{item.EstimatedCost:F2},{item.ImpactPoints},{item.Roi:F2},{item.HasAutoFix}");
        }
        return sb.ToString();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static double GetBaseHours(string category)
    {
        return CategoryBaseHours.TryGetValue(category, out var hours) ? hours : DefaultBaseHours;
    }
}

// ── Models ───────────────────────────────────────────────────────────

public class CostOptions
{
    /// <summary>Hourly rate in USD for cost estimation.</summary>
    public int HourlyRate { get; set; } = 85;

    /// <summary>Hours available per sprint for sprint planning.</summary>
    public double SprintHours { get; set; } = 4.0;
}

public class CostReport
{
    public DateTimeOffset GeneratedAt { get; set; }
    public int HourlyRate { get; set; }
    public int CurrentScore { get; set; }
    public List<CostItem> Items { get; set; } = [];
    public double TotalHours { get; set; }
    public double TotalCost { get; set; }
    public int TotalImpactPoints { get; set; }
    public double OverallRoi { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int AutoFixCount { get; set; }
    public List<CategoryCost> CategoryBreakdown { get; set; } = [];
    public List<SprintPlan> Sprints { get; set; } = [];
}

public class CostItem
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Category { get; set; } = "";

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity Severity { get; set; }

    public double EstimatedHours { get; set; }
    public double EstimatedCost { get; set; }
    public int ImpactPoints { get; set; }

    /// <summary>Score points gained per hour spent — higher is better.</summary>
    public double Roi { get; set; }

    public bool HasAutoFix { get; set; }
    public string? Remediation { get; set; }
    public string? FixCommand { get; set; }
}

public class CategoryCost
{
    public string Category { get; set; } = "";
    public int ItemCount { get; set; }
    public double TotalHours { get; set; }
    public double TotalCost { get; set; }
    public int TotalImpact { get; set; }
    public double AverageRoi { get; set; }
}

public class SprintPlan
{
    public int SprintNumber { get; set; }
    public List<CostItem> Items { get; set; } = [];
    public double TotalHours { get; set; }
    public double TotalCost { get; set; }
    public int TotalImpact { get; set; }
    public int ItemCount { get; set; }
}
