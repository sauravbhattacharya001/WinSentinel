using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a prioritized remediation plan from security audit results.
/// Groups findings into Quick Wins (automated or trivial), Medium Effort
/// (manual but straightforward), and Major Changes (significant work),
/// ordered by impact-to-effort ratio within each group.
/// </summary>
public class RemediationPlanner
{
    /// <summary>
    /// Generate a remediation plan from a security report.
    /// </summary>
    public RemediationPlan GeneratePlan(SecurityReport report)
    {
        var plan = new RemediationPlan
        {
            CurrentScore = report.SecurityScore,
            CurrentGrade = SecurityScorer.GetGrade(report.SecurityScore)
        };

        // Collect actionable findings (Critical and Warning only)
        var actionableFindings = report.Results
            .SelectMany(r => r.Findings.Select(f => (finding: f, category: r.Category)))
            .Where(x => x.finding.Severity is Severity.Critical or Severity.Warning)
            .ToList();

        if (actionableFindings.Count == 0)
        {
            plan.ProjectedScore = plan.CurrentScore;
            plan.ProjectedGrade = plan.CurrentGrade;
            return plan;
        }

        // Classify each finding and compute priority
        var items = new List<RemediationItem>();
        int stepNumber = 0;

        foreach (var (finding, category) in actionableFindings)
        {
            var impact = finding.Severity == Severity.Critical ? 20 : 5;
            var effort = ClassifyEffort(finding);
            var estimatedTime = EstimateTime(effort, finding.Severity);
            var priorityScore = ComputePriority(finding, effort);

            items.Add(new RemediationItem
            {
                Title = finding.Title,
                Description = finding.Description,
                Severity = finding.Severity,
                Category = category,
                Impact = impact,
                Effort = effort,
                EstimatedTime = estimatedTime,
                Remediation = finding.Remediation,
                FixCommand = finding.FixCommand,
                PriorityScore = priorityScore
            });
        }

        // Sort by priority within each effort group
        var quickWins = items
            .Where(i => i.Effort == "QuickWin")
            .OrderByDescending(i => i.PriorityScore)
            .ToList();

        var medium = items
            .Where(i => i.Effort == "Medium")
            .OrderByDescending(i => i.PriorityScore)
            .ToList();

        var major = items
            .Where(i => i.Effort == "Major")
            .OrderByDescending(i => i.PriorityScore)
            .ToList();

        // Assign step numbers: quick wins first, then medium, then major
        foreach (var item in quickWins.Concat(medium).Concat(major))
        {
            item.StepNumber = ++stepNumber;
        }

        plan.QuickWins = quickWins;
        plan.MediumEffort = medium;
        plan.MajorChanges = major;

        // Calculate projected score
        var totalImpact = items.Sum(i => i.Impact);
        plan.ProjectedScore = Math.Min(100, plan.CurrentScore + totalImpact);
        plan.ProjectedGrade = SecurityScorer.GetGrade(plan.ProjectedScore);

        return plan;
    }

    /// <summary>
    /// Classify a finding's remediation effort level.
    /// </summary>
    public static string ClassifyEffort(Finding finding)
    {
        // Quick Win: has an automated fix command
        if (!string.IsNullOrWhiteSpace(finding.FixCommand))
        {
            return "QuickWin";
        }

        // Quick Win: simple config/setting changes (heuristic based on remediation text)
        if (!string.IsNullOrWhiteSpace(finding.Remediation))
        {
            var remediation = finding.Remediation.ToLowerInvariant();

            // Quick wins: enable/disable settings, run a command
            if (IsQuickWinRemediation(remediation))
            {
                return "QuickWin";
            }

            // Major: requires installation, policy changes, infrastructure work
            if (IsMajorRemediation(remediation))
            {
                return "Major";
            }
        }

        // Default: medium effort for warnings, major for criticals without auto-fix
        return finding.Severity == Severity.Critical ? "Major" : "Medium";
    }

    /// <summary>
    /// Estimate time to complete based on effort and severity.
    /// </summary>
    public static string EstimateTime(string effort, Severity severity)
    {
        return effort switch
        {
            "QuickWin" => severity == Severity.Critical ? "2-5 min" : "1-3 min",
            "Medium" => severity == Severity.Critical ? "15-30 min" : "5-15 min",
            "Major" => severity == Severity.Critical ? "1-2 hours" : "30-60 min",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Compute a priority score for ordering.
    /// Higher score = should be fixed first.
    /// Factors: severity (critical > warning), auto-fixability, impact-to-effort ratio.
    /// </summary>
    public static double ComputePriority(Finding finding, string effort)
    {
        double score = 0;

        // Severity weight
        score += finding.Severity == Severity.Critical ? 100 : 50;

        // Auto-fix bonus (much faster to apply)
        if (!string.IsNullOrWhiteSpace(finding.FixCommand))
        {
            score += 30;
        }

        // Effort-to-impact ratio bonus
        var effortMultiplier = effort switch
        {
            "QuickWin" => 3.0,
            "Medium" => 1.5,
            "Major" => 1.0,
            _ => 1.0
        };
        score *= effortMultiplier;

        // Remediation available bonus
        if (!string.IsNullOrWhiteSpace(finding.Remediation))
        {
            score += 10;
        }

        return score;
    }

    /// <summary>
    /// Check if remediation text suggests a quick win (settings toggle, simple command).
    /// </summary>
    private static bool IsQuickWinRemediation(string remediation)
    {
        var quickPatterns = new[]
        {
            "enable", "disable", "turn on", "turn off",
            "set-", "get-", "set ", "toggle",
            "settings >", "settings >", "check the",
            "open settings", "group policy", "gpedit",
            "registry", "regedit", "reg add",
            "right-click", "properties"
        };

        return quickPatterns.Any(p => remediation.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Check if remediation text suggests major effort (installations, infrastructure).
    /// </summary>
    private static bool IsMajorRemediation(string remediation)
    {
        var majorPatterns = new[]
        {
            "install ", "deploy", "migrate", "upgrade",
            "third-party", "3rd party", "purchase",
            "enterprise", "infrastructure", "architecture",
            "redesign", "replace", "overhaul",
            "contact your administrator", "it department"
        };

        return majorPatterns.Any(p => remediation.Contains(p, StringComparison.OrdinalIgnoreCase));
    }
}
