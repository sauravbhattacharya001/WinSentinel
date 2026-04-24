namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Security Negotiator — simulates a negotiation between security hardening
/// and operational convenience to produce a phased implementation "deal".
/// </summary>
public class SecurityNegotiatorService
{
    private readonly AuditHistoryService _history;

    public SecurityNegotiatorService(AuditHistoryService history)
    {
        _history = history;
    }

    public NegotiationResult Negotiate(int days, string strategy, int phases)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count == 0) return new NegotiationResult { Strategy = strategy };

        var latestRun = runs[0];

        // Build negotiation items with effort/impact scoring
        var items = new List<NegotiationItem>();
        var moduleGroups = latestRun.Findings.GroupBy(f => f.ModuleName);

        foreach (var group in moduleGroups)
        {
            foreach (var finding in group)
            {
                var impact = SeverityToImpact(finding.Severity);
                var effort = EstimateEffort(finding);
                var freq = CountRecurrence(finding.Title, runs);
                var adjustedImpact = Math.Min(10, impact + (freq > 3 ? 2 : freq > 1 ? 1 : 0));

                var priority = CalculatePriority(adjustedImpact, effort, strategy);

                items.Add(new NegotiationItem
                {
                    Module = group.Key,
                    Finding = finding.Title,
                    Severity = finding.Severity,
                    EffortScore = effort,
                    ImpactScore = adjustedImpact,
                    Priority = Math.Round(priority, 2),
                    Recommendation = GenerateRecommendation(finding, strategy),
                    Compromise = GenerateCompromise(finding, strategy)
                });
            }
        }

        // Sort by priority descending
        items = items.OrderByDescending(i => i.Priority).ToList();

        // Split into phases
        var phaseList = SplitIntoPhases(items, phases, strategy);

        // Calculate current score
        var currentScore = (double)latestRun.OverallScore;

        // Generate compromises per module
        var compromises = GenerateModuleCompromises(items, strategy);

        // Generate deal terms
        var dealTerms = GenerateDealTerms(items, strategy, currentScore);

        // Build summary
        var quickWins = items.Count(i => i.EffortScore <= 3 && i.ImpactScore >= 6);
        var deferred = items.Count(i => i.Priority < 3);
        var acceptedRisks = items.Count(i => i.ImpactScore <= 3);

        return new NegotiationResult
        {
            Strategy = strategy,
            TotalFindings = items.Count,
            SecurityScore = Math.Round(currentScore, 1),
            ProjectedScore = Math.Round(Math.Min(100, currentScore + EstimateScoreGain(items, strategy)), 1),
            Phases = phaseList,
            Compromises = compromises,
            DealTerms = dealTerms,
            Summary = new NegotiationSummary
            {
                QuickWins = quickWins,
                DeferredItems = deferred,
                AcceptedRisks = acceptedRisks,
                EstimatedEffort = Math.Round(items.Sum(i => i.EffortScore * 0.5), 1),
                Verdict = GenerateVerdict(currentScore, items.Count, quickWins, strategy),
                ProactiveRecommendations = GenerateProactiveRecommendations(items, currentScore, strategy)
            }
        };
    }

    private static double SeverityToImpact(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 9.5,
        "warning" => 7.0,
        "info" => 3.0,
        _ => 5.0
    };

    private static double EstimateEffort(FindingRecord finding)
    {
        var hasRemediation = !string.IsNullOrWhiteSpace(finding.Remediation);
        var baseEffort = finding.Severity.ToLowerInvariant() switch
        {
            "critical" => 7.0,
            "warning" => 5.0,
            "info" => 2.0,
            _ => 4.0
        };
        return hasRemediation ? Math.Max(1, baseEffort - 2) : baseEffort;
    }

    private static int CountRecurrence(string title, List<AuditRunRecord> runs)
    {
        return runs.Count(r => r.Findings.Any(f =>
            string.Equals(f.Title, title, StringComparison.OrdinalIgnoreCase)));
    }

    private static double CalculatePriority(double impact, double effort, string strategy)
    {
        return strategy switch
        {
            "aggressive" => impact * 1.5 / Math.Max(1, effort * 0.5),
            "conservative" => impact * 0.7 / Math.Max(1, effort * 1.3),
            _ => impact / Math.Max(1, effort) // balanced
        };
    }

    private static string GenerateRecommendation(FindingRecord finding, string strategy)
    {
        if (!string.IsNullOrWhiteSpace(finding.Remediation))
            return strategy == "conservative"
                ? $"Schedule fix: {finding.Remediation}"
                : $"Apply fix now: {finding.Remediation}";

        return finding.Severity.ToLowerInvariant() switch
        {
            "critical" => "Requires immediate manual remediation — assign to security team",
            "warning" => "Plan remediation within next maintenance window",
            _ => "Document and monitor — low urgency"
        };
    }

    private static string GenerateCompromise(FindingRecord finding, string strategy)
    {
        return finding.Severity.ToLowerInvariant() switch
        {
            "critical" when strategy == "conservative" =>
                "Accept 48h remediation window instead of immediate action",
            "critical" =>
                "Immediate fix with rollback plan ready",
            "warning" when strategy == "aggressive" =>
                "Fix in current sprint, no deferral allowed",
            "warning" =>
                "Fix within 2 weeks, temporary mitigation if blocking",
            _ => "Monitor and revisit in next review cycle"
        };
    }

    private static List<NegotiationPhase> SplitIntoPhases(List<NegotiationItem> items, int phases, string strategy)
    {
        var result = new List<NegotiationPhase>();
        if (items.Count == 0) return result;

        var chunkSize = Math.Max(1, (int)Math.Ceiling((double)items.Count / phases));
        var phaseNames = new[] { "Quick Wins", "Steady Progress", "Long-Term Hardening", "Deep Remediation", "Final Polish" };
        var phaseTimelines = new[] { "1-2 days", "1-2 weeks", "1-3 months", "3-6 months", "Ongoing" };

        var runningScore = 0.0;
        for (int p = 0; p < phases; p++)
        {
            var phaseItems = items.Skip(p * chunkSize).Take(chunkSize).ToList();
            if (phaseItems.Count == 0) break;

            var phaseImpact = phaseItems.Sum(i => i.ImpactScore);
            runningScore += phaseImpact * 0.3;

            result.Add(new NegotiationPhase
            {
                PhaseNumber = p + 1,
                Name = phaseNames[Math.Min(p, phaseNames.Length - 1)],
                Description = p switch
                {
                    0 => "High-impact, low-effort items that deliver immediate security gains",
                    1 => "Medium-effort items that strengthen the security posture",
                    2 => "Deeper hardening requiring more planning and resources",
                    3 => "Complex remediation with longer timelines",
                    _ => "Ongoing maintenance and monitoring"
                },
                Items = phaseItems,
                EffortScore = Math.Round(phaseItems.Sum(i => i.EffortScore), 1),
                ImpactScore = Math.Round(phaseImpact, 1),
                ProjectedScoreAfter = Math.Round(runningScore, 1),
                Timeline = phaseTimelines[Math.Min(p, phaseTimelines.Length - 1)]
            });
        }

        return result;
    }

    private static List<NegotiationCompromise> GenerateModuleCompromises(List<NegotiationItem> items, string strategy)
    {
        var compromises = new List<NegotiationCompromise>();
        var modules = items.GroupBy(i => i.Module).Take(6);

        foreach (var module in modules)
        {
            var critCount = module.Count(i => i.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
            var warnCount = module.Count(i => i.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));

            compromises.Add(new NegotiationCompromise
            {
                Area = module.Key,
                SecurityWants = critCount > 0
                    ? $"Fix all {critCount} critical + {warnCount} warnings immediately"
                    : $"Remediate all {warnCount} warnings this sprint",
                OperationsWants = "Minimize downtime and change risk",
                Deal = strategy switch
                {
                    "aggressive" => critCount > 0
                        ? $"Fix {critCount} critical within 24h; warnings within 1 week"
                        : $"Fix all {warnCount} warnings within 1 week",
                    "conservative" => critCount > 0
                        ? $"Fix {critCount} critical within 1 week; defer warnings to next cycle"
                        : $"Fix top {Math.Min(3, warnCount)} warnings; defer rest",
                    _ => critCount > 0
                        ? $"Fix {critCount} critical within 48h; warnings within 2 weeks"
                        : $"Fix top {Math.Min(5, warnCount)} warnings within 2 weeks"
                },
                Rationale = critCount > 0
                    ? "Critical findings represent active risk — urgency justified"
                    : "Warnings are preventive — phased approach reduces operational impact"
            });
        }

        return compromises;
    }

    private static List<string> GenerateDealTerms(List<NegotiationItem> items, string strategy, double currentScore)
    {
        var terms = new List<string>();
        var critCount = items.Count(i => i.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
        var warnCount = items.Count(i => i.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        var infoCount = items.Count(i => i.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase));

        terms.Add(strategy switch
        {
            "aggressive" => "All critical findings must be resolved before any new deployments",
            "conservative" => "Critical findings addressed in next scheduled maintenance window",
            _ => "Critical findings resolved within 48 hours with rollback plans"
        });

        if (warnCount > 0)
        {
            terms.Add(strategy switch
            {
                "aggressive" => $"All {warnCount} warnings resolved within 1 sprint (2 weeks max)",
                "conservative" => $"Top 50% of warnings ({warnCount / 2}) resolved within 1 month",
                _ => $"Warnings triaged by impact — top {Math.Min(10, warnCount)} resolved within 2 weeks"
            });
        }

        if (infoCount > 0)
            terms.Add($"Informational items ({infoCount}) tracked but not blocking — review quarterly");

        terms.Add("Security score target: " + (strategy switch
        {
            "aggressive" => $"reach {Math.Min(100, (int)currentScore + 20)} within 30 days",
            "conservative" => $"reach {Math.Min(100, (int)currentScore + 8)} within 60 days",
            _ => $"reach {Math.Min(100, (int)currentScore + 12)} within 45 days"
        }));

        terms.Add("Automated remediation enabled for findings with known fix commands");
        terms.Add("Re-audit scheduled after each phase completion to verify progress");

        return terms;
    }

    private static double EstimateScoreGain(List<NegotiationItem> items, string strategy)
    {
        var totalImpact = items.Sum(i => i.ImpactScore);
        var factor = strategy switch
        {
            "aggressive" => 0.4,
            "conservative" => 0.2,
            _ => 0.3
        };
        return Math.Min(30, totalImpact * factor / Math.Max(1, items.Count) * 5);
    }

    private static string GenerateVerdict(double score, int findings, int quickWins, string strategy)
    {
        if (findings == 0) return "Clean slate — no findings to negotiate";
        if (score >= 90) return "Strong posture — minor refinements only";
        if (score >= 70) return quickWins > 3
            ? "Good posture with easy gains available — deal favors quick action"
            : "Solid base — steady improvement recommended";
        if (score >= 50) return strategy == "aggressive"
            ? "Moderate risk — aggressive remediation justified"
            : "Room for improvement — phased approach advisable";
        return "Significant gaps — prioritized remediation critical";
    }

    private static List<string> GenerateProactiveRecommendations(List<NegotiationItem> items, double score, string strategy)
    {
        var recs = new List<string>();

        var autoFixable = items.Count(i => i.Recommendation.StartsWith("Apply fix now") || i.Recommendation.StartsWith("Schedule fix"));
        if (autoFixable > 0)
            recs.Add($"Enable auto-remediation for {autoFixable} findings with known fixes — saves ~{autoFixable * 0.5:F0}h manual effort");

        var highImpact = items.Where(i => i.ImpactScore >= 8).ToList();
        if (highImpact.Count > 0)
            recs.Add($"Set up watchdog alerts for {highImpact.Count} high-impact findings to catch regressions early");

        if (score < 70)
            recs.Add("Consider running --mission to generate a goal-oriented improvement plan alongside this negotiation");

        if (items.Count > 20)
            recs.Add("Large finding count detected — use --cluster to group related findings before negotiating");

        var modules = items.Select(i => i.Module).Distinct().Count();
        if (modules > 5)
            recs.Add($"Findings span {modules} modules — assign module owners for accountability in each phase");

        recs.Add("Re-run --negotiate after each phase to adapt the deal based on actual progress");

        return recs;
    }
}

// ── Models ──────────────────────────────────────────────────────────

public class NegotiationResult
{
    public string Strategy { get; set; } = "";
    public int TotalFindings { get; set; }
    public double SecurityScore { get; set; }
    public double ProjectedScore { get; set; }
    public List<NegotiationPhase> Phases { get; set; } = new();
    public List<NegotiationCompromise> Compromises { get; set; } = new();
    public List<string> DealTerms { get; set; } = new();
    public NegotiationSummary Summary { get; set; } = new();
}

public class NegotiationPhase
{
    public int PhaseNumber { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public List<NegotiationItem> Items { get; set; } = new();
    public double EffortScore { get; set; }
    public double ImpactScore { get; set; }
    public double ProjectedScoreAfter { get; set; }
    public string Timeline { get; set; } = "";
}

public class NegotiationItem
{
    public string Module { get; set; } = "";
    public string Finding { get; set; } = "";
    public string Severity { get; set; } = "";
    public double EffortScore { get; set; }
    public double ImpactScore { get; set; }
    public double Priority { get; set; }
    public string Recommendation { get; set; } = "";
    public string Compromise { get; set; } = "";
}

public class NegotiationCompromise
{
    public string Area { get; set; } = "";
    public string SecurityWants { get; set; } = "";
    public string OperationsWants { get; set; } = "";
    public string Deal { get; set; } = "";
    public string Rationale { get; set; } = "";
}

public class NegotiationSummary
{
    public int QuickWins { get; set; }
    public int DeferredItems { get; set; }
    public int AcceptedRisks { get; set; }
    public double EstimatedEffort { get; set; }
    public string Verdict { get; set; } = "";
    public List<string> ProactiveRecommendations { get; set; } = new();
}
