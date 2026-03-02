using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Declarative alert rules engine for security scan results.
/// <para>
/// Users define <see cref="AlertRule"/> objects that are evaluated against
/// a <see cref="SecurityReport"/> (and optionally a previous report for
/// regression detection). When a rule's condition is met, it produces an
/// <see cref="AlertResult"/> describing what triggered and why.
/// </para>
/// <para>
/// Rules support several condition types (score thresholds, severity counts,
/// module regression, new findings, pattern matching) and can be combined
/// via <see cref="AlertRuleGroup"/> with AND/OR logic.
/// </para>
/// </summary>
public class AlertRuleEngine
{
    // ── Rule definitions ─────────────────────────────────────────

    /// <summary>The type of condition a rule checks.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ConditionType
    {
        /// <summary>Overall score drops below a threshold.</summary>
        ScoreBelow,

        /// <summary>Overall score drops by more than N points from the previous scan.</summary>
        ScoreDropExceeds,

        /// <summary>Count of findings at a given severity exceeds a limit.</summary>
        SeverityCountExceeds,

        /// <summary>A specific module's score drops below a threshold.</summary>
        ModuleScoreBelow,

        /// <summary>New findings appeared compared to the previous scan.</summary>
        NewFindingsExceed,

        /// <summary>A finding title or description matches a pattern (case-insensitive substring).</summary>
        FindingPatternMatch,

        /// <summary>Grade is at or below a threshold (e.g. "D" or "F").</summary>
        GradeAtOrBelow,

        /// <summary>A specific module produced any Critical finding.</summary>
        ModuleHasCritical,
    }

    /// <summary>Priority level assigned to a triggered alert.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AlertPriority
    {
        Low,
        Medium,
        High,
        Critical,
    }

    /// <summary>
    /// A single alert rule. Set <see cref="Condition"/> and the relevant
    /// threshold/parameter fields. Irrelevant fields are ignored.
    /// </summary>
    public class AlertRule
    {
        /// <summary>Unique identifier for the rule.</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];

        /// <summary>Human-readable rule name.</summary>
        public string Name { get; set; } = "";

        /// <summary>The condition this rule checks.</summary>
        public ConditionType Condition { get; set; }

        /// <summary>Numeric threshold (meaning depends on <see cref="Condition"/>).</summary>
        public int Threshold { get; set; }

        /// <summary>Severity level for <see cref="ConditionType.SeverityCountExceeds"/>.</summary>
        public Severity? TargetSeverity { get; set; }

        /// <summary>Module name for module-specific conditions.</summary>
        public string? ModuleName { get; set; }

        /// <summary>Pattern string for <see cref="ConditionType.FindingPatternMatch"/>.</summary>
        public string? Pattern { get; set; }

        /// <summary>Minimum grade letter for <see cref="ConditionType.GradeAtOrBelow"/>.</summary>
        public string? GradeThreshold { get; set; }

        /// <summary>Priority assigned when this rule fires.</summary>
        public AlertPriority Priority { get; set; } = AlertPriority.Medium;

        /// <summary>Whether this rule is currently active.</summary>
        public bool Enabled { get; set; } = true;
    }

    /// <summary>How rules in a group are combined.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum GroupOperator
    {
        /// <summary>All rules must fire for the group to fire.</summary>
        And,

        /// <summary>Any rule firing causes the group to fire.</summary>
        Or,
    }

    /// <summary>
    /// Groups multiple rules with AND/OR logic. A group is itself
    /// evaluable, so groups can be used wherever rules can.
    /// </summary>
    public class AlertRuleGroup
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
        public string Name { get; set; } = "";
        public GroupOperator Operator { get; set; } = GroupOperator.And;
        public List<AlertRule> Rules { get; set; } = [];
        public AlertPriority Priority { get; set; } = AlertPriority.High;
        public bool Enabled { get; set; } = true;
    }

    /// <summary>Result of a triggered alert.</summary>
    public class AlertResult
    {
        /// <summary>The rule ID that fired.</summary>
        public string RuleId { get; init; } = "";

        /// <summary>The rule name.</summary>
        public string RuleName { get; init; } = "";

        /// <summary>Human-readable description of what triggered.</summary>
        public string Message { get; init; } = "";

        /// <summary>Alert priority.</summary>
        public AlertPriority Priority { get; init; }

        /// <summary>When the alert was generated.</summary>
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

        /// <summary>The actual value that triggered the threshold (for numeric conditions).</summary>
        public int? ActualValue { get; init; }

        /// <summary>The threshold that was exceeded (for numeric conditions).</summary>
        public int? ThresholdValue { get; init; }

        /// <summary>Matched findings (for pattern/count conditions).</summary>
        public List<string> MatchedFindings { get; init; } = [];
    }

    /// <summary>Complete evaluation result.</summary>
    public class EvaluationResult
    {
        /// <summary>All triggered alerts.</summary>
        public List<AlertResult> Alerts { get; init; } = [];

        /// <summary>Total rules evaluated (including disabled ones skipped).</summary>
        public int RulesEvaluated { get; init; }

        /// <summary>How many rules fired.</summary>
        public int RulesFired => Alerts.Count;

        /// <summary>Whether any alert fired.</summary>
        public bool HasAlerts => Alerts.Count > 0;

        /// <summary>Highest priority among triggered alerts, or null if none.</summary>
        public AlertPriority? HighestPriority =>
            Alerts.Count > 0 ? Alerts.Max(a => a.Priority) : null;

        /// <summary>Human-readable summary.</summary>
        public string Summary()
        {
            if (!HasAlerts)
                return "No alerts triggered.";
            var byPriority = Alerts
                .GroupBy(a => a.Priority)
                .OrderByDescending(g => g.Key)
                .Select(g => $"{g.Count()} {g.Key}")
                .ToList();
            return $"{Alerts.Count} alert(s) triggered: {string.Join(", ", byPriority)}";
        }
    }

    // ── Evaluation ───────────────────────────────────────────────

    /// <summary>
    /// Evaluate a set of rules against a scan report.
    /// </summary>
    /// <param name="rules">Rules to evaluate.</param>
    /// <param name="report">Current scan report.</param>
    /// <param name="previousReport">Optional previous report for regression detection.</param>
    /// <returns>Evaluation result with all triggered alerts.</returns>
    public EvaluationResult Evaluate(
        IEnumerable<AlertRule> rules,
        SecurityReport report,
        SecurityReport? previousReport = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(report);

        var alerts = new List<AlertResult>();
        int evaluated = 0;

        foreach (var rule in rules)
        {
            if (!rule.Enabled) continue;
            evaluated++;
            var result = EvaluateRule(rule, report, previousReport);
            if (result != null)
                alerts.Add(result);
        }

        return new EvaluationResult
        {
            Alerts = alerts,
            RulesEvaluated = evaluated,
        };
    }

    /// <summary>
    /// Evaluate a rule group with AND/OR logic.
    /// </summary>
    public AlertResult? EvaluateGroup(
        AlertRuleGroup group,
        SecurityReport report,
        SecurityReport? previousReport = null)
    {
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(report);

        if (!group.Enabled || group.Rules.Count == 0)
            return null;

        var firedResults = new List<AlertResult>();
        foreach (var rule in group.Rules)
        {
            if (!rule.Enabled) continue;
            var result = EvaluateRule(rule, report, previousReport);
            if (result != null)
                firedResults.Add(result);
        }

        bool groupFired = group.Operator switch
        {
            GroupOperator.And => firedResults.Count == group.Rules.Count(r => r.Enabled),
            GroupOperator.Or => firedResults.Count > 0,
            _ => false,
        };

        if (!groupFired) return null;

        var messages = firedResults.Select(r => r.Message).ToList();
        return new AlertResult
        {
            RuleId = group.Id,
            RuleName = group.Name,
            Message = $"Group '{group.Name}' ({group.Operator}): {string.Join("; ", messages)}",
            Priority = group.Priority,
            MatchedFindings = firedResults.SelectMany(r => r.MatchedFindings).Distinct().ToList(),
        };
    }

    /// <summary>
    /// Evaluate a mixed collection of rules and groups.
    /// </summary>
    public EvaluationResult EvaluateAll(
        IEnumerable<AlertRule> rules,
        IEnumerable<AlertRuleGroup> groups,
        SecurityReport report,
        SecurityReport? previousReport = null)
    {
        var alerts = new List<AlertResult>();
        int evaluated = 0;

        foreach (var rule in rules)
        {
            if (!rule.Enabled) continue;
            evaluated++;
            var result = EvaluateRule(rule, report, previousReport);
            if (result != null)
                alerts.Add(result);
        }

        foreach (var group in groups)
        {
            if (!group.Enabled) continue;
            evaluated++;
            var result = EvaluateGroup(group, report, previousReport);
            if (result != null)
                alerts.Add(result);
        }

        return new EvaluationResult
        {
            Alerts = alerts,
            RulesEvaluated = evaluated,
        };
    }

    // ── Serialization ────────────────────────────────────────────

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Serialize rules to JSON.</summary>
    public static string SerializeRules(IEnumerable<AlertRule> rules)
        => JsonSerializer.Serialize(rules.ToList(), s_jsonOptions);

    /// <summary>Deserialize rules from JSON.</summary>
    public static List<AlertRule> DeserializeRules(string json)
        => JsonSerializer.Deserialize<List<AlertRule>>(json, s_jsonOptions) ?? [];

    /// <summary>Serialize rule groups to JSON.</summary>
    public static string SerializeGroups(IEnumerable<AlertRuleGroup> groups)
        => JsonSerializer.Serialize(groups.ToList(), s_jsonOptions);

    /// <summary>Deserialize rule groups from JSON.</summary>
    public static List<AlertRuleGroup> DeserializeGroups(string json)
        => JsonSerializer.Deserialize<List<AlertRuleGroup>>(json, s_jsonOptions) ?? [];

    // ── Built-in rule presets ────────────────────────────────────

    /// <summary>
    /// Returns a set of sensible default alert rules for common scenarios.
    /// </summary>
    public static List<AlertRule> DefaultRules() =>
    [
        new AlertRule
        {
            Id = "default-score-critical",
            Name = "Score critically low",
            Condition = ConditionType.ScoreBelow,
            Threshold = 40,
            Priority = AlertPriority.Critical,
        },
        new AlertRule
        {
            Id = "default-score-warning",
            Name = "Score below acceptable",
            Condition = ConditionType.ScoreBelow,
            Threshold = 70,
            Priority = AlertPriority.Medium,
        },
        new AlertRule
        {
            Id = "default-score-drop",
            Name = "Score regression",
            Condition = ConditionType.ScoreDropExceeds,
            Threshold = 10,
            Priority = AlertPriority.High,
        },
        new AlertRule
        {
            Id = "default-critical-count",
            Name = "Multiple critical findings",
            Condition = ConditionType.SeverityCountExceeds,
            TargetSeverity = Severity.Critical,
            Threshold = 3,
            Priority = AlertPriority.Critical,
        },
        new AlertRule
        {
            Id = "default-new-findings",
            Name = "New findings appeared",
            Condition = ConditionType.NewFindingsExceed,
            Threshold = 5,
            Priority = AlertPriority.Medium,
        },
        new AlertRule
        {
            Id = "default-grade-fail",
            Name = "Failing grade",
            Condition = ConditionType.GradeAtOrBelow,
            GradeThreshold = "F",
            Priority = AlertPriority.Critical,
        },
    ];

    // ── Private evaluation logic ─────────────────────────────────

    private AlertResult? EvaluateRule(
        AlertRule rule,
        SecurityReport report,
        SecurityReport? previousReport)
    {
        return rule.Condition switch
        {
            ConditionType.ScoreBelow => EvalScoreBelow(rule, report),
            ConditionType.ScoreDropExceeds => EvalScoreDrop(rule, report, previousReport),
            ConditionType.SeverityCountExceeds => EvalSeverityCount(rule, report),
            ConditionType.ModuleScoreBelow => EvalModuleScore(rule, report),
            ConditionType.NewFindingsExceed => EvalNewFindings(rule, report, previousReport),
            ConditionType.FindingPatternMatch => EvalPatternMatch(rule, report),
            ConditionType.GradeAtOrBelow => EvalGrade(rule, report),
            ConditionType.ModuleHasCritical => EvalModuleCritical(rule, report),
            _ => null,
        };
    }

    private static AlertResult? EvalScoreBelow(AlertRule rule, SecurityReport report)
    {
        if (report.SecurityScore >= rule.Threshold) return null;
        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"Security score {report.SecurityScore} is below threshold {rule.Threshold}",
            Priority = rule.Priority,
            ActualValue = report.SecurityScore,
            ThresholdValue = rule.Threshold,
        };
    }

    private static AlertResult? EvalScoreDrop(AlertRule rule, SecurityReport report, SecurityReport? previous)
    {
        if (previous == null) return null;
        int drop = previous.SecurityScore - report.SecurityScore;
        if (drop <= rule.Threshold) return null;
        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"Score dropped by {drop} points ({previous.SecurityScore} → {report.SecurityScore}), exceeds threshold of {rule.Threshold}",
            Priority = rule.Priority,
            ActualValue = drop,
            ThresholdValue = rule.Threshold,
        };
    }

    private static AlertResult? EvalSeverityCount(AlertRule rule, SecurityReport report)
    {
        var severity = rule.TargetSeverity ?? Severity.Critical;
        int count = report.Results
            .SelectMany(r => r.Findings)
            .Count(f => f.Severity == severity);
        if (count <= rule.Threshold) return null;

        var matched = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity == severity)
            .Select(f => f.Title)
            .ToList();

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"{count} {severity} finding(s) exceed threshold of {rule.Threshold}",
            Priority = rule.Priority,
            ActualValue = count,
            ThresholdValue = rule.Threshold,
            MatchedFindings = matched,
        };
    }

    private static AlertResult? EvalModuleScore(AlertRule rule, SecurityReport report)
    {
        if (string.IsNullOrEmpty(rule.ModuleName)) return null;
        var module = report.Results
            .FirstOrDefault(r => r.ModuleName.Equals(rule.ModuleName, StringComparison.OrdinalIgnoreCase));
        if (module == null) return null;

        int score = SecurityScorer.CalculateCategoryScore(module);
        if (score >= rule.Threshold) return null;

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"Module '{rule.ModuleName}' score {score} is below threshold {rule.Threshold}",
            Priority = rule.Priority,
            ActualValue = score,
            ThresholdValue = rule.Threshold,
        };
    }

    private static AlertResult? EvalNewFindings(AlertRule rule, SecurityReport report, SecurityReport? previous)
    {
        if (previous == null) return null;

        var oldTitles = new HashSet<string>(
            previous.Results.SelectMany(r => r.Findings).Select(f => f.Title),
            StringComparer.OrdinalIgnoreCase);

        var newFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => !oldTitles.Contains(f.Title))
            .ToList();

        if (newFindings.Count <= rule.Threshold) return null;

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"{newFindings.Count} new finding(s) exceed threshold of {rule.Threshold}",
            Priority = rule.Priority,
            ActualValue = newFindings.Count,
            ThresholdValue = rule.Threshold,
            MatchedFindings = newFindings.Select(f => f.Title).ToList(),
        };
    }

    private static AlertResult? EvalPatternMatch(AlertRule rule, SecurityReport report)
    {
        if (string.IsNullOrEmpty(rule.Pattern)) return null;

        var matches = report.Results
            .SelectMany(r => r.Findings)
            .Where(f =>
                f.Title.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase)
                || f.Description.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase))
            .Select(f => f.Title)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (matches.Count == 0) return null;

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"{matches.Count} finding(s) match pattern '{rule.Pattern}'",
            Priority = rule.Priority,
            ActualValue = matches.Count,
            MatchedFindings = matches,
        };
    }

    private static readonly Dictionary<string, int> s_gradeRank = new(StringComparer.OrdinalIgnoreCase)
    {
        ["A"] = 5, ["B"] = 4, ["C"] = 3, ["D"] = 2, ["F"] = 1,
    };

    private static AlertResult? EvalGrade(AlertRule rule, SecurityReport report)
    {
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var threshold = rule.GradeThreshold ?? "F";

        if (!s_gradeRank.TryGetValue(grade, out int gradeVal)) gradeVal = 0;
        if (!s_gradeRank.TryGetValue(threshold, out int threshVal)) threshVal = 0;

        if (gradeVal > threshVal) return null;

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"Grade '{grade}' is at or below threshold '{threshold}'",
            Priority = rule.Priority,
        };
    }

    private static AlertResult? EvalModuleCritical(AlertRule rule, SecurityReport report)
    {
        if (string.IsNullOrEmpty(rule.ModuleName)) return null;
        var module = report.Results
            .FirstOrDefault(r => r.ModuleName.Equals(rule.ModuleName, StringComparison.OrdinalIgnoreCase));
        if (module == null) return null;

        var criticals = module.Findings
            .Where(f => f.Severity == Severity.Critical)
            .Select(f => f.Title)
            .ToList();

        if (criticals.Count == 0) return null;

        return new AlertResult
        {
            RuleId = rule.Id,
            RuleName = rule.Name,
            Message = $"Module '{rule.ModuleName}' has {criticals.Count} critical finding(s)",
            Priority = rule.Priority,
            ActualValue = criticals.Count,
            MatchedFindings = criticals,
        };
    }
}
