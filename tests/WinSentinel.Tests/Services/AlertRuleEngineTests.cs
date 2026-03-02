using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.AlertRuleEngine;

namespace WinSentinel.Tests.Services;

public class AlertRuleEngineTests
{
    private readonly AlertRuleEngine _engine = new();

    // ── Test helpers ─────────────────────────────────────────────

    private static SecurityReport MakeReport(int score, params AuditResult[] results)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = results.ToList(),
        };
    }

    private static AuditResult MakeModule(string name, string category, params Finding[] findings)
    {
        return new AuditResult
        {
            ModuleName = name,
            Category = category,
            Findings = findings.ToList(),
        };
    }

    // ── ScoreBelow ───────────────────────────────────────────────

    [Fact]
    public void ScoreBelow_Fires_WhenScoreUnderThreshold()
    {
        var rule = new AlertRule
        {
            Id = "r1",
            Name = "Low score",
            Condition = ConditionType.ScoreBelow,
            Threshold = 70,
        };
        var report = MakeReport(65);

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Single(result.Alerts);
        Assert.Equal("r1", result.Alerts[0].RuleId);
        Assert.Equal(65, result.Alerts[0].ActualValue);
        Assert.Equal(70, result.Alerts[0].ThresholdValue);
    }

    [Fact]
    public void ScoreBelow_DoesNotFire_WhenScoreAtThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreBelow,
            Threshold = 70,
        };
        var report = MakeReport(70);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void ScoreBelow_DoesNotFire_WhenScoreAboveThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreBelow,
            Threshold = 50,
        };
        var report = MakeReport(85);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    // ── ScoreDropExceeds ─────────────────────────────────────────

    [Fact]
    public void ScoreDropExceeds_Fires_WhenDropExceedsThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreDropExceeds,
            Threshold = 10,
            Priority = AlertPriority.High,
        };
        var prev = MakeReport(85);
        var curr = MakeReport(70);

        var result = _engine.Evaluate([rule], curr, prev);

        Assert.True(result.HasAlerts);
        Assert.Equal(15, result.Alerts[0].ActualValue);
        Assert.Contains("85", result.Alerts[0].Message);
        Assert.Contains("70", result.Alerts[0].Message);
    }

    [Fact]
    public void ScoreDropExceeds_DoesNotFire_WhenDropEqualsThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreDropExceeds,
            Threshold = 10,
        };
        var prev = MakeReport(80);
        var curr = MakeReport(70);

        var result = _engine.Evaluate([rule], curr, prev);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void ScoreDropExceeds_DoesNotFire_WithoutPreviousReport()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreDropExceeds,
            Threshold = 5,
        };
        var curr = MakeReport(50);

        var result = _engine.Evaluate([rule], curr);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void ScoreDropExceeds_DoesNotFire_WhenScoreImproved()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreDropExceeds,
            Threshold = 5,
        };
        var prev = MakeReport(60);
        var curr = MakeReport(80);

        var result = _engine.Evaluate([rule], curr, prev);

        Assert.False(result.HasAlerts);
    }

    // ── SeverityCountExceeds ─────────────────────────────────────

    [Fact]
    public void SeverityCountExceeds_Fires_WhenCountExceedsThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.SeverityCountExceeds,
            TargetSeverity = Severity.Critical,
            Threshold = 2,
            Priority = AlertPriority.Critical,
        };
        var report = MakeReport(50,
            MakeModule("Firewall", "Network",
                Finding.Critical("FW1", "Open port 22", "Network"),
                Finding.Critical("FW2", "Open port 3389", "Network"),
                Finding.Critical("FW3", "No rules", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Equal(3, result.Alerts[0].ActualValue);
        Assert.Equal(3, result.Alerts[0].MatchedFindings.Count);
    }

    [Fact]
    public void SeverityCountExceeds_DoesNotFire_WhenAtThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.SeverityCountExceeds,
            TargetSeverity = Severity.Warning,
            Threshold = 2,
        };
        var report = MakeReport(80,
            MakeModule("System", "System",
                Finding.Warning("W1", "Check1", "System"),
                Finding.Warning("W2", "Check2", "System")));

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void SeverityCountExceeds_DefaultsToSeverityCritical()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.SeverityCountExceeds,
            // TargetSeverity not set, should default to Critical
            Threshold = 0,
        };
        var report = MakeReport(80,
            MakeModule("System", "System",
                Finding.Critical("C1", "Critical thing", "System")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
    }

    // ── ModuleScoreBelow ─────────────────────────────────────────

    [Fact]
    public void ModuleScoreBelow_Fires_WhenModuleScoreLow()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleScoreBelow,
            ModuleName = "Firewall",
            Threshold = 60,
        };
        // 4 critical findings = 80 penalty = score 20
        var report = MakeReport(50,
            MakeModule("Firewall", "Network",
                Finding.Critical("F1", "Issue1", "Network"),
                Finding.Critical("F2", "Issue2", "Network"),
                Finding.Critical("F3", "Issue3", "Network"),
                Finding.Critical("F4", "Issue4", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Equal(20, result.Alerts[0].ActualValue);
    }

    [Fact]
    public void ModuleScoreBelow_DoesNotFire_WhenModuleNotFound()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleScoreBelow,
            ModuleName = "NonExistent",
            Threshold = 60,
        };
        var report = MakeReport(80,
            MakeModule("Firewall", "Network"));

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void ModuleScoreBelow_CaseInsensitiveModuleName()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleScoreBelow,
            ModuleName = "firewall",
            Threshold = 100,  // 1 warning = score 95, which is < 100
        };
        var report = MakeReport(80,
            MakeModule("Firewall", "Network",
                Finding.Warning("W1", "Issue", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
    }

    [Fact]
    public void ModuleScoreBelow_DoesNotFire_WhenModuleNameNull()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleScoreBelow,
            ModuleName = null,
            Threshold = 50,
        };
        var report = MakeReport(40);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    // ── NewFindingsExceed ────────────────────────────────────────

    [Fact]
    public void NewFindingsExceed_Fires_WhenNewFindingsOverThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.NewFindingsExceed,
            Threshold = 1,
        };
        var prev = MakeReport(90,
            MakeModule("System", "System",
                Finding.Info("Old1", "Already known", "System")));
        var curr = MakeReport(80,
            MakeModule("System", "System",
                Finding.Info("Old1", "Already known", "System"),
                Finding.Warning("New1", "New issue 1", "System"),
                Finding.Warning("New2", "New issue 2", "System")));

        var result = _engine.Evaluate([rule], curr, prev);

        Assert.True(result.HasAlerts);
        Assert.Equal(2, result.Alerts[0].ActualValue);
        Assert.Contains("New1", result.Alerts[0].MatchedFindings);
        Assert.Contains("New2", result.Alerts[0].MatchedFindings);
    }

    [Fact]
    public void NewFindingsExceed_DoesNotFire_WithoutPreviousReport()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.NewFindingsExceed,
            Threshold = 0,
        };
        var curr = MakeReport(80,
            MakeModule("System", "System",
                Finding.Warning("W1", "Issue", "System")));

        var result = _engine.Evaluate([rule], curr);

        Assert.False(result.HasAlerts);
    }

    // ── FindingPatternMatch ──────────────────────────────────────

    [Fact]
    public void FindingPatternMatch_MatchesTitle()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = "open port",
        };
        var report = MakeReport(80,
            MakeModule("Firewall", "Network",
                Finding.Warning("Open Port 22", "SSH exposed", "Network"),
                Finding.Warning("Open Port 3389", "RDP exposed", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Equal(2, result.Alerts[0].MatchedFindings.Count);
    }

    [Fact]
    public void FindingPatternMatch_MatchesDescription()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = "elevated",
        };
        var report = MakeReport(80,
            MakeModule("Process", "System",
                Finding.Warning("Suspicious Process", "Running with elevated privileges", "System")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Contains("Suspicious Process", result.Alerts[0].MatchedFindings);
    }

    [Fact]
    public void FindingPatternMatch_CaseInsensitive()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = "FIREWALL",
        };
        var report = MakeReport(80,
            MakeModule("FW", "Network",
                Finding.Warning("Firewall disabled", "Windows firewall is off", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
    }

    [Fact]
    public void FindingPatternMatch_DoesNotFire_WhenNoMatch()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = "ransomware",
        };
        var report = MakeReport(80,
            MakeModule("System", "System",
                Finding.Info("Update available", "KB12345 pending", "System")));

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void FindingPatternMatch_DoesNotFire_WhenPatternNull()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = null,
        };
        var report = MakeReport(80,
            MakeModule("System", "System",
                Finding.Warning("Anything", "Description", "System")));

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void FindingPatternMatch_DeduplicatesMatchedFindings()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.FindingPatternMatch,
            Pattern = "ssl",
        };
        var report = MakeReport(80,
            MakeModule("Net1", "Network",
                Finding.Warning("SSL Weak", "Old SSL cipher", "Network")),
            MakeModule("Net2", "Network",
                Finding.Warning("SSL Weak", "Old SSL cipher", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        // Deduplicated by title
        Assert.Single(result.Alerts[0].MatchedFindings);
    }

    // ── GradeAtOrBelow ───────────────────────────────────────────

    [Fact]
    public void GradeAtOrBelow_Fires_WhenGradeMatchesThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.GradeAtOrBelow,
            GradeThreshold = "D",
        };
        // Score 65 = D
        var report = MakeReport(65);

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Contains("D", result.Alerts[0].Message);
    }

    [Fact]
    public void GradeAtOrBelow_Fires_WhenGradeBelowThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.GradeAtOrBelow,
            GradeThreshold = "C",
        };
        // Score 55 = F (wait, 55 is D)
        // D is below C
        var report = MakeReport(55);

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
    }

    [Fact]
    public void GradeAtOrBelow_DoesNotFire_WhenGradeAboveThreshold()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.GradeAtOrBelow,
            GradeThreshold = "D",
        };
        // Score 85 = B
        var report = MakeReport(85);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    // ── ModuleHasCritical ────────────────────────────────────────

    [Fact]
    public void ModuleHasCritical_Fires_WhenModuleHasCriticalFindings()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleHasCritical,
            ModuleName = "Firewall",
            Priority = AlertPriority.Critical,
        };
        var report = MakeReport(60,
            MakeModule("Firewall", "Network",
                Finding.Critical("FW disabled", "Firewall is off", "Network"),
                Finding.Warning("FW rule", "Permissive rule", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.True(result.HasAlerts);
        Assert.Single(result.Alerts[0].MatchedFindings);
        Assert.Contains("FW disabled", result.Alerts[0].MatchedFindings);
    }

    [Fact]
    public void ModuleHasCritical_DoesNotFire_WhenNoCriticals()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleHasCritical,
            ModuleName = "Firewall",
        };
        var report = MakeReport(80,
            MakeModule("Firewall", "Network",
                Finding.Warning("Minor issue", "Not critical", "Network")));

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void ModuleHasCritical_DoesNotFire_WhenModuleNotFound()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ModuleHasCritical,
            ModuleName = "NonExistent",
        };
        var report = MakeReport(80);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    // ── Disabled rules ───────────────────────────────────────────

    [Fact]
    public void DisabledRule_IsSkipped()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreBelow,
            Threshold = 100,
            Enabled = false,
        };
        var report = MakeReport(50);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
        Assert.Equal(0, result.RulesEvaluated);
    }

    // ── Multiple rules ───────────────────────────────────────────

    [Fact]
    public void MultipleRules_AllEvaluatedIndependently()
    {
        var rules = new List<AlertRule>
        {
            new() { Id = "r1", Condition = ConditionType.ScoreBelow, Threshold = 70 },
            new() { Id = "r2", Condition = ConditionType.ScoreBelow, Threshold = 50 },
            new() { Id = "r3", Condition = ConditionType.ScoreBelow, Threshold = 30 },
        };
        var report = MakeReport(45);

        var result = _engine.Evaluate(rules, report);

        Assert.Equal(3, result.RulesEvaluated);
        Assert.Equal(2, result.RulesFired); // r1 and r2 fire, r3 does not
    }

    // ── Rule groups ──────────────────────────────────────────────

    [Fact]
    public void GroupAnd_Fires_WhenAllRulesFire()
    {
        var group = new AlertRuleGroup
        {
            Id = "g1",
            Name = "Critical state",
            Operator = GroupOperator.And,
            Rules =
            [
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 50 },
                new AlertRule
                {
                    Condition = ConditionType.SeverityCountExceeds,
                    TargetSeverity = Severity.Critical,
                    Threshold = 0,
                },
            ],
        };
        var report = MakeReport(30,
            MakeModule("FW", "Network",
                Finding.Critical("Issue", "Bad", "Network")));

        var result = _engine.EvaluateGroup(group, report);

        Assert.NotNull(result);
        Assert.Contains("Critical state", result.RuleName);
    }

    [Fact]
    public void GroupAnd_DoesNotFire_WhenOnlyOneRuleFires()
    {
        var group = new AlertRuleGroup
        {
            Operator = GroupOperator.And,
            Rules =
            [
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 50 },
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 20 },
            ],
        };
        var report = MakeReport(30);

        var result = _engine.EvaluateGroup(group, report);

        Assert.Null(result);
    }

    [Fact]
    public void GroupOr_Fires_WhenAnyRuleFires()
    {
        var group = new AlertRuleGroup
        {
            Id = "g2",
            Name = "Any problem",
            Operator = GroupOperator.Or,
            Rules =
            [
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 20 },
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 80 },
            ],
        };
        var report = MakeReport(50);

        var result = _engine.EvaluateGroup(group, report);

        Assert.NotNull(result);
    }

    [Fact]
    public void GroupOr_DoesNotFire_WhenNoRuleFires()
    {
        var group = new AlertRuleGroup
        {
            Operator = GroupOperator.Or,
            Rules =
            [
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 20 },
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 30 },
            ],
        };
        var report = MakeReport(50);

        var result = _engine.EvaluateGroup(group, report);

        Assert.Null(result);
    }

    [Fact]
    public void DisabledGroup_ReturnsNull()
    {
        var group = new AlertRuleGroup
        {
            Enabled = false,
            Rules =
            [
                new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 100 },
            ],
        };
        var report = MakeReport(10);

        var result = _engine.EvaluateGroup(group, report);

        Assert.Null(result);
    }

    [Fact]
    public void EmptyGroup_ReturnsNull()
    {
        var group = new AlertRuleGroup { Rules = [] };
        var report = MakeReport(10);

        var result = _engine.EvaluateGroup(group, report);

        Assert.Null(result);
    }

    // ── EvaluateAll ──────────────────────────────────────────────

    [Fact]
    public void EvaluateAll_CombinesRulesAndGroups()
    {
        var rules = new[]
        {
            new AlertRule
            {
                Id = "r1",
                Condition = ConditionType.ScoreBelow,
                Threshold = 60,
            },
        };
        var groups = new[]
        {
            new AlertRuleGroup
            {
                Id = "g1",
                Name = "group1",
                Operator = GroupOperator.Or,
                Rules =
                [
                    new AlertRule
                    {
                        Condition = ConditionType.FindingPatternMatch,
                        Pattern = "firewall",
                    },
                ],
            },
        };
        var report = MakeReport(50,
            MakeModule("FW", "Network",
                Finding.Warning("Firewall off", "Firewall is disabled", "Network")));

        var result = _engine.EvaluateAll(rules, groups, report);

        Assert.Equal(2, result.RulesFired);
        Assert.Equal(2, result.RulesEvaluated);
    }

    // ── Serialization ────────────────────────────────────────────

    [Fact]
    public void SerializeRules_RoundTrips()
    {
        var rules = new List<AlertRule>
        {
            new()
            {
                Id = "test1",
                Name = "Test Rule",
                Condition = ConditionType.ScoreBelow,
                Threshold = 70,
                Priority = AlertPriority.High,
            },
        };

        var json = AlertRuleEngine.SerializeRules(rules);
        var deserialized = AlertRuleEngine.DeserializeRules(json);

        Assert.Single(deserialized);
        Assert.Equal("test1", deserialized[0].Id);
        Assert.Equal(ConditionType.ScoreBelow, deserialized[0].Condition);
        Assert.Equal(70, deserialized[0].Threshold);
        Assert.Equal(AlertPriority.High, deserialized[0].Priority);
    }

    [Fact]
    public void SerializeGroups_RoundTrips()
    {
        var groups = new List<AlertRuleGroup>
        {
            new()
            {
                Id = "g1",
                Name = "Test Group",
                Operator = GroupOperator.And,
                Rules =
                [
                    new AlertRule { Condition = ConditionType.ScoreBelow, Threshold = 50 },
                ],
            },
        };

        var json = AlertRuleEngine.SerializeGroups(groups);
        var deserialized = AlertRuleEngine.DeserializeGroups(json);

        Assert.Single(deserialized);
        Assert.Equal("g1", deserialized[0].Id);
        Assert.Equal(GroupOperator.And, deserialized[0].Operator);
        Assert.Single(deserialized[0].Rules);
    }

    [Fact]
    public void DeserializeRules_EmptyJson_ReturnsEmptyList()
    {
        var result = AlertRuleEngine.DeserializeRules("[]");
        Assert.Empty(result);
    }

    // ── Default rules ────────────────────────────────────────────

    [Fact]
    public void DefaultRules_AreValid()
    {
        var defaults = AlertRuleEngine.DefaultRules();
        Assert.True(defaults.Count >= 5);
        Assert.All(defaults, r =>
        {
            Assert.NotEmpty(r.Id);
            Assert.NotEmpty(r.Name);
            Assert.True(r.Enabled);
        });
    }

    [Fact]
    public void DefaultRules_FireOnBadReport()
    {
        var defaults = AlertRuleEngine.DefaultRules();
        var report = MakeReport(35,
            MakeModule("FW", "Network",
                Finding.Critical("C1", "Issue1", "Network"),
                Finding.Critical("C2", "Issue2", "Network"),
                Finding.Critical("C3", "Issue3", "Network"),
                Finding.Critical("C4", "Issue4", "Network")));

        var result = _engine.Evaluate(defaults, report);

        // Score 35 < 40 (critical) and < 70 (warning) and grade F ≤ F
        Assert.True(result.HasAlerts);
        Assert.True(result.RulesFired >= 3);
    }

    [Fact]
    public void DefaultRules_QuietOnGoodReport()
    {
        var defaults = AlertRuleEngine.DefaultRules();
        var report = MakeReport(95,
            MakeModule("System", "System",
                Finding.Pass("All good", "Nothing wrong", "System")));

        var result = _engine.Evaluate(defaults, report);

        Assert.False(result.HasAlerts);
    }

    // ── EvaluationResult ─────────────────────────────────────────

    [Fact]
    public void EvaluationResult_Summary_NoAlerts()
    {
        var result = new EvaluationResult();
        Assert.Equal("No alerts triggered.", result.Summary());
        Assert.Null(result.HighestPriority);
    }

    [Fact]
    public void EvaluationResult_HighestPriority_IsCorrect()
    {
        var result = new EvaluationResult
        {
            Alerts =
            [
                new AlertResult { Priority = AlertPriority.Low },
                new AlertResult { Priority = AlertPriority.Critical },
                new AlertResult { Priority = AlertPriority.Medium },
            ],
        };

        Assert.Equal(AlertPriority.Critical, result.HighestPriority);
    }

    [Fact]
    public void EvaluationResult_Summary_ShowsPriorityCounts()
    {
        var result = new EvaluationResult
        {
            Alerts =
            [
                new AlertResult { Priority = AlertPriority.Critical },
                new AlertResult { Priority = AlertPriority.Critical },
                new AlertResult { Priority = AlertPriority.Medium },
            ],
        };

        var summary = result.Summary();
        Assert.Contains("3 alert(s)", summary);
        Assert.Contains("Critical", summary);
        Assert.Contains("Medium", summary);
    }

    // ── Priority setting ─────────────────────────────────────────

    [Fact]
    public void AlertResult_InheritsPriorityFromRule()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.ScoreBelow,
            Threshold = 80,
            Priority = AlertPriority.Low,
        };
        var report = MakeReport(50);

        var result = _engine.Evaluate([rule], report);

        Assert.Equal(AlertPriority.Low, result.Alerts[0].Priority);
    }

    // ── Edge cases ───────────────────────────────────────────────

    [Fact]
    public void Evaluate_EmptyRuleList_ReturnsNoAlerts()
    {
        var result = _engine.Evaluate(Array.Empty<AlertRule>(), MakeReport(50));

        Assert.False(result.HasAlerts);
        Assert.Equal(0, result.RulesEvaluated);
    }

    [Fact]
    public void Evaluate_EmptyReport_HandledGracefully()
    {
        var rule = new AlertRule
        {
            Condition = ConditionType.SeverityCountExceeds,
            TargetSeverity = Severity.Critical,
            Threshold = 0,
        };
        var report = MakeReport(100);

        var result = _engine.Evaluate([rule], report);

        Assert.False(result.HasAlerts);
    }

    [Fact]
    public void GroupAnd_SkipsDisabledSubRules()
    {
        var group = new AlertRuleGroup
        {
            Operator = GroupOperator.And,
            Rules =
            [
                new AlertRule
                {
                    Condition = ConditionType.ScoreBelow,
                    Threshold = 80,
                    Enabled = true,
                },
                new AlertRule
                {
                    Condition = ConditionType.ScoreBelow,
                    Threshold = 20,
                    Enabled = false,
                },
            ],
        };
        // Only 1 enabled rule, and it fires — group should fire
        var report = MakeReport(50);

        var result = _engine.EvaluateGroup(group, report);

        Assert.NotNull(result);
    }
}
