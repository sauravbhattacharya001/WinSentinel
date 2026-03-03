using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Models;

public class FixResultTests
{
    #region Factory Methods

    [Fact]
    public void Succeeded_SetsAllProperties()
    {
        var result = FixResult.Succeeded("cmd", "output", TimeSpan.FromSeconds(2), "Fix Title");
        Assert.True(result.Success);
        Assert.Equal("cmd", result.Command);
        Assert.Equal("output", result.Output);
        Assert.Equal(TimeSpan.FromSeconds(2), result.Duration);
        Assert.Equal("Fix Title", result.FindingTitle);
        Assert.False(result.DryRun);
        Assert.Null(result.Error);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void Succeeded_DefaultFindingTitle_Empty()
    {
        var result = FixResult.Succeeded("cmd", "out", TimeSpan.Zero);
        Assert.Equal("", result.FindingTitle);
    }

    [Fact]
    public void Failed_SetsAllProperties()
    {
        var result = FixResult.Failed("cmd", "err", TimeSpan.FromMilliseconds(500), 42, "Broken Fix");
        Assert.False(result.Success);
        Assert.Equal("cmd", result.Command);
        Assert.Equal("err", result.Error);
        Assert.Equal(TimeSpan.FromMilliseconds(500), result.Duration);
        Assert.Equal(42, result.ExitCode);
        Assert.Equal("Broken Fix", result.FindingTitle);
        Assert.False(result.DryRun);
    }

    [Fact]
    public void Failed_DefaultExitCode_Is1()
    {
        var result = FixResult.Failed("cmd", "err", TimeSpan.Zero);
        Assert.Equal(1, result.ExitCode);
    }

    [Fact]
    public void Failed_DefaultFindingTitle_Empty()
    {
        var result = FixResult.Failed("cmd", "err", TimeSpan.Zero);
        Assert.Equal("", result.FindingTitle);
    }

    [Fact]
    public void DryRunResult_SetsProperties()
    {
        var result = FixResult.DryRunResult("Set-ExecutionPolicy Restricted", "PS Exec Policy");
        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Equal("Set-ExecutionPolicy Restricted", result.Command);
        Assert.Equal("PS Exec Policy", result.FindingTitle);
        Assert.Contains("[DRY RUN]", result.Output);
        Assert.Contains("Set-ExecutionPolicy Restricted", result.Output);
    }

    [Fact]
    public void DryRunResult_DefaultFindingTitle_Empty()
    {
        var result = FixResult.DryRunResult("cmd");
        Assert.Equal("", result.FindingTitle);
    }

    [Fact]
    public void NoFixAvailable_SetsProperties()
    {
        var result = FixResult.NoFixAvailable("Unresolvable Finding");
        Assert.False(result.Success);
        Assert.Equal("Unresolvable Finding", result.FindingTitle);
        Assert.Contains("No fix command available", result.Error!);
    }

    #endregion

    #region ToString

    [Fact]
    public void ToString_DryRun_ShowsDryRunPrefix()
    {
        var result = FixResult.DryRunResult("net stop wuauserv");
        Assert.StartsWith("[DRY RUN]", result.ToString());
        Assert.Contains("net stop wuauserv", result.ToString());
    }

    [Fact]
    public void ToString_Success_ShowsOK()
    {
        var result = FixResult.Succeeded("cmd", "Fixed", TimeSpan.Zero, "Firewall");
        Assert.StartsWith("[OK]", result.ToString());
        Assert.Contains("Firewall", result.ToString());
        Assert.Contains("Fixed", result.ToString());
    }

    [Fact]
    public void ToString_Failure_ShowsFail()
    {
        var result = FixResult.Failed("cmd", "Access denied", TimeSpan.Zero, 5, "Defender");
        Assert.StartsWith("[FAIL]", result.ToString());
        Assert.Contains("Defender", result.ToString());
        Assert.Contains("Access denied", result.ToString());
    }

    #endregion

    #region Property Defaults

    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var result = new FixResult();
        Assert.False(result.Success);
        Assert.Equal("", result.Output);
        Assert.Null(result.Error);
        Assert.Equal("", result.Command);
        Assert.False(result.DryRun);
        Assert.False(result.RequiredElevation);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(TimeSpan.Zero, result.Duration);
        Assert.Equal("", result.FindingTitle);
    }

    [Fact]
    public void RequiredElevation_CanBeSet()
    {
        var result = FixResult.Succeeded("cmd", "ok", TimeSpan.Zero);
        result.RequiredElevation = true;
        Assert.True(result.RequiredElevation);
    }

    #endregion
}

public class SecurityReportTests
{
    private static AuditResult MakeAuditResult(string module, params Severity[] severities)
    {
        return new AuditResult
        {
            ModuleName = module,
            Category = module,
            Findings = severities.Select((s, i) => new Finding
            {
                Title = $"{module} Finding {i}",
                Description = $"Description {i}",
                Severity = s,
                Category = module
            }).ToList()
        };
    }

    #region Computed Properties

    [Fact]
    public void TotalFindings_SumsAcrossResults()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("A", Severity.Critical, Severity.Warning),
                MakeAuditResult("B", Severity.Info),
                MakeAuditResult("C", Severity.Pass, Severity.Pass, Severity.Warning)
            }
        };
        Assert.Equal(6, report.TotalFindings);
    }

    [Fact]
    public void TotalCritical_CountsOnlyCritical()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("A", Severity.Critical, Severity.Critical, Severity.Warning),
                MakeAuditResult("B", Severity.Info, Severity.Critical)
            }
        };
        Assert.Equal(3, report.TotalCritical);
    }

    [Fact]
    public void TotalWarnings_CountsOnlyWarnings()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("A", Severity.Warning, Severity.Warning),
                MakeAuditResult("B", Severity.Critical, Severity.Warning)
            }
        };
        Assert.Equal(3, report.TotalWarnings);
    }

    [Fact]
    public void TotalInfo_CountsOnlyInfo()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("A", Severity.Info, Severity.Info, Severity.Info),
                MakeAuditResult("B", Severity.Warning)
            }
        };
        Assert.Equal(3, report.TotalInfo);
    }

    [Fact]
    public void TotalPass_CountsOnlyPass()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("A", Severity.Pass, Severity.Pass),
                MakeAuditResult("B", Severity.Critical, Severity.Pass)
            }
        };
        Assert.Equal(3, report.TotalPass);
    }

    [Fact]
    public void EmptyReport_AllZeros()
    {
        var report = new SecurityReport();
        Assert.Equal(0, report.TotalFindings);
        Assert.Equal(0, report.TotalCritical);
        Assert.Equal(0, report.TotalWarnings);
        Assert.Equal(0, report.TotalInfo);
        Assert.Equal(0, report.TotalPass);
    }

    [Fact]
    public void EmptyResults_AllZeros()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new AuditResult { ModuleName = "Empty", Category = "Empty" }
            }
        };
        Assert.Equal(0, report.TotalFindings);
    }

    #endregion

    #region Default Values

    [Fact]
    public void DefaultResults_IsEmptyList()
    {
        var report = new SecurityReport();
        Assert.NotNull(report.Results);
        Assert.Empty(report.Results);
    }

    [Fact]
    public void GeneratedAt_IsSet()
    {
        var before = DateTimeOffset.UtcNow;
        var report = new SecurityReport();
        Assert.True(report.GeneratedAt >= before);
    }

    [Fact]
    public void SecurityScore_DefaultIsZero()
    {
        var report = new SecurityReport();
        Assert.Equal(0, report.SecurityScore);
    }

    [Fact]
    public void SecurityScore_CanBeSet()
    {
        var report = new SecurityReport { SecurityScore = 85 };
        Assert.Equal(85, report.SecurityScore);
    }

    #endregion

    #region Mixed Severity Scenarios

    [Fact]
    public void AllSeverities_CountedCorrectly()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("Mixed",
                    Severity.Critical,
                    Severity.Warning,
                    Severity.Info,
                    Severity.Pass)
            }
        };
        Assert.Equal(4, report.TotalFindings);
        Assert.Equal(1, report.TotalCritical);
        Assert.Equal(1, report.TotalWarnings);
        Assert.Equal(1, report.TotalInfo);
        Assert.Equal(1, report.TotalPass);
    }

    [Fact]
    public void MultipleResults_SumsCorrectly()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                MakeAuditResult("R1", Severity.Critical, Severity.Critical),
                MakeAuditResult("R2", Severity.Warning, Severity.Warning, Severity.Warning),
                MakeAuditResult("R3", Severity.Info),
                MakeAuditResult("R4", Severity.Pass, Severity.Pass, Severity.Pass, Severity.Pass)
            }
        };
        Assert.Equal(10, report.TotalFindings);
        Assert.Equal(2, report.TotalCritical);
        Assert.Equal(3, report.TotalWarnings);
        Assert.Equal(1, report.TotalInfo);
        Assert.Equal(4, report.TotalPass);
    }

    #endregion
}

public class RemediationPlanTests
{
    private static RemediationItem MakeItem(string title, Severity severity,
        string effort, string? fixCommand = null, int impact = 5)
    {
        return new RemediationItem
        {
            Title = title,
            Severity = severity,
            Effort = effort,
            FixCommand = fixCommand,
            Impact = impact,
            Category = "Test"
        };
    }

    #region Computed Properties

    [Fact]
    public void TotalImpact_IsProjectedMinusCurrent()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 55,
            ProjectedScore = 90
        };
        Assert.Equal(35, plan.TotalImpact);
    }

    [Fact]
    public void TotalImpact_CanBeNegative()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 90,
            ProjectedScore = 85
        };
        Assert.Equal(-5, plan.TotalImpact);
    }

    [Fact]
    public void TotalImpact_ZeroWhenEqual()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 70,
            ProjectedScore = 70
        };
        Assert.Equal(0, plan.TotalImpact);
    }

    [Fact]
    public void TotalItems_SumsAllCategories()
    {
        var plan = new RemediationPlan
        {
            QuickWins = new List<RemediationItem>
            {
                MakeItem("QW1", Severity.Warning, "QuickWin"),
                MakeItem("QW2", Severity.Info, "QuickWin")
            },
            MediumEffort = new List<RemediationItem>
            {
                MakeItem("ME1", Severity.Warning, "Medium")
            },
            MajorChanges = new List<RemediationItem>
            {
                MakeItem("MC1", Severity.Critical, "Major"),
                MakeItem("MC2", Severity.Critical, "Major"),
                MakeItem("MC3", Severity.Warning, "Major")
            }
        };
        Assert.Equal(6, plan.TotalItems);
    }

    [Fact]
    public void TotalItems_ZeroWhenEmpty()
    {
        var plan = new RemediationPlan();
        Assert.Equal(0, plan.TotalItems);
    }

    [Fact]
    public void AutoFixableCount_CountsItemsWithFixCommand()
    {
        var plan = new RemediationPlan
        {
            QuickWins = new List<RemediationItem>
            {
                MakeItem("QW1", Severity.Warning, "QuickWin", fixCommand: "Set-NetFirewallProfile -Enabled True"),
                MakeItem("QW2", Severity.Info, "QuickWin")
            },
            MediumEffort = new List<RemediationItem>
            {
                MakeItem("ME1", Severity.Warning, "Medium", fixCommand: "Enable-BitLocker")
            },
            MajorChanges = new List<RemediationItem>
            {
                MakeItem("MC1", Severity.Critical, "Major")
            }
        };
        Assert.Equal(2, plan.AutoFixableCount);
    }

    [Fact]
    public void AutoFixableCount_ZeroWhenNoFixCommands()
    {
        var plan = new RemediationPlan
        {
            QuickWins = new List<RemediationItem>
            {
                MakeItem("QW1", Severity.Warning, "QuickWin")
            }
        };
        Assert.Equal(0, plan.AutoFixableCount);
    }

    #endregion

    #region Default Values

    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var plan = new RemediationPlan();
        Assert.Equal(0, plan.CurrentScore);
        Assert.Equal("", plan.CurrentGrade);
        Assert.Equal(0, plan.ProjectedScore);
        Assert.Equal("", plan.ProjectedGrade);
        Assert.NotNull(plan.QuickWins);
        Assert.NotNull(plan.MediumEffort);
        Assert.NotNull(plan.MajorChanges);
        Assert.Empty(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Empty(plan.MajorChanges);
    }

    [Fact]
    public void GeneratedAt_IsRecent()
    {
        var before = DateTimeOffset.UtcNow;
        var plan = new RemediationPlan();
        Assert.True(plan.GeneratedAt >= before.AddSeconds(-1));
    }

    #endregion
}

public class RemediationItemTests
{
    [Fact]
    public void HasAutoFix_True_WhenFixCommandSet()
    {
        var item = new RemediationItem { FixCommand = "Set-ExecutionPolicy Restricted" };
        Assert.True(item.HasAutoFix);
    }

    [Fact]
    public void HasAutoFix_False_WhenFixCommandNull()
    {
        var item = new RemediationItem { FixCommand = null };
        Assert.False(item.HasAutoFix);
    }

    [Fact]
    public void HasAutoFix_False_WhenFixCommandEmpty()
    {
        var item = new RemediationItem { FixCommand = "" };
        Assert.False(item.HasAutoFix);
    }

    [Fact]
    public void HasAutoFix_False_WhenFixCommandWhitespace()
    {
        var item = new RemediationItem { FixCommand = "   " };
        Assert.False(item.HasAutoFix);
    }

    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var item = new RemediationItem();
        Assert.Equal(0, item.StepNumber);
        Assert.Equal("", item.Title);
        Assert.Equal("", item.Description);
        Assert.Equal("", item.Category);
        Assert.Equal(0, item.Impact);
        Assert.Equal("", item.Effort);
        Assert.Equal("", item.EstimatedTime);
        Assert.Null(item.Remediation);
        Assert.Null(item.FixCommand);
        Assert.Equal(0.0, item.PriorityScore);
    }

    [Fact]
    public void AllPropertiesSettable()
    {
        var item = new RemediationItem
        {
            StepNumber = 3,
            Title = "Enable Firewall",
            Description = "Windows Firewall is disabled",
            Severity = Severity.Critical,
            Category = "Network",
            Impact = 15,
            Effort = "QuickWin",
            EstimatedTime = "< 5 min",
            Remediation = "Enable via Control Panel",
            FixCommand = "Set-NetFirewallProfile -All -Enabled True",
            PriorityScore = 95.5
        };
        Assert.Equal(3, item.StepNumber);
        Assert.Equal("Enable Firewall", item.Title);
        Assert.Equal(Severity.Critical, item.Severity);
        Assert.Equal(15, item.Impact);
        Assert.True(item.HasAutoFix);
        Assert.Equal(95.5, item.PriorityScore);
    }
}

public class ComplianceResultTests
{
    private static ComplianceProfile MakeProfile(int threshold = 70)
    {
        return new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test Profile",
            Description = "Test",
            ComplianceThreshold = threshold
        };
    }

    [Fact]
    public void IsCompliant_True_WhenScoreAboveThreshold()
    {
        var result = new ComplianceResult
        {
            Profile = MakeProfile(70),
            AdjustedScore = 85
        };
        Assert.True(result.IsCompliant);
    }

    [Fact]
    public void IsCompliant_True_WhenScoreEqualsThreshold()
    {
        var result = new ComplianceResult
        {
            Profile = MakeProfile(70),
            AdjustedScore = 70
        };
        Assert.True(result.IsCompliant);
    }

    [Fact]
    public void IsCompliant_False_WhenScoreBelowThreshold()
    {
        var result = new ComplianceResult
        {
            Profile = MakeProfile(70),
            AdjustedScore = 69
        };
        Assert.False(result.IsCompliant);
    }

    [Fact]
    public void ComplianceThreshold_DelegatesToProfile()
    {
        var result = new ComplianceResult
        {
            Profile = MakeProfile(85),
            AdjustedScore = 80
        };
        Assert.Equal(85, result.ComplianceThreshold);
        Assert.False(result.IsCompliant);
    }

    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var profile = MakeProfile();
        var result = new ComplianceResult { Profile = profile };
        Assert.Equal(0, result.OriginalScore);
        Assert.Equal(0, result.AdjustedScore);
        Assert.Equal("", result.OriginalGrade);
        Assert.Equal("", result.AdjustedGrade);
        Assert.Equal(0, result.OverridesApplied);
        Assert.Equal(0, result.ModulesSkipped);
        Assert.Equal(0, result.ModulesWeighted);
        Assert.NotNull(result.ModuleScores);
        Assert.NotNull(result.AppliedOverrides);
        Assert.NotNull(result.Recommendations);
    }

    [Fact]
    public void ComplianceThreshold_ZeroMeansAlwaysCompliant()
    {
        var result = new ComplianceResult
        {
            Profile = MakeProfile(0),
            AdjustedScore = 0
        };
        Assert.True(result.IsCompliant);
    }

    [Fact]
    public void ComplianceThreshold_100RequiresPerfectScore()
    {
        var result99 = new ComplianceResult
        {
            Profile = MakeProfile(100),
            AdjustedScore = 99
        };
        Assert.False(result99.IsCompliant);

        var result100 = new ComplianceResult
        {
            Profile = MakeProfile(100),
            AdjustedScore = 100
        };
        Assert.True(result100.IsCompliant);
    }
}

public class SeverityOverrideTests
{
    [Fact]
    public void ParameterlessConstructor_DefaultValues()
    {
        var so = new SeverityOverride();
        Assert.Equal(default(Severity), so.NewSeverity);
        Assert.Equal("", so.Reason);
    }

    [Fact]
    public void ParameterizedConstructor_SetsProperties()
    {
        var so = new SeverityOverride(Severity.Critical, "Upgraded for enterprise");
        Assert.Equal(Severity.Critical, so.NewSeverity);
        Assert.Equal("Upgraded for enterprise", so.Reason);
    }
}

public class ComplianceProfileTests
{
    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test profile"
        };
        Assert.Equal("", profile.TargetAudience);
        Assert.NotNull(profile.ModuleWeights);
        Assert.Empty(profile.ModuleWeights);
        Assert.NotNull(profile.SeverityOverrides);
        Assert.Empty(profile.SeverityOverrides);
        Assert.NotNull(profile.SkippedModules);
        Assert.Empty(profile.SkippedModules);
        Assert.Equal(70, profile.ComplianceThreshold);
        Assert.NotNull(profile.Recommendations);
        Assert.Empty(profile.Recommendations);
    }

    [Fact]
    public void SkippedModules_CaseInsensitive()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
            SkippedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "EventLog"
            }
        };
        Assert.Contains("eventlog", profile.SkippedModules);
        Assert.Contains("EVENTLOG", profile.SkippedModules);
    }
}

public class ModuleComplianceScoreTests
{
    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var score = new ModuleComplianceScore();
        Assert.Equal("", score.Category);
        Assert.Equal(0, score.OriginalScore);
        Assert.Equal(1.0, score.Weight);
        Assert.False(score.Skipped);
        Assert.Equal(0, score.FindingCount);
        Assert.Equal(0, score.OverridesInModule);
    }
}

public class AppliedOverrideTests
{
    [Fact]
    public void DefaultProperties_HaveExpectedValues()
    {
        var ao = new AppliedOverride();
        Assert.Equal("", ao.FindingTitle);
        Assert.Equal("", ao.Reason);
        Assert.Equal("", ao.ModuleCategory);
    }

    [Fact]
    public void AllPropertiesSettable()
    {
        var ao = new AppliedOverride
        {
            FindingTitle = "Firewall Disabled",
            OriginalSeverity = Severity.Warning,
            NewSeverity = Severity.Critical,
            Reason = "Enterprise requirement",
            ModuleCategory = "Network"
        };
        Assert.Equal("Firewall Disabled", ao.FindingTitle);
        Assert.Equal(Severity.Warning, ao.OriginalSeverity);
        Assert.Equal(Severity.Critical, ao.NewSeverity);
        Assert.Equal("Enterprise requirement", ao.Reason);
    }
}
