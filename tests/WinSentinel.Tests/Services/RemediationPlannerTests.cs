using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class RemediationPlannerTests
{
    private readonly RemediationPlanner _planner = new();

    // ── Helper Methods ──────────────────────────────────────────────

    private static SecurityReport CreateReport(params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test Category",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };

        foreach (var f in findings)
        {
            result.Findings.Add(f);
        }

        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = [result]
        };
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    private static SecurityReport CreateMultiModuleReport()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var firewall = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall & Network Protection",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        firewall.Findings.Add(Finding.Critical("Firewall Disabled", "Windows Firewall is off",
            "Firewall", "Enable Windows Firewall", "Set-NetFirewallProfile -All -Enabled True"));
        firewall.Findings.Add(Finding.Warning("LLMNR Enabled", "LLMNR protocol is enabled",
            "Firewall", "Disable LLMNR via Group Policy"));
        firewall.Findings.Add(Finding.Pass("Inbound Blocked", "Default inbound action is Block", "Firewall"));

        var defender = new AuditResult
        {
            ModuleName = "DefenderAudit",
            Category = "Windows Defender",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        defender.Findings.Add(Finding.Warning("PUA Protection Off", "Potentially unwanted app protection disabled",
            "Defender", "Enable PUA protection", "Set-MpPreference -PUAProtection Enabled"));
        defender.Findings.Add(Finding.Warning("Definitions Outdated", "Defender definitions are outdated",
            "Defender", "Update definitions", "Update-MpSignature"));

        var accounts = new AuditResult
        {
            ModuleName = "AccountAudit",
            Category = "Accounts & Authentication",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        accounts.Findings.Add(Finding.Critical("Guest Account Active", "Guest account is enabled",
            "Accounts", "Disable the guest account. Contact your administrator or IT department for enterprise policy."));
        accounts.Findings.Add(Finding.Warning("Weak Password Policy", "Min password length is low",
            "Accounts", "Set minimum password length to 12", "net accounts /minpwlen:12"));

        report.Results.AddRange([firewall, defender, accounts]);
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    // ── GeneratePlan Tests ──────────────────────────────────────────

    [Fact]
    public void GeneratePlan_EmptyReport_ReturnsEmptyPlan()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 100
        };

        var plan = _planner.GeneratePlan(report);

        Assert.Equal(0, plan.TotalItems);
        Assert.Empty(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Empty(plan.MajorChanges);
        Assert.Equal(100, plan.CurrentScore);
        Assert.Equal(100, plan.ProjectedScore);
    }

    [Fact]
    public void GeneratePlan_OnlyPassFindings_ReturnsEmptyPlan()
    {
        var report = CreateReport(
            Finding.Pass("All Good", "Everything is fine", "Test"),
            Finding.Info("FYI", "Just an info item", "Test")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Equal(0, plan.TotalItems);
    }

    [Fact]
    public void GeneratePlan_CriticalWithAutoFix_IsQuickWin()
    {
        var report = CreateReport(
            Finding.Critical("Critical Issue", "Something critical",
                "Test", "Fix it", "Fix-Command")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Single(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Empty(plan.MajorChanges);
        Assert.Equal("Critical Issue", plan.QuickWins[0].Title);
        Assert.True(plan.QuickWins[0].HasAutoFix);
    }

    [Fact]
    public void GeneratePlan_WarningWithAutoFix_IsQuickWin()
    {
        var report = CreateReport(
            Finding.Warning("Warning Issue", "Something needs attention",
                "Test", "Enable this feature", "Set-Something -Enabled True")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Single(plan.QuickWins);
        Assert.Equal("Warning Issue", plan.QuickWins[0].Title);
    }

    [Fact]
    public void GeneratePlan_WarningWithoutFix_IsMediumEffort()
    {
        var report = CreateReport(
            Finding.Warning("Manual Warning", "Needs manual investigation", "Test")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Empty(plan.QuickWins);
        Assert.Single(plan.MediumEffort);
        Assert.Equal("Manual Warning", plan.MediumEffort[0].Title);
    }

    [Fact]
    public void GeneratePlan_CriticalWithoutFix_IsMajorChange()
    {
        var report = CreateReport(
            Finding.Critical("Critical No Fix", "Severe issue without auto-fix", "Test")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Empty(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Single(plan.MajorChanges);
        Assert.Equal("Critical No Fix", plan.MajorChanges[0].Title);
    }

    [Fact]
    public void GeneratePlan_MajorRemediation_ClassifiedAsMajor()
    {
        var report = CreateReport(
            Finding.Warning("Third Party Tool", "Need external tool",
                "Test", "Install a third-party security tool to monitor this")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Empty(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Single(plan.MajorChanges);
    }

    [Fact]
    public void GeneratePlan_QuickWinRemediation_ClassifiedAsQuickWin()
    {
        var report = CreateReport(
            Finding.Warning("Settings Toggle", "Feature is off",
                "Test", "Enable this feature in Settings > Privacy > General")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Single(plan.QuickWins);
        Assert.Empty(plan.MediumEffort);
        Assert.Empty(plan.MajorChanges);
    }

    [Fact]
    public void GeneratePlan_CorrectCurrentScore()
    {
        var report = CreateReport(
            Finding.Critical("Issue1", "Desc", "Test", "Fix", "cmd1"),
            Finding.Warning("Issue2", "Desc", "Test")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Equal(report.SecurityScore, plan.CurrentScore);
    }

    [Fact]
    public void GeneratePlan_ProjectedScoreIncreasesAfterFixes()
    {
        var report = CreateReport(
            Finding.Critical("Issue1", "Desc", "Test", "Fix", "cmd1"),
            Finding.Warning("Issue2", "Desc", "Test")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.True(plan.ProjectedScore > plan.CurrentScore);
    }

    [Fact]
    public void GeneratePlan_ProjectedScoreCappedAt100()
    {
        var report = CreateReport(
            Finding.Warning("Small Issue", "Minor thing", "Test", "Fix", "cmd")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.True(plan.ProjectedScore <= 100);
    }

    [Fact]
    public void GeneratePlan_CriticalImpactIs20()
    {
        var report = CreateReport(
            Finding.Critical("Issue", "Desc", "Test", "Fix", "cmd")
        );

        var plan = _planner.GeneratePlan(report);
        var item = plan.QuickWins.Single();

        Assert.Equal(20, item.Impact);
    }

    [Fact]
    public void GeneratePlan_WarningImpactIs5()
    {
        var report = CreateReport(
            Finding.Warning("Issue", "Desc", "Test", "Fix", "cmd")
        );

        var plan = _planner.GeneratePlan(report);
        var item = plan.QuickWins.Single();

        Assert.Equal(5, item.Impact);
    }

    [Fact]
    public void GeneratePlan_StepNumbersAreSequential()
    {
        var report = CreateMultiModuleReport();
        var plan = _planner.GeneratePlan(report);

        var allItems = plan.QuickWins
            .Concat(plan.MediumEffort)
            .Concat(plan.MajorChanges)
            .ToList();

        for (int i = 0; i < allItems.Count; i++)
        {
            Assert.Equal(i + 1, allItems[i].StepNumber);
        }
    }

    [Fact]
    public void GeneratePlan_QuickWinsFirst_ThenMedium_ThenMajor()
    {
        var report = CreateMultiModuleReport();
        var plan = _planner.GeneratePlan(report);

        var allItems = plan.QuickWins
            .Concat(plan.MediumEffort)
            .Concat(plan.MajorChanges)
            .ToList();

        // Verify quick wins come before medium, medium before major
        var lastQuickWinStep = plan.QuickWins.Count > 0 ? plan.QuickWins.Max(i => i.StepNumber) : 0;
        var firstMediumStep = plan.MediumEffort.Count > 0 ? plan.MediumEffort.Min(i => i.StepNumber) : int.MaxValue;
        var lastMediumStep = plan.MediumEffort.Count > 0 ? plan.MediumEffort.Max(i => i.StepNumber) : 0;
        var firstMajorStep = plan.MajorChanges.Count > 0 ? plan.MajorChanges.Min(i => i.StepNumber) : int.MaxValue;

        if (plan.QuickWins.Count > 0 && plan.MediumEffort.Count > 0)
            Assert.True(lastQuickWinStep < firstMediumStep);
        if (plan.MediumEffort.Count > 0 && plan.MajorChanges.Count > 0)
            Assert.True(lastMediumStep < firstMajorStep);
    }

    [Fact]
    public void GeneratePlan_AutoFixableCountIsCorrect()
    {
        var report = CreateMultiModuleReport();
        var plan = _planner.GeneratePlan(report);

        var expectedAutoFix = plan.QuickWins.Count(i => i.HasAutoFix) +
                              plan.MediumEffort.Count(i => i.HasAutoFix) +
                              plan.MajorChanges.Count(i => i.HasAutoFix);

        Assert.Equal(expectedAutoFix, plan.AutoFixableCount);
    }

    [Fact]
    public void GeneratePlan_TotalItemsMatchesSumOfGroups()
    {
        var report = CreateMultiModuleReport();
        var plan = _planner.GeneratePlan(report);

        Assert.Equal(plan.QuickWins.Count + plan.MediumEffort.Count + plan.MajorChanges.Count, plan.TotalItems);
    }

    [Fact]
    public void GeneratePlan_MultiModule_PreservesCategory()
    {
        var report = CreateMultiModuleReport();
        var plan = _planner.GeneratePlan(report);

        var allItems = plan.QuickWins.Concat(plan.MediumEffort).Concat(plan.MajorChanges).ToList();

        Assert.Contains(allItems, i => i.Category == "Firewall & Network Protection");
        Assert.Contains(allItems, i => i.Category == "Windows Defender");
        Assert.Contains(allItems, i => i.Category == "Accounts & Authentication");
    }

    [Fact]
    public void GeneratePlan_HigherPriorityItemsFirst_WithinGroup()
    {
        var report = CreateReport(
            Finding.Critical("Critical AutoFix", "Critical with fix", "Test", "Fix it", "cmd"),
            Finding.Warning("Warning AutoFix", "Warning with fix", "Test", "Fix it", "cmd2")
        );

        var plan = _planner.GeneratePlan(report);

        // Both are quick wins (both have auto-fix), critical should come first
        Assert.True(plan.QuickWins.Count >= 2);
        Assert.Equal(Severity.Critical, plan.QuickWins[0].Severity);
    }

    [Fact]
    public void GeneratePlan_TotalImpactIsCorrect()
    {
        var report = CreateReport(
            Finding.Critical("C1", "Desc", "Test", "Fix", "cmd"),
            Finding.Warning("W1", "Desc", "Test", "Fix", "cmd")
        );

        var plan = _planner.GeneratePlan(report);

        Assert.Equal(25, plan.TotalImpact); // 20 + 5
    }

    // ── ClassifyEffort Tests ────────────────────────────────────────

    [Fact]
    public void ClassifyEffort_WithFixCommand_ReturnsQuickWin()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Fix it", "Some-Command");
        Assert.Equal("QuickWin", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_EnableInRemediation_ReturnsQuickWin()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Enable this feature in settings");
        Assert.Equal("QuickWin", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_SettingsRemediation_ReturnsQuickWin()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Open Settings > Privacy > General");
        Assert.Equal("QuickWin", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_RegistryRemediation_ReturnsQuickWin()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Set registry key via regedit");
        Assert.Equal("QuickWin", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_InstallRemediation_ReturnsMajor()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Install a third-party tool");
        Assert.Equal("Major", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_DeployRemediation_ReturnsMajor()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Deploy new infrastructure");
        Assert.Equal("Major", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_ITDepartmentRemediation_ReturnsMajor()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Contact your administrator or IT department");
        Assert.Equal("Major", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_CriticalNoFix_ReturnsMajor()
    {
        var finding = Finding.Critical("Test", "Desc", "Cat");
        Assert.Equal("Major", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_WarningNoFix_ReturnsMedium()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat");
        Assert.Equal("Medium", RemediationPlanner.ClassifyEffort(finding));
    }

    [Fact]
    public void ClassifyEffort_WarningGenericRemediation_ReturnsMedium()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Review and update your configuration");
        Assert.Equal("Medium", RemediationPlanner.ClassifyEffort(finding));
    }

    // ── EstimateTime Tests ──────────────────────────────────────────

    [Fact]
    public void EstimateTime_QuickWinCritical_Returns2To5Min()
    {
        Assert.Equal("2-5 min", RemediationPlanner.EstimateTime("QuickWin", Severity.Critical));
    }

    [Fact]
    public void EstimateTime_QuickWinWarning_Returns1To3Min()
    {
        Assert.Equal("1-3 min", RemediationPlanner.EstimateTime("QuickWin", Severity.Warning));
    }

    [Fact]
    public void EstimateTime_MediumCritical_Returns15To30Min()
    {
        Assert.Equal("15-30 min", RemediationPlanner.EstimateTime("Medium", Severity.Critical));
    }

    [Fact]
    public void EstimateTime_MediumWarning_Returns5To15Min()
    {
        Assert.Equal("5-15 min", RemediationPlanner.EstimateTime("Medium", Severity.Warning));
    }

    [Fact]
    public void EstimateTime_MajorCritical_Returns1To2Hours()
    {
        Assert.Equal("1-2 hours", RemediationPlanner.EstimateTime("Major", Severity.Critical));
    }

    [Fact]
    public void EstimateTime_MajorWarning_Returns30To60Min()
    {
        Assert.Equal("30-60 min", RemediationPlanner.EstimateTime("Major", Severity.Warning));
    }

    // ── ComputePriority Tests ───────────────────────────────────────

    [Fact]
    public void ComputePriority_CriticalHigherThanWarning()
    {
        var critical = Finding.Critical("Test", "Desc", "Cat");
        var warning = Finding.Warning("Test", "Desc", "Cat");

        var critScore = RemediationPlanner.ComputePriority(critical, "Medium");
        var warnScore = RemediationPlanner.ComputePriority(warning, "Medium");

        Assert.True(critScore > warnScore);
    }

    [Fact]
    public void ComputePriority_AutoFixHigherThanManual()
    {
        var autoFix = Finding.Warning("Test", "Desc", "Cat", "Fix", "cmd");
        var manual = Finding.Warning("Test", "Desc", "Cat");

        var autoScore = RemediationPlanner.ComputePriority(autoFix, "QuickWin");
        var manualScore = RemediationPlanner.ComputePriority(manual, "Medium");

        Assert.True(autoScore > manualScore);
    }

    [Fact]
    public void ComputePriority_QuickWinHigherEffortMultiplier()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat", "Fix");

        var quickScore = RemediationPlanner.ComputePriority(finding, "QuickWin");
        var majorScore = RemediationPlanner.ComputePriority(finding, "Major");

        Assert.True(quickScore > majorScore);
    }

    [Fact]
    public void ComputePriority_WithRemediation_HigherThanWithout()
    {
        var withRem = Finding.Warning("Test", "Desc", "Cat", "Fix it this way");
        var withoutRem = Finding.Warning("Test", "Desc", "Cat");

        var remScore = RemediationPlanner.ComputePriority(withRem, "Medium");
        var noRemScore = RemediationPlanner.ComputePriority(withoutRem, "Medium");

        Assert.True(remScore > noRemScore);
    }

    // ── RemediationItem Property Tests ──────────────────────────────

    [Fact]
    public void RemediationItem_HasAutoFix_TrueWithCommand()
    {
        var item = new RemediationItem { FixCommand = "Some-Command" };
        Assert.True(item.HasAutoFix);
    }

    [Fact]
    public void RemediationItem_HasAutoFix_FalseWithNull()
    {
        var item = new RemediationItem { FixCommand = null };
        Assert.False(item.HasAutoFix);
    }

    [Fact]
    public void RemediationItem_HasAutoFix_FalseWithEmpty()
    {
        var item = new RemediationItem { FixCommand = "" };
        Assert.False(item.HasAutoFix);
    }

    [Fact]
    public void RemediationItem_HasAutoFix_FalseWithWhitespace()
    {
        var item = new RemediationItem { FixCommand = "   " };
        Assert.False(item.HasAutoFix);
    }

    // ── RemediationPlan Property Tests ──────────────────────────────

    [Fact]
    public void RemediationPlan_TotalImpact_Computed()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 60,
            ProjectedScore = 85
        };
        Assert.Equal(25, plan.TotalImpact);
    }

    [Fact]
    public void RemediationPlan_TotalItems_SumsAllGroups()
    {
        var plan = new RemediationPlan();
        plan.QuickWins.Add(new RemediationItem());
        plan.QuickWins.Add(new RemediationItem());
        plan.MediumEffort.Add(new RemediationItem());
        plan.MajorChanges.Add(new RemediationItem());

        Assert.Equal(4, plan.TotalItems);
    }

    [Fact]
    public void RemediationPlan_AutoFixableCount_Computed()
    {
        var plan = new RemediationPlan();
        plan.QuickWins.Add(new RemediationItem { FixCommand = "cmd1" });
        plan.QuickWins.Add(new RemediationItem { FixCommand = null });
        plan.MediumEffort.Add(new RemediationItem { FixCommand = "cmd2" });
        plan.MajorChanges.Add(new RemediationItem { FixCommand = null });

        Assert.Equal(2, plan.AutoFixableCount);
    }
}
