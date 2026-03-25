using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class PriorityPlannerTests
{
    private static SecurityReport CreateTestReport(params Finding[] findings)
    {
        var result = new AuditResult { ModuleName = "TestModule", Category = "Test" };
        foreach (var f in findings)
            result.Findings.Add(f);

        var report = new SecurityReport();
        report.Results.Add(result);
        return report;
    }

    [Fact]
    public void Generate_EmptyReport_ReturnsEmptyPlan()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport();

        var plan = planner.Generate(report);

        Assert.Empty(plan.Actions);
        Assert.Equal(0, plan.TotalActionsAvailable);
    }

    [Fact]
    public void Generate_SkipsPassAndInfoFindings()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Pass("All good", "Nothing wrong", "General"),
            Finding.Info("FYI", "Informational", "General")
        );

        var plan = planner.Generate(report);

        Assert.Empty(plan.Actions);
    }

    [Fact]
    public void Generate_CriticalRankedAboveWarning()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Warning("Enable audit policy", "Audit policy disabled", "Policy"),
            Finding.Critical("Firewall disabled", "Windows Firewall is off", "Network")
        );

        var plan = planner.Generate(report);

        Assert.Equal(2, plan.Actions.Count);
        Assert.Equal("Firewall disabled", plan.Actions[0].Title);
        Assert.Equal(Severity.Critical, plan.Actions[0].Severity);
    }

    [Fact]
    public void Generate_RespectsMaxActions()
    {
        var planner = new PriorityPlanner();
        var findings = Enumerable.Range(1, 20)
            .Select(i => Finding.Warning($"Finding {i}", $"Desc {i}", "General"))
            .ToArray();
        var report = CreateTestReport(findings);

        var plan = planner.Generate(report, maxActions: 5);

        Assert.Equal(5, plan.Actions.Count);
        Assert.Equal(20, plan.TotalActionsAvailable);
    }

    [Fact]
    public void Generate_IdentifiesQuickWins()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Critical("Enable firewall setting", "Quick config change", "Configuration"),
            Finding.Warning("Install security software", "Needs installation", "General")
        );

        var plan = planner.Generate(report);

        // "Enable" in title -> effort 1.0, Critical -> impact 10.0 -> QuickWin
        var enableAction = plan.Actions.First(a => a.Title.Contains("Enable"));
        Assert.True(enableAction.QuickWin);
    }

    [Fact]
    public void Generate_CalculatesEstimatedTotalMinutes()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Critical("Enable setting A", "Desc", "Config"),
            Finding.Warning("Enable setting B", "Desc", "Config")
        );

        var plan = planner.Generate(report);

        Assert.True(plan.EstimatedTotalMinutes > 0);
    }

    [Fact]
    public void Generate_CategoryBreakdown_HasEntries()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Critical("Firewall port open", "Desc", "Network"),
            Finding.Warning("Account privilege issue", "Desc", "Identity")
        );

        var plan = planner.Generate(report);

        Assert.True(plan.CategoryBreakdown.Count > 0);
    }

    [Fact]
    public void RenderText_ProducesOutput()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Critical("Test finding", "Description", "General")
        );

        var plan = planner.Generate(report);
        var text = PriorityPlanner.RenderText(plan);

        Assert.Contains("SECURITY PRIORITY PLAN", text);
        Assert.Contains("Test finding", text);
    }

    [Fact]
    public void RenderJson_ProducesValidJson()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Warning("Test", "Desc", "General")
        );

        var plan = planner.Generate(report);
        var json = PriorityPlanner.RenderJson(plan);

        Assert.Contains("\"CurrentScore\"", json);
        Assert.Contains("\"Actions\"", json);
    }

    [Fact]
    public void Generate_ExpectedScoreAfter_GreaterThanOrEqualCurrent()
    {
        var planner = new PriorityPlanner();
        var report = CreateTestReport(
            Finding.Critical("Issue A", "Desc", "General"),
            Finding.Warning("Issue B", "Desc", "General")
        );

        var plan = planner.Generate(report);

        Assert.True(plan.ExpectedScoreAfter >= plan.CurrentScore);
    }
}
