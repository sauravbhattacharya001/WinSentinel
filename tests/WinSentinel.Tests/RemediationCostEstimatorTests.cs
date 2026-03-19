using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

public class RemediationCostEstimatorTests
{
    private static SecurityReport MakeReport(params Finding[] findings)
    {
        var report = new SecurityReport { SecurityScore = 55 };
        var result = new AuditResult { ModuleName = "TestModule", Category = "Firewall" };
        result.Findings.AddRange(findings);
        report.Results.Add(result);
        return report;
    }

    [Fact]
    public void Estimate_EmptyReport_ReturnsEmptyCostReport()
    {
        var estimator = new RemediationCostEstimator();
        var report = new SecurityReport { SecurityScore = 100 };
        var result = estimator.Estimate(report);

        Assert.Empty(result.Items);
        Assert.Equal(0, result.TotalHours);
        Assert.Equal(0, result.TotalCost);
        Assert.Empty(result.Sprints);
    }

    [Fact]
    public void Estimate_CriticalFinding_HigherCostThanWarning()
    {
        var estimator = new RemediationCostEstimator();

        var critReport = MakeReport(
            Finding.Critical("Crit", "desc", "Firewall"));
        var warnReport = MakeReport(
            Finding.Warning("Warn", "desc", "Firewall"));

        var critCost = estimator.Estimate(critReport);
        var warnCost = estimator.Estimate(warnReport);

        Assert.True(critCost.Items[0].EstimatedHours > warnCost.Items[0].EstimatedHours);
        Assert.True(critCost.Items[0].EstimatedCost > warnCost.Items[0].EstimatedCost);
    }

    [Fact]
    public void Estimate_AutoFixReducesCost()
    {
        var estimator = new RemediationCostEstimator();

        var manualReport = MakeReport(
            Finding.Warning("Manual", "desc", "Firewall"));
        var autoReport = MakeReport(
            Finding.Warning("Auto", "desc", "Firewall", fixCommand: "Set-NetFirewallProfile -Enabled True"));

        var manual = estimator.Estimate(manualReport);
        var auto = estimator.Estimate(autoReport);

        Assert.True(auto.Items[0].EstimatedHours < manual.Items[0].EstimatedHours);
        Assert.True(auto.Items[0].HasAutoFix);
        Assert.False(manual.Items[0].HasAutoFix);
    }

    [Fact]
    public void Estimate_PassFindingsAreExcluded()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(
            Finding.Pass("Good", "all fine", "Firewall"),
            Finding.Warning("Bad", "not fine", "Firewall"));

        var result = estimator.Estimate(report);
        Assert.Single(result.Items);
        Assert.Equal("Bad", result.Items[0].Title);
    }

    [Fact]
    public void Estimate_RoiCalculation()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(
            Finding.Critical("High ROI", "desc", "Defender", fixCommand: "Enable-MpProtection"));

        var result = estimator.Estimate(report);
        var item = result.Items[0];

        // ROI = ImpactPoints / EstimatedHours
        Assert.True(item.Roi > 0);
        Assert.Equal(5, item.ImpactPoints); // Critical = 5 pts
    }

    [Fact]
    public void Estimate_SprintPlanGenerated()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(
            Finding.Critical("A", "desc", "Firewall"),
            Finding.Warning("B", "desc", "Network"),
            Finding.Warning("C", "desc", "Defender"),
            Finding.Info("D", "desc", "System"));

        var result = estimator.Estimate(report, new CostOptions { SprintHours = 1.0 });

        Assert.NotEmpty(result.Sprints);
        Assert.True(result.Sprints.All(s => s.ItemCount > 0));
    }

    [Fact]
    public void Estimate_CustomHourlyRate()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(Finding.Warning("Test", "desc", "Firewall"));

        var cheap = estimator.Estimate(report, new CostOptions { HourlyRate = 50 });
        var expensive = estimator.Estimate(report, new CostOptions { HourlyRate = 200 });

        Assert.Equal(cheap.Items[0].EstimatedHours, expensive.Items[0].EstimatedHours);
        Assert.True(expensive.Items[0].EstimatedCost > cheap.Items[0].EstimatedCost);
    }

    [Fact]
    public void Estimate_CategoryBreakdownGenerated()
    {
        var estimator = new RemediationCostEstimator();
        var report = new SecurityReport { SecurityScore = 50 };

        var fwResult = new AuditResult { ModuleName = "FirewallAudit", Category = "Firewall" };
        fwResult.Findings.Add(Finding.Warning("FW issue", "desc", "Firewall"));
        report.Results.Add(fwResult);

        var netResult = new AuditResult { ModuleName = "NetworkAudit", Category = "Network" };
        netResult.Findings.Add(Finding.Critical("Net issue", "desc", "Network"));
        report.Results.Add(netResult);

        var result = estimator.Estimate(report);
        Assert.Equal(2, result.CategoryBreakdown.Count);
    }

    [Fact]
    public void RenderText_DoesNotThrow()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(
            Finding.Critical("A", "desc", "Firewall"),
            Finding.Warning("B", "desc", "Network"));
        var costReport = estimator.Estimate(report);

        var text = RemediationCostEstimator.RenderText(costReport);
        Assert.Contains("Remediation Cost Estimator", text);
        Assert.Contains("SPRINT PLAN", text);
    }

    [Fact]
    public void RenderJson_ValidJson()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(Finding.Warning("Test", "desc", "Firewall"));
        var costReport = estimator.Estimate(report);

        var json = RemediationCostEstimator.RenderJson(costReport);
        Assert.Contains("\"TotalHours\"", json);
    }

    [Fact]
    public void RenderCsv_HasHeader()
    {
        var estimator = new RemediationCostEstimator();
        var report = MakeReport(Finding.Warning("Test", "desc", "Firewall"));
        var costReport = estimator.Estimate(report);

        var csv = RemediationCostEstimator.RenderCsv(costReport);
        Assert.StartsWith("Id,Title,Category", csv);
    }
}
