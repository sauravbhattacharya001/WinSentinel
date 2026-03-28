using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class RemediationBatchAnalyzerTests
{
    private readonly RemediationBatchAnalyzer _analyzer = new();

    private static SecurityReport MakeReport(params AuditResult[] results) =>
        new() { Results = [.. results], SecurityScore = 50 };

    private static AuditResult MakeAudit(string category, params Finding[] findings) =>
        new() { ModuleName = category + "Audit", Category = category, Findings = [.. findings] };

    [Fact]
    public void Analyze_EmptyReport_ReturnsEmpty()
    {
        var result = _analyzer.Analyze(MakeReport());
        Assert.Empty(result.Batches);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.MinimumActions);
    }

    [Fact]
    public void Analyze_SingleFinding_OneBatch()
    {
        var report = MakeReport(MakeAudit("Firewall",
            Finding.Warning("Port open", "Port 445 open", "Firewall", "Close port 445")));
        var result = _analyzer.Analyze(report);
        Assert.Single(result.Batches);
        Assert.Equal(1, result.TotalFindings);
        Assert.Equal(0, result.ActionsSaved);
    }

    [Fact]
    public void Analyze_SharedRemediation_GroupsTogether()
    {
        var report = MakeReport(
            MakeAudit("Firewall",
                Finding.Warning("Port 445", "Open", "Firewall", "Close unused ports"),
                Finding.Warning("Port 139", "Open", "Firewall", "Close unused ports")),
            MakeAudit("Network",
                Finding.Warning("Port 3389", "Open", "Network", "Close unused ports")));
        var result = _analyzer.Analyze(report, RemediationBatchAnalyzer.GroupingStrategy.ByRemediation);
        var batch = result.Batches.First(b => b.FindingCount > 1);
        Assert.Equal(3, batch.FindingCount);
        Assert.Equal(2, batch.CategoryCount);
    }

    [Fact]
    public void Analyze_SharedFixCommand_GroupsTogether()
    {
        var report = MakeReport(MakeAudit("Services",
            Finding.Warning("Svc1", "desc", "Services", "Stop service", "Stop-Service Svc1"),
            Finding.Warning("Svc2", "desc", "Services", "Stop service", "Stop-Service Svc1")));
        var result = _analyzer.Analyze(report, RemediationBatchAnalyzer.GroupingStrategy.ByFixCommand);
        Assert.Single(result.Batches, b => b.FindingCount > 1);
    }

    [Fact]
    public void Analyze_CombinedStrategy_PrefersFixCommand()
    {
        var report = MakeReport(MakeAudit("Registry",
            Finding.Warning("A", "d", "Registry", "Enable UAC", "reg add HKLM\\..."),
            Finding.Warning("B", "d", "Registry", "Different text", "reg add HKLM\\...")));
        var result = _analyzer.Analyze(report, RemediationBatchAnalyzer.GroupingStrategy.Combined);
        Assert.Contains(result.Batches, b => b.FindingCount == 2);
    }

    [Fact]
    public void TotalImpact_WeighsBySeverity()
    {
        var report = MakeReport(MakeAudit("Firewall",
            Finding.Critical("A", "d", "Firewall", "Fix it"),
            Finding.Warning("B", "d", "Firewall", "Fix it"),
            Finding.Info("C", "d", "Firewall", "Fix it")));
        var result = _analyzer.Analyze(report);
        var batch = result.Batches.First(b => b.FindingCount == 3);
        Assert.Equal(16, batch.TotalImpact);
    }

    [Fact]
    public void MaxSeverity_ReturnsCritical()
    {
        var report = MakeReport(MakeAudit("DNS",
            Finding.Warning("W", "d", "DNS", "Fix DNS"),
            Finding.Critical("C", "d", "DNS", "Fix DNS")));
        var result = _analyzer.Analyze(report);
        Assert.Equal(Severity.Critical, result.Batches.First(b => b.FindingCount == 2).MaxSeverity);
    }

    [Fact]
    public void EfficiencyScore_HigherForMoreFindings()
    {
        var report = MakeReport(
            MakeAudit("A",
                Finding.Warning("1", "d", "A", "Action X"),
                Finding.Warning("2", "d", "A", "Action X"),
                Finding.Warning("3", "d", "A", "Action X")),
            MakeAudit("B",
                Finding.Warning("4", "d", "B", "Action Y")));
        var result = _analyzer.Analyze(report);
        var batchX = result.Batches.First(b => b.Action == "Action X");
        var batchY = result.Batches.First(b => b.Action == "Action Y");
        Assert.True(batchX.EfficiencyScore > batchY.EfficiencyScore);
    }

    [Fact]
    public void ActionsSaved_CalculatedCorrectly()
    {
        var report = MakeReport(MakeAudit("Firewall",
            Finding.Warning("A", "d", "Firewall", "Fix A"),
            Finding.Warning("B", "d", "Firewall", "Fix A"),
            Finding.Warning("C", "d", "Firewall", "Fix B")));
        var result = _analyzer.Analyze(report);
        Assert.Equal(3, result.TotalFindings);
        Assert.Equal(2, result.MinimumActions);
        Assert.Equal(1, result.ActionsSaved);
    }

    [Fact]
    public void BatchablePercent_Correct()
    {
        var report = MakeReport(MakeAudit("Network",
            Finding.Warning("A", "d", "Network", "Shared fix"),
            Finding.Warning("B", "d", "Network", "Shared fix"),
            Finding.Warning("C", "d", "Network", "Unique fix")));
        var result = _analyzer.Analyze(report);
        Assert.True(result.BatchablePercent > 60 && result.BatchablePercent < 70);
    }

    [Fact]
    public void AutomatableBatchCount_CountsFixCommands()
    {
        var report = MakeReport(MakeAudit("Services",
            Finding.Warning("A", "d", "Services", "Fix A", "cmd1"),
            Finding.Warning("B", "d", "Services", "Fix B")));
        var result = _analyzer.Analyze(report);
        Assert.Equal(1, result.AutomatableBatchCount);
    }

    [Fact]
    public void TopOpportunities_ExcludesSingleFindingBatches()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("1", "d", "A", "Shared"),
            Finding.Warning("2", "d", "A", "Shared"),
            Finding.Warning("3", "d", "A", "Unique")));
        var result = _analyzer.Analyze(report);
        Assert.All(result.TopOpportunities(10), b => Assert.True(b.FindingCount > 1));
    }

    [Fact]
    public void OptimalFixOrder_AutomatableFirst()
    {
        var report = MakeReport(
            MakeAudit("A", Finding.Critical("X", "d", "A", "Manual fix")),
            MakeAudit("B", Finding.Warning("Y", "d", "B", "Auto fix", "cmd1")));
        var result = _analyzer.Analyze(report);
        var order = _analyzer.OptimalFixOrder(result);
        Assert.True(order.First().HasFixCommand);
    }

    [Fact]
    public void OptimalFixOrder_SeverityBreaksTie()
    {
        var report = MakeReport(
            MakeAudit("A", Finding.Warning("W", "d", "A", "Fix W", "cmd1")),
            MakeAudit("B", Finding.Critical("C", "d", "B", "Fix C", "cmd2")));
        var result = _analyzer.Analyze(report);
        var order = _analyzer.OptimalFixOrder(result);
        Assert.Equal(Severity.Critical, order.First().MaxSeverity);
    }

    [Fact]
    public void FindOrphans_ReturnsNoRemediationFindings()
    {
        var report = MakeReport(MakeAudit("System",
            Finding.Warning("Has fix", "d", "System", "Do this"),
            Finding.Warning("No fix", "d", "System")));
        var orphans = _analyzer.FindOrphans(report);
        Assert.Single(orphans);
        Assert.Equal("No fix", orphans[0].Title);
    }

    [Fact]
    public void FindOrphans_Empty_WhenAllHaveRemediation()
    {
        var report = MakeReport(MakeAudit("DNS",
            Finding.Warning("A", "d", "DNS", "Fix A")));
        Assert.Empty(_analyzer.FindOrphans(report));
    }

    [Fact]
    public void AnalyzeMultiple_DedupsByTitleAndCategory()
    {
        var r1 = MakeReport(MakeAudit("Firewall",
            Finding.Warning("Port 445", "Open", "Firewall", "Close ports")));
        var r2 = MakeReport(MakeAudit("Firewall",
            Finding.Warning("Port 445", "Open", "Firewall", "Close ports")));
        var result = _analyzer.AnalyzeMultiple([r1, r2]);
        Assert.Equal(1, result.TotalFindings);
    }

    [Fact]
    public void AnalyzeMultiple_MergesAcrossReports()
    {
        var r1 = MakeReport(MakeAudit("Firewall",
            Finding.Warning("Port 445", "Open", "Firewall", "Close ports")));
        var r2 = MakeReport(MakeAudit("Network",
            Finding.Warning("Port 139", "Open", "Network", "Close ports")));
        var result = _analyzer.AnalyzeMultiple([r1, r2]);
        Assert.Equal(2, result.TotalFindings);
        Assert.Contains(result.Batches, b => b.FindingCount == 2);
    }

    [Fact]
    public void GroupsIgnoreCaseAndWhitespace()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("X", "d", "A", "Close Unused Ports"),
            Finding.Warning("Y", "d", "A", "close  unused  ports")));
        var result = _analyzer.Analyze(report, RemediationBatchAnalyzer.GroupingStrategy.ByRemediation);
        Assert.Contains(result.Batches, b => b.FindingCount == 2);
    }

    [Fact]
    public void Analyze_ExcludesPassFindings()
    {
        var report = MakeReport(MakeAudit("System",
            Finding.Pass("Good", "All good", "System", "N/A"),
            Finding.Warning("Bad", "Issue", "System", "Fix it")));
        Assert.Equal(1, _analyzer.Analyze(report).TotalFindings);
    }

    [Fact]
    public void ToSummary_ContainsKeyInfo()
    {
        var report = MakeReport(MakeAudit("Firewall",
            Finding.Critical("A", "d", "Firewall", "Shared fix"),
            Finding.Warning("B", "d", "Firewall", "Shared fix")));
        var summary = _analyzer.Analyze(report).ToSummary();
        Assert.Contains("Remediation Batch Analysis", summary);
        Assert.Contains("Total findings", summary);
        Assert.Contains("Actions saved", summary);
    }

    [Fact]
    public void Analyze_NullReport_Throws() =>
        Assert.Throws<ArgumentNullException>(() => _analyzer.Analyze(null!));

    [Fact]
    public void AnalyzeMultiple_NullReports_Throws() =>
        Assert.Throws<ArgumentNullException>(() => _analyzer.AnalyzeMultiple(null!));

    [Fact]
    public void FindOrphans_NullReport_Throws() =>
        Assert.Throws<ArgumentNullException>(() => _analyzer.FindOrphans(null!));

    [Fact]
    public void OptimalFixOrder_NullAnalysis_Throws() =>
        Assert.Throws<ArgumentNullException>(() => _analyzer.OptimalFixOrder(null!));

    [Fact]
    public void Analyze_AllOrphans_EachGetOwnBatch()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("X", "d", "A"),
            Finding.Warning("Y", "d", "A")));
        var result = _analyzer.Analyze(report);
        Assert.Equal(2, result.Batches.Count);
        Assert.Equal(0, result.MultiFindingBatchCount);
    }

    [Fact]
    public void Categories_ListedAlphabetically()
    {
        var report = MakeReport(
            MakeAudit("Zebra", Finding.Warning("A", "d", "Zebra", "Fix")),
            MakeAudit("Alpha", Finding.Warning("B", "d", "Alpha", "Fix")));
        var batch = _analyzer.Analyze(report).Batches.First(b => b.FindingCount == 2);
        Assert.Equal("Alpha", batch.Categories[0]);
        Assert.Equal("Zebra", batch.Categories[1]);
    }

    [Fact]
    public void SeverityWeight_Values()
    {
        Assert.Equal(10, RemediationBatchAnalyzer.SeverityWeight(Severity.Critical));
        Assert.Equal(5, RemediationBatchAnalyzer.SeverityWeight(Severity.Warning));
        Assert.Equal(1, RemediationBatchAnalyzer.SeverityWeight(Severity.Info));
        Assert.Equal(0, RemediationBatchAnalyzer.SeverityWeight(Severity.Pass));
    }

    [Fact]
    public void Batches_OrderedByEfficiencyScore()
    {
        var report = MakeReport(
            MakeAudit("A",
                Finding.Critical("1", "d", "A", "High impact"),
                Finding.Critical("2", "d", "A", "High impact"),
                Finding.Critical("3", "d", "A", "High impact")),
            MakeAudit("B",
                Finding.Info("4", "d", "B", "Low impact")));
        var result = _analyzer.Analyze(report);
        for (int i = 1; i < result.Batches.Count; i++)
            Assert.True(result.Batches[i - 1].EfficiencyScore >= result.Batches[i].EfficiencyScore);
    }

    [Fact]
    public void AverageImpact_Calculated()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Critical("X", "d", "A", "Fix"),
            Finding.Info("Y", "d", "A", "Fix")));
        var batch = _analyzer.Analyze(report).Batches.First(b => b.FindingCount == 2);
        Assert.Equal(5.5, batch.AverageImpact);
    }

    [Fact]
    public void MaxSeverity_EmptyBatch_ReturnsPass() =>
        Assert.Equal(Severity.Pass, new RemediationBatchAnalyzer.RemediationBatch().MaxSeverity);

    [Fact]
    public void AverageImpact_EmptyBatch_ReturnsZero() =>
        Assert.Equal(0, new RemediationBatchAnalyzer.RemediationBatch().AverageImpact);

    [Fact]
    public void MultiFindingBatchCount_Accurate()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("1", "d", "A", "Fix A"),
            Finding.Warning("2", "d", "A", "Fix A"),
            Finding.Warning("3", "d", "A", "Fix B"),
            Finding.Warning("4", "d", "A", "Fix C")));
        var result = _analyzer.Analyze(report);
        Assert.Equal(1, result.MultiFindingBatchCount);
    }

    [Fact]
    public void HasFixCommand_TrueWhenPresent()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("X", "d", "A", "Remediate", "some-cmd")));
        var batch = _analyzer.Analyze(report).Batches.First();
        Assert.True(batch.HasFixCommand);
        Assert.Equal("some-cmd", batch.FixCommand);
    }

    [Fact]
    public void HasFixCommand_FalseWhenAbsent()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("X", "d", "A", "Remediate")));
        Assert.False(_analyzer.Analyze(report).Batches.First().HasFixCommand);
    }

    [Fact]
    public void ToSummary_ShowsAutoTag()
    {
        var report = MakeReport(MakeAudit("A",
            Finding.Warning("1", "d", "A", "Fix", "cmd"),
            Finding.Warning("2", "d", "A", "Fix", "cmd")));
        var summary = _analyzer.Analyze(report).ToSummary();
        Assert.Contains("[AUTO]", summary);
    }

    [Fact]
    public void ToSummary_TruncatesLargeBatches()
    {
        var findings = Enumerable.Range(1, 8)
            .Select(i => Finding.Warning($"F{i}", "d", "A", "Same fix"))
            .ToArray();
        var report = MakeReport(MakeAudit("A", findings));
        var summary = _analyzer.Analyze(report).ToSummary();
        Assert.Contains("... and", summary);
    }
}
