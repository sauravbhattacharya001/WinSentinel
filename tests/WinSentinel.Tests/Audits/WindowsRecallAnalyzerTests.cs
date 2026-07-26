using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WindowsRecallAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WindowsRecallAnalyzer"/> -
/// the single-machine Windows Recall privacy posture checks (DisableAIDataAnalysis
/// kill switch, AllowRecallEnablement, and an existing snapshot store on disk).
/// Every rule is exercised directly against a synthetic
/// <see cref="WindowsRecallState"/>; no registry or I/O is touched.
/// </summary>
public class WindowsRecallAnalyzerTests
{
    private static WindowsRecallState HardenedState() => new()
    {
        DisableAiDataAnalysis = 1,
        AllowRecallEnablement = 0,
        SnapshotStorePresent = false,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_HardenedState_IsAllPass()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Privacy", f.Category));
    }

    [Fact]
    public void DisableAiDataAnalysis_Set_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeDisableAiDataAnalysis(HardenedState() with { DisableAiDataAnalysis = 1 }).Severity);
    }

    [Fact]
    public void DisableAiDataAnalysis_Absent_Warns_WithFix()
    {
        var f = AnalyzeDisableAiDataAnalysis(HardenedState() with { DisableAiDataAnalysis = null });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("DisableAIDataAnalysis", f.FixCommand);
    }

    [Fact]
    public void DisableAiDataAnalysis_Zero_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeDisableAiDataAnalysis(HardenedState() with { DisableAiDataAnalysis = 0 }).Severity);
    }

    [Fact]
    public void AllowRecallEnablement_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAllowRecallEnablement(HardenedState() with { AllowRecallEnablement = 0 }).Severity);
    }

    [Fact]
    public void AllowRecallEnablement_One_Warns_WithFix()
    {
        var f = AnalyzeAllowRecallEnablement(HardenedState() with { AllowRecallEnablement = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("AllowRecallEnablement", f.FixCommand);
    }

    [Fact]
    public void AllowRecallEnablement_Null_TreatedAsDefault_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeAllowRecallEnablement(HardenedState() with { AllowRecallEnablement = null }).Severity);
    }

    [Fact]
    public void SnapshotStore_Absent_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSnapshotStore(HardenedState() with { SnapshotStorePresent = false }).Severity);
    }

    [Fact]
    public void SnapshotStore_Present_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeSnapshotStore(HardenedState() with { SnapshotStorePresent = true }).Severity);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesWarnings_NoPass()
    {
        var findings = Analyze(new WindowsRecallState
        {
            DisableAiDataAnalysis = 0,
            AllowRecallEnablement = 1,
            SnapshotStorePresent = true,
        });
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Warning, f.Severity));
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }
}
