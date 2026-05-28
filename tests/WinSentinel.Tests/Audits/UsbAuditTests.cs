using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the UsbAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class UsbAuditTests
{
    private readonly UsbAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("USB & Removable Media Audit", _audit.Name);
        Assert.Equal("USB", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
        Assert.Contains("USB", _audit.Description);
        Assert.Contains("autorun", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("USB & Removable Media Audit", result.ModuleName);
        Assert.Equal("USB", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        // Should always produce at least AutoRun, AutoPlay, write-protect,
        // storage disable, BitLocker-to-Go, device history, and encryption findings
        Assert.NotEmpty(result.Findings);
        Assert.True(result.Findings.Count >= 5,
            $"Expected at least 5 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveCategory()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.Equal("USB", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveTitleAndDescription()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "Finding title should not be empty");
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                "Finding description should not be empty");
        }
    }

    [Fact]
    public async Task RunAuditAsync_ContainsAutoRunCheck()
    {
        var result = await _audit.RunAuditAsync();

        var autoRunFinding = result.Findings.FirstOrDefault(f =>
            f.Title.Contains("AutoRun", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(autoRunFinding);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsAutoPlayCheck()
    {
        var result = await _audit.RunAuditAsync();

        var autoPlayFinding = result.Findings.FirstOrDefault(f =>
            f.Title.Contains("AutoPlay", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(autoPlayFinding);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsDeviceHistoryCheck()
    {
        var result = await _audit.RunAuditAsync();

        var historyFinding = result.Findings.FirstOrDefault(f =>
            f.Title.Contains("USB storage device", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("device history", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(historyFinding);
    }

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = await _audit.RunAuditAsync(cts.Token);
        Assert.True(result.Success);
    }
}
