using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the NetworkAudit module.
/// Runs audit once and shares the result across all tests.
/// </summary>
public class NetworkAuditTests : IAsyncLifetime
{
    private readonly NetworkAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Network Audit", _audit.Name);
        Assert.Equal("Network", _audit.Category);
        Assert.Contains("LLMNR", _audit.Description);
        Assert.Contains("ARP", _audit.Description);
    }

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ChecksListeningPorts()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Port", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Listening", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksSmbOrRdp()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("SMB", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("RDP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksDns()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("DNS", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksNetworkProfile()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Network Profile", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Public Network", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksLlmnr()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("LLMNR", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksNetBios()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("NetBIOS", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksArpTable()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("ARP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        // With 5 new checks, we should now have significantly more findings
        Assert.True(_result.Findings.Count >= 6,
            $"Expected at least 6 findings, got {_result.Findings.Count}");
    }

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }

    [Fact]
    public void RunAuditAsync_LlmnrFindingsHaveRemediation()
    {
        var llmnrFindings = _result.Findings
            .Where(f => f.Title.Contains("LLMNR", StringComparison.OrdinalIgnoreCase) &&
                        f.Severity == Severity.Warning)
            .ToList();

        foreach (var finding in llmnrFindings)
        {
            Assert.False(string.IsNullOrEmpty(finding.Remediation),
                $"LLMNR warning finding '{finding.Title}' should have remediation");
            Assert.False(string.IsNullOrEmpty(finding.FixCommand),
                $"LLMNR warning finding '{finding.Title}' should have a fix command");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveCategory()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.Equal("Network", finding.Category);
        }
    }

    [Fact]
    public void RunAuditAsync_WarningFindingsHaveRemediation()
    {
        var warnings = _result.Findings.Where(f =>
            f.Severity == Severity.Warning || f.Severity == Severity.Critical).ToList();

        foreach (var finding in warnings)
        {
            Assert.False(string.IsNullOrEmpty(finding.Remediation),
                $"Warning/Critical finding '{finding.Title}' should have remediation text");
        }
    }

    [Fact]
    public void RunAuditAsync_HasValidTimestamps()
    {
        Assert.True(_result.StartTime > DateTimeOffset.MinValue);
        Assert.True(_result.EndTime >= _result.StartTime);
    }
}
