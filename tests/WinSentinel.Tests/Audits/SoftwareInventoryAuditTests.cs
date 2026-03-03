using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for SoftwareInventoryAudit.
/// Uses synchronous collection methods where possible to avoid
/// long-running PowerShell commands in CI.
/// </summary>
public class SoftwareInventoryAuditTests
{
    private readonly SoftwareInventoryAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Software Inventory Audit", _audit.Name);
        Assert.Equal("Software", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public void CollectSoftwareInventory_ReturnsNonEmptyList()
    {
        var inventory = _audit.CollectSoftwareInventory();
        Assert.NotEmpty(inventory);
    }

    [Fact]
    public void CollectSoftwareInventory_EntriesHaveNames()
    {
        var inventory = _audit.CollectSoftwareInventory();
        foreach (var entry in inventory)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.Name),
                "Every software entry must have a display name");
        }
    }

    [Fact]
    public void CollectSoftwareInventory_NoDuplicates()
    {
        var inventory = _audit.CollectSoftwareInventory();
        var keys = inventory.Select(e => $"{e.Name}|{e.Version}".ToLowerInvariant()).ToList();
        Assert.Equal(keys.Count, keys.Distinct().Count());
    }

    [Fact]
    public void CollectSoftwareInventory_ExcludesSystemComponents()
    {
        var inventory = _audit.CollectSoftwareInventory();
        Assert.DoesNotContain(inventory, e => e.IsSystemComponent);
    }

    [Fact]
    public void CollectSoftwareInventory_HasRegistryMetadata()
    {
        var inventory = _audit.CollectSoftwareInventory();
        Assert.Contains(inventory, e =>
            e.RegistryHive == "HKLM" || e.RegistryHive == "HKCU");
    }

    [Fact]
    public void CollectSoftwareInventory_SomeEntriesHavePublisher()
    {
        var inventory = _audit.CollectSoftwareInventory();
        Assert.Contains(inventory, e => !string.IsNullOrWhiteSpace(e.Publisher));
    }

    [Fact]
    public void CollectSoftwareInventory_SomeEntriesHaveVersion()
    {
        var inventory = _audit.CollectSoftwareInventory();
        Assert.Contains(inventory, e => !string.IsNullOrWhiteSpace(e.Version));
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var result = await _audit.RunAuditAsync(cts.Token);
        // Even if PowerShell commands time out, the audit should not throw
        Assert.NotNull(result);
        Assert.Equal("Software Inventory Audit", result.ModuleName);
        Assert.Equal("Software", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var result = await _audit.RunAuditAsync(cts.Token);
        // Should always produce at least: inventory count, suspicious locations, PUP check
        Assert.True(result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveCategory()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var result = await _audit.RunAuditAsync(cts.Token);
        foreach (var finding in result.Findings)
        {
            Assert.Equal("Software", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveTitleAndDescription()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var result = await _audit.RunAuditAsync(cts.Token);
        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title));
            Assert.False(string.IsNullOrWhiteSpace(finding.Description));
        }
    }

    [Fact]
    public async Task RunAuditAsync_FindingsUseValidSeverities()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var result = await _audit.RunAuditAsync(cts.Token);
        foreach (var finding in result.Findings)
        {
            Assert.True(
                finding.Severity == Severity.Pass ||
                finding.Severity == Severity.Info ||
                finding.Severity == Severity.Warning ||
                finding.Severity == Severity.Critical,
                $"Invalid severity: {finding.Severity}");
        }
    }
}
