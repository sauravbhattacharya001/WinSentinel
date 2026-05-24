using System;
using System.IO;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Covers <see cref="LicenseManager.IsEntitled"/> across the documented
/// states: no record, expired record, trial, individual, team. The entitlement
/// matrix today is deliberately dumb — any active license entitles to any
/// feature — and these tests pin that contract so future SKU work doesn't
/// silently change it.
/// </summary>
public sealed class LicenseManagerEntitlementTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _path;

    public LicenseManagerEntitlementTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "winsentinel-lic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _path = Path.Combine(_tempDir, "license.json");
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort */ }
    }

    private void WriteRecord(string tier, DateTimeOffset expiresAt, string key = "WSP-ABCD-EFGH-JKMN")
    {
        var record = new LicenseRecord
        {
            Tier = tier,
            Key = key,
            Email = "test@example.com",
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-1),
            ExpiresAt = expiresAt,
        };
        LicenseManager.Save(record, _path);
    }

    [Fact]
    public void NoRecord_IsNotEntitled()
    {
        Assert.False(LicenseManager.IsEntitled("any-feature", _path));
    }

    [Fact]
    public void ExpiredRecord_IsNotEntitled()
    {
        WriteRecord("individual", DateTimeOffset.UtcNow.AddDays(-1));
        Assert.False(LicenseManager.IsEntitled("any-feature", _path));
    }

    [Fact]
    public void ActiveTrial_IsEntitled()
    {
        WriteRecord("trial", DateTimeOffset.UtcNow.AddDays(7), key: "");
        Assert.True(LicenseManager.IsEntitled("any-feature", _path));
    }

    [Fact]
    public void ActiveIndividual_IsEntitled()
    {
        WriteRecord("individual", DateTimeOffset.UtcNow.AddDays(30));
        Assert.True(LicenseManager.IsEntitled("any-feature", _path));
    }

    [Fact]
    public void ActiveTeam_IsEntitled()
    {
        WriteRecord("team", DateTimeOffset.UtcNow.AddDays(30));
        Assert.True(LicenseManager.IsEntitled("any-feature", _path));
    }
}
