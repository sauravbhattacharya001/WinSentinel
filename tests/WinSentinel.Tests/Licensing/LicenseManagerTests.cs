using System;
using System.IO;
using Xunit;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Tests.Licensing;

/// <summary>
/// Covers <see cref="LicenseManager"/>: key validation, on-disk round-trips,
/// 14-day trial issuance, expiry semantics, deactivation, and the
/// <c>TryRequirePro</c> gate. Each test gets its own temp file via
/// <see cref="GetTempPath"/> so they can run in parallel and never touch the
/// real %APPDATA%\WinSentinel\license.json.
/// </summary>
public class LicenseManagerTests : IDisposable
{
    private readonly string _tempDir;

    public LicenseManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "winsentinel-lic-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }
    }

    private string GetTempPath() => Path.Combine(_tempDir, "license.json");

    // ── Key format validation ──────────────────────────────────────

    [Theory]
    [InlineData("WSP-ABCD-EFGH-JKMN")]              // 3 groups, no forbidden chars
    [InlineData("wsp-abcd-efgh-jkmn")]              // lower-cased gets normalized
    [InlineData("  WSP-1234-5678-9ABC  ")]          // surrounding whitespace
    [InlineData("WSP-ABCD-EFGH-JKMN-PQRS")]         // 4 groups (extended team key)
    [InlineData("WSP-0000-0000-0000")]              // all zeros
    [InlineData("WSP-ZYXW-VTSR-QPNM")]              // boundary chars (no I/L/O/U)
    public void TryNormalizeKey_AcceptsValid(string input)
    {
        Assert.True(LicenseManager.TryNormalizeKey(input, out var normalized));
        Assert.StartsWith("WSP-", normalized);
        Assert.Equal(normalized, normalized.ToUpperInvariant());
        Assert.DoesNotContain(' ', normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("FOO-ABCD-EFGH-JKMN")]              // wrong prefix
    [InlineData("WSP-ABC-EFGH-JKMN")]               // group too short
    [InlineData("WSP-ABCDE-EFGH-JKMN")]             // group too long
    [InlineData("WSP-ABCD-EFGH")]                   // only 2 groups
    [InlineData("WSP-ABCD-EFGH-JKM!")]              // illegal char
    [InlineData("WSP-IIII-EFGH-JKMN")]              // I is excluded (Crockford)
    [InlineData("WSP-LLLL-EFGH-JKMN")]              // L excluded
    [InlineData("WSP-OOOO-EFGH-JKMN")]              // O excluded
    [InlineData("WSP-UUUU-EFGH-JKMN")]              // U excluded
    [InlineData("WSP")]                              // empty after prefix
    public void TryNormalizeKey_RejectsInvalid(string? input)
    {
        Assert.False(LicenseManager.TryNormalizeKey(input, out var normalized));
        Assert.Equal(string.Empty, normalized);
    }

    // ── Activation ─────────────────────────────────────────────────

    [Fact]
    public void Activate_PersistsAndLoadsRoundTrip()
    {
        var path = GetTempPath();
        var exp = DateTimeOffset.UtcNow.AddDays(30);
        var rec = LicenseManager.Activate("wsp-abcd-efgh-jkmn", "me@example.com", "individual", exp, path: path);

        Assert.Equal("WSP-ABCD-EFGH-JKMN", rec.Key);
        Assert.Equal("individual", rec.Tier);
        Assert.True(File.Exists(path));

        var loaded = LicenseManager.Load(path);
        Assert.NotNull(loaded);
        Assert.Equal("WSP-ABCD-EFGH-JKMN", loaded!.Key);
        Assert.Equal("me@example.com", loaded.Email);
        Assert.Equal(exp.ToUnixTimeSeconds(), loaded.ExpiresAt.ToUnixTimeSeconds());
        Assert.True(loaded.IsActive);
        Assert.False(loaded.IsTrial);
    }

    [Fact]
    public void Activate_RejectsBadKey()
    {
        var path = GetTempPath();
        Assert.Throws<ArgumentException>(() =>
            LicenseManager.Activate("not-a-key", "x@y.com", "individual", DateTimeOffset.UtcNow.AddDays(30), path: path));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Activate_RejectsUnknownTier()
    {
        var path = GetTempPath();
        Assert.Throws<ArgumentException>(() =>
            LicenseManager.Activate("WSP-ABCD-EFGH-JKMN", "x@y.com", "enterprise", DateTimeOffset.UtcNow.AddDays(30), path: path));
    }

    [Fact]
    public void Activate_RejectsPastExpiry()
    {
        var path = GetTempPath();
        Assert.Throws<ArgumentException>(() =>
            LicenseManager.Activate("WSP-ABCD-EFGH-JKMN", "x@y.com", "individual", DateTimeOffset.UtcNow.AddDays(-1), path: path));
    }

    [Fact]
    public void Activate_StoresEnvelopeVerbatim()
    {
        var path = GetTempPath();
        var env = "{\"sig\":\"deadbeef\",\"payload\":\"...\"}";
        LicenseManager.Activate("WSP-ABCD-EFGH-JKMN", "x@y.com", "team",
            DateTimeOffset.UtcNow.AddDays(30), envelope: env, path: path);
        var loaded = LicenseManager.Load(path);
        Assert.Equal(env, loaded!.Envelope);
        Assert.Equal("team", loaded.Tier);
    }

    // ── Trial ──────────────────────────────────────────────────────

    [Fact]
    public void StartTrial_Creates14DayTrial()
    {
        var path = GetTempPath();
        var rec = LicenseManager.StartTrial("me@x.com", path: path);
        Assert.True(rec.IsTrial);
        Assert.True(rec.IsActive);
        var window = rec.ExpiresAt - rec.IssuedAt;
        Assert.Equal(14, (int)Math.Round(window.TotalDays));
    }

    [Fact]
    public void StartTrial_RefusesToOverwriteWithoutForce()
    {
        var path = GetTempPath();
        LicenseManager.StartTrial(path: path);
        Assert.Throws<InvalidOperationException>(() => LicenseManager.StartTrial(path: path));
    }

    [Fact]
    public void StartTrial_OverwritesWithForce()
    {
        var path = GetTempPath();
        LicenseManager.Activate("WSP-ABCD-EFGH-JKMN", "x@y.com", "individual",
            DateTimeOffset.UtcNow.AddDays(365), path: path);
        var rec = LicenseManager.StartTrial(force: true, path: path);
        Assert.True(rec.IsTrial);
        // Confirm the underlying file is now a trial record.
        var loaded = LicenseManager.Load(path);
        Assert.Equal("trial", loaded!.Tier);
        Assert.Equal(string.Empty, loaded.Key);
    }

    // ── Status & gating ───────────────────────────────────────────

    [Fact]
    public void GetStatus_NoFile_ReportsFree()
    {
        var path = GetTempPath();
        var st = LicenseManager.GetStatus(path);
        Assert.False(st.IsPro);
        Assert.Equal(LicenseState.NoLicense, st.State);
        Assert.Equal("free", st.Tier);
        Assert.Contains("winsentinel.ai", st.Message);
    }

    [Fact]
    public void GetStatus_ActiveTrial_IsPro()
    {
        var path = GetTempPath();
        LicenseManager.StartTrial(path: path);
        var st = LicenseManager.GetStatus(path);
        Assert.True(st.IsPro);
        Assert.Equal(LicenseState.TrialActive, st.State);
        Assert.Equal("trial", st.Tier);
        Assert.True(st.DaysRemaining > 0);
    }

    [Fact]
    public void GetStatus_ExpiredPaid_IsNotPro()
    {
        var path = GetTempPath();
        // Hand-craft an expired record on disk (skip activation guard).
        var record = new LicenseRecord
        {
            Tier = "individual",
            Key = "WSP-ABCD-EFGH-JKMN",
            Email = "x@y.com",
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-400),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1),
        };
        LicenseManager.Save(record, path);

        var st = LicenseManager.GetStatus(path);
        Assert.False(st.IsPro);
        Assert.Equal(LicenseState.Expired, st.State);
        Assert.Equal(0, st.DaysRemaining);
    }

    [Fact]
    public void GetStatus_ExpiredTrial_ReportsTrialExpired()
    {
        var path = GetTempPath();
        var record = new LicenseRecord
        {
            Tier = "trial",
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-30),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(-16),
        };
        LicenseManager.Save(record, path);
        var st = LicenseManager.GetStatus(path);
        Assert.False(st.IsPro);
        Assert.Equal(LicenseState.TrialExpired, st.State);
    }

    [Fact]
    public void Load_CorruptFile_ReturnsNull()
    {
        var path = GetTempPath();
        File.WriteAllText(path, "{ this is not valid json ::");
        Assert.Null(LicenseManager.Load(path));
    }

    [Fact]
    public void Deactivate_RemovesFile()
    {
        var path = GetTempPath();
        LicenseManager.StartTrial(path: path);
        Assert.True(File.Exists(path));
        Assert.True(LicenseManager.Deactivate(path));
        Assert.False(File.Exists(path));
        // Idempotent second call.
        Assert.False(LicenseManager.Deactivate(path));
    }

    [Fact]
    public void TryRequirePro_AllowsActiveTrial()
    {
        var path = GetTempPath();
        LicenseManager.StartTrial(path: path);
        Assert.True(LicenseManager.TryRequirePro("monitor", out var msg, path: path));
        Assert.Contains("active", msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryRequirePro_DeniesFreeAndIncludesUpgradeUrl()
    {
        var path = GetTempPath();
        Assert.False(LicenseManager.TryRequirePro("real-time monitor", out var msg, path: path));
        Assert.Contains("real-time monitor", msg);
        Assert.Contains(LicenseManager.UpgradeUrl, msg);
        Assert.Contains("start-trial", msg);
        Assert.Contains("activate", msg);
    }

    [Fact]
    public void DefaultLicensePath_IsWithinWinSentinelFolder()
    {
        var p = LicenseManager.DefaultLicensePath;
        Assert.EndsWith(Path.Combine("WinSentinel", "license.json"), p);
    }
}
