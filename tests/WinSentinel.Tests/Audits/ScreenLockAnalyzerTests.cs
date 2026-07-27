using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.ScreenLockAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="ScreenLockAnalyzer"/> - the
/// single-machine interactive-session lock / sign-in hardening checks (machine
/// inactivity lock, secure screensaver, hidden last user, secure attention
/// sequence, hidden locked-screen user info). Every rule is exercised directly
/// against a synthetic <see cref="ScreenLockState"/>; no registry or I/O is touched.
/// </summary>
public class ScreenLockAnalyzerTests
{
    private static ScreenLockState HardenedState() => new()
    {
        InactivityTimeoutSecs = 600,
        ScreenSaverActive = true,
        ScreenSaverIsSecure = true,
        ScreenSaverTimeoutSecs = 600,
        DontDisplayLastUserName = 1,
        DisableCad = 0,
        DontDisplayLockedUserId = 3,
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
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Session Security", f.Category));
    }

    // ---- InactivityTimeout ------------------------------------------------

    [Fact]
    public void Inactivity_WithinLimit_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeInactivityTimeout(HardenedState() with { InactivityTimeoutSecs = 900 }).Severity);
    }

    [Fact]
    public void Inactivity_Zero_Warns()
    {
        var f = AnalyzeInactivityTimeout(HardenedState() with { InactivityTimeoutSecs = 0 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("never", f.Title, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("InactivityTimeoutSecs", f.FixCommand);
    }

    [Fact]
    public void Inactivity_Null_TreatedAsNever_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeInactivityTimeout(HardenedState() with { InactivityTimeoutSecs = null }).Severity);
    }

    [Fact]
    public void Inactivity_TooLong_Warns()
    {
        var f = AnalyzeInactivityTimeout(HardenedState() with { InactivityTimeoutSecs = 3600 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("too long", f.Title, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Inactivity_ExactlyAtBoundary_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeInactivityTimeout(HardenedState() with { InactivityTimeoutSecs = MaxInactivityTimeoutSecs }).Severity);
    }

    // ---- Screensaver ------------------------------------------------------

    [Fact]
    public void ScreenSaver_Secure_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeScreenSaver(HardenedState()).Severity);
    }

    [Fact]
    public void ScreenSaver_Inactive_Warns()
    {
        var f = AnalyzeScreenSaver(HardenedState() with { ScreenSaverActive = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("No screensaver", f.Title, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScreenSaver_NotSecure_Warns()
    {
        var f = AnalyzeScreenSaver(HardenedState() with { ScreenSaverIsSecure = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("password", f.Title, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScreenSaver_NoTimeout_Warns()
    {
        var f = AnalyzeScreenSaver(HardenedState() with { ScreenSaverTimeoutSecs = null });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("timeout", f.Title, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScreenSaver_TooLong_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeScreenSaver(HardenedState() with { ScreenSaverTimeoutSecs = 5000 }).Severity);
    }

    // ---- Last username ----------------------------------------------------

    [Fact]
    public void LastUserName_Hidden_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeLastUserName(HardenedState()).Severity);
    }

    [Fact]
    public void LastUserName_Shown_Warns()
    {
        var f = AnalyzeLastUserName(HardenedState() with { DontDisplayLastUserName = 0 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("DontDisplayLastUserName", f.FixCommand);
    }

    [Fact]
    public void LastUserName_Null_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeLastUserName(HardenedState() with { DontDisplayLastUserName = null }).Severity);
    }

    // ---- Secure attention sequence (CAD) ----------------------------------

    [Fact]
    public void Cad_Required_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSecureAttentionSequence(HardenedState()).Severity);
    }

    [Fact]
    public void Cad_Null_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSecureAttentionSequence(HardenedState() with { DisableCad = null }).Severity);
    }

    [Fact]
    public void Cad_Disabled_Warns()
    {
        var f = AnalyzeSecureAttentionSequence(HardenedState() with { DisableCad = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("DisableCAD", f.FixCommand);
    }

    // ---- Locked-screen user info ------------------------------------------

    [Fact]
    public void LockedUserInfo_Hidden_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeLockedUserInfo(HardenedState()).Severity);
    }

    [Fact]
    public void LockedUserInfo_NotSet_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeLockedUserInfo(HardenedState() with { DontDisplayLockedUserId = null }).Severity);
    }

    [Fact]
    public void LockedUserInfo_WrongValue_Warns()
    {
        var f = AnalyzeLockedUserInfo(HardenedState() with { DontDisplayLockedUserId = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("DontDisplayLockedUserId", f.FixCommand);
    }
}
