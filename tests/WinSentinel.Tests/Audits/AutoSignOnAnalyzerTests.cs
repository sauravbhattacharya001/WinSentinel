using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.AutoSignOnAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="AutoSignOnAnalyzer"/> - the single-machine
/// Windows Automatic Restart Sign-On (DisableAutomaticRestartSignOn) and sign-in-screen
/// account-detail (BlockUserFromShowingAccountDetailsOnSignin) checks. Every rule is exercised
/// directly against a synthetic <see cref="AutoSignOnState"/>; no registry I/O is touched.
/// </summary>
public class AutoSignOnAnalyzerTests
{
    private static AutoSignOnState SecureState() => new()
    {
        DisableAutomaticRestartSignOn = 1,
        BlockUserFromShowingAccountDetailsOnSignin = 1,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => AutoSignOnAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Secure_State_Is_All_Pass()
    {
        var findings = AutoSignOnAnalyzer.Analyze(SecureState());
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = AutoSignOnAnalyzer.Analyze(SecureState());
        var b = AutoSignOnAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Count, b.Count);
        for (int i = 0; i < a.Count; i++)
        {
            Assert.Equal(a[i].Title, b[i].Title);
            Assert.Equal(a[i].Severity, b[i].Severity);
        }
    }

    // --- Automatic Restart Sign-On (ARSO) ---

    [Fact]
    public void Arso_Disabled_Is_Pass()
    {
        var f = AnalyzeAutomaticRestartSignOn(SecureState() with { DisableAutomaticRestartSignOn = 1 });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("disabled", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]      // any value other than the sanctioned 1 means ARSO is not explicitly disabled
    [InlineData(-1)]
    public void Arso_Not_Disabled_Is_Warning(int value)
    {
        var f = AnalyzeAutomaticRestartSignOn(SecureState() with { DisableAutomaticRestartSignOn = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.NotNull(f.Remediation);
        Assert.NotNull(f.FixCommand);
    }

    [Fact]
    public void Arso_Fix_Sets_Disable_Value()
    {
        var f = AnalyzeAutomaticRestartSignOn(SecureState() with { DisableAutomaticRestartSignOn = 0 });
        Assert.Contains("DisableAutomaticRestartSignOn", f.FixCommand);
    }

    // --- Sign-in-screen account details ---

    [Fact]
    public void AccountDetails_Blocked_Is_Pass()
    {
        var f = AnalyzeSignInAccountDetails(SecureState() with { BlockUserFromShowingAccountDetailsOnSignin = 1 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void AccountDetails_Not_Blocked_Is_Info(int value)
    {
        var f = AnalyzeSignInAccountDetails(SecureState() with { BlockUserFromShowingAccountDetailsOnSignin = value });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.NotNull(f.Remediation);
        Assert.Contains("BlockUserFromShowingAccountDetailsOnSignin", f.FixCommand);
    }

    [Fact]
    public void Default_State_Is_Secure()
    {
        // Defaults on the record are the secure values (1), so an unreadable registry never
        // false-positives the dangerous posture.
        var f = AutoSignOnAnalyzer.Analyze(new AutoSignOnState());
        Assert.All(f, x => Assert.Equal(Severity.Pass, x.Severity));
    }
}
