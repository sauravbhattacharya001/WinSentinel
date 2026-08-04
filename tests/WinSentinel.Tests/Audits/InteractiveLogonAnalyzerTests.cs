using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.InteractiveLogonAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="InteractiveLogonAnalyzer"/> - the single-machine
/// Windows interactive-logon policy checks: the pre-logon legal-notice banner
/// (LegalNoticeCaption / LegalNoticeText) and, when smart-card logon is in use, the smart-card
/// removal behavior (ScRemoveOption). Every rule is exercised directly against a synthetic
/// <see cref="InteractiveLogonState"/>; no registry or service I/O is touched.
/// </summary>
public class InteractiveLogonAnalyzerTests
{
    private static InteractiveLogonState SecureState() => new()
    {
        LegalNoticeCaption = "Authorized Use Only",
        LegalNoticeText = "This system is for authorized users only.",
        SmartCardLogonInUse = true,
        ScRemoveOption = "1",
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => InteractiveLogonAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Secure_State_Is_All_Pass()
    {
        var findings = InteractiveLogonAnalyzer.Analyze(SecureState());
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = InteractiveLogonAnalyzer.Analyze(SecureState());
        var b = InteractiveLogonAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    // --- Logon legal-notice banner ---

    [Fact]
    public void Banner_Both_Set_Is_Pass()
    {
        var f = AnalyzeLogonBanner(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal(Category, f.Category);
    }

    [Theory]
    [InlineData("", "body")]
    [InlineData("title", "")]
    [InlineData(null, "body")]
    [InlineData("title", null)]
    [InlineData("", "")]
    [InlineData("   ", "body")]
    public void Banner_Missing_Caption_Or_Text_Is_Info(string? caption, string? text)
    {
        var f = AnalyzeLogonBanner(SecureState() with { LegalNoticeCaption = caption, LegalNoticeText = text });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // --- Smart-card removal ---

    [Fact]
    public void SmartCard_Not_In_Use_Is_Pass_Regardless_Of_Option()
    {
        var f = AnalyzeSmartCardRemoval(SecureState() with { SmartCardLogonInUse = false, ScRemoveOption = "0" });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("")]
    [InlineData(null)]
    public void SmartCard_NoAction_Or_Unset_Is_Warning_With_Fix(string? option)
    {
        var f = AnalyzeSmartCardRemoval(SecureState() with { SmartCardLogonInUse = true, ScRemoveOption = option });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    public void SmartCard_Lock_Or_Logoff_Is_Pass(string option)
    {
        var f = AnalyzeSmartCardRemoval(SecureState() with { SmartCardLogonInUse = true, ScRemoveOption = option });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void SmartCard_Unknown_NonZero_Value_Is_Pass()
    {
        // Any non-"0" value means some action is taken on removal -> not the insecure "no action" state.
        var f = AnalyzeSmartCardRemoval(SecureState() with { SmartCardLogonInUse = true, ScRemoveOption = "3" });
        Assert.Equal(Severity.Pass, f.Severity);
    }
}
