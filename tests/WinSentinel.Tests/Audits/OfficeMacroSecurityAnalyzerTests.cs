using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.OfficeMacroSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="OfficeMacroSecurityAnalyzer"/> -
/// the single-machine Office macro-security posture checks (VBAWarnings enablement,
/// blocking macros in Mark-of-the-Web files, and Protected View for risky origins).
/// Every rule is exercised directly against a synthetic
/// <see cref="OfficeMacroSecurityState"/>; no registry or I/O is touched.
/// </summary>
public class OfficeMacroSecurityAnalyzerTests
{
    private static OfficeMacroSecurityState HardenedState() => new()
    {
        OfficeInstalled = true,
        VbaWarnings = 4,
        BlockInternetMacros = true,
        DisableInternetFilesInProtectedView = false,
        DisableUnsafeLocationsInProtectedView = false,
        DisableAttachmentsInProtectedView = false,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_OfficeNotInstalled_SinglePass()
    {
        var findings = Analyze(new OfficeMacroSecurityState { OfficeInstalled = false });
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
        Assert.Equal("Application Security", findings[0].Category);
    }

    [Fact]
    public void Analyze_HardenedState_IsAllPass()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Application Security", f.Category));
    }

    [Fact]
    public void VbaWarnings_EnableAll_IsCritical_WithFix()
    {
        var f = AnalyzeVbaWarnings(HardenedState() with { VbaWarnings = 1 });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("VBAWarnings", f.FixCommand);
    }

    [Fact]
    public void VbaWarnings_SignedOnly_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeVbaWarnings(HardenedState() with { VbaWarnings = 3 }).Severity);
    }

    [Fact]
    public void VbaWarnings_DisableAll_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeVbaWarnings(HardenedState() with { VbaWarnings = 4 }).Severity);
    }

    [Fact]
    public void VbaWarnings_DisableWithNotification_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeVbaWarnings(HardenedState() with { VbaWarnings = 2 }).Severity);
    }

    [Fact]
    public void VbaWarnings_Unset_Warns_WithFix()
    {
        var f = AnalyzeVbaWarnings(HardenedState() with { VbaWarnings = null });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("VBAWarnings", f.FixCommand);
    }

    [Fact]
    public void BlockInternetMacros_Enabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeBlockInternetMacros(HardenedState() with { BlockInternetMacros = true }).Severity);
    }

    [Fact]
    public void BlockInternetMacros_Disabled_Warns_WithFix()
    {
        var f = AnalyzeBlockInternetMacros(HardenedState() with { BlockInternetMacros = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("blockcontentexecutionfrominternet", f.FixCommand);
    }

    [Fact]
    public void BlockInternetMacros_Null_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeBlockInternetMacros(HardenedState() with { BlockInternetMacros = null }).Severity);
    }

    [Fact]
    public void ProtectedView_AllEnabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeProtectedView(HardenedState()).Severity);
    }

    [Fact]
    public void ProtectedView_InternetDisabled_Warns_ListsOrigin()
    {
        var f = AnalyzeProtectedView(HardenedState() with { DisableInternetFilesInProtectedView = true });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("internet files", f.Description);
    }

    [Fact]
    public void ProtectedView_AllDisabled_Warns_ListsAllOrigins()
    {
        var f = AnalyzeProtectedView(new OfficeMacroSecurityState
        {
            OfficeInstalled = true,
            DisableInternetFilesInProtectedView = true,
            DisableUnsafeLocationsInProtectedView = true,
            DisableAttachmentsInProtectedView = true,
        });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("internet files", f.Description);
        Assert.Contains("unsafe locations", f.Description);
        Assert.Contains("e-mail attachments", f.Description);
    }

    [Fact]
    public void ProtectedView_NullValues_TreatedAsEnabled_Passes()
    {
        var f = AnalyzeProtectedView(new OfficeMacroSecurityState { OfficeInstalled = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesCriticalAndWarnings_NoPass()
    {
        var findings = Analyze(new OfficeMacroSecurityState
        {
            OfficeInstalled = true,
            VbaWarnings = 1,
            BlockInternetMacros = false,
            DisableInternetFilesInProtectedView = true,
            DisableUnsafeLocationsInProtectedView = true,
            DisableAttachmentsInProtectedView = true,
        });
        Assert.Equal(3, findings.Count);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
    }
}
