using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.NameResolutionAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="NameResolutionAnalyzer"/> - the
/// single-machine name-resolution poisoning hardening checks (LLMNR, NBT-NS, mDNS,
/// WPAD). Every rule is exercised directly against a synthetic
/// <see cref="NameResolutionState"/>; no registry or I/O is touched.
/// </summary>
public class NameResolutionAnalyzerTests
{
    /// <summary>A fully-hardened machine: LLMNR/mDNS off, NBT-NS disabled on all NICs, WPAD off.</summary>
    private static NameResolutionState HardenedState() => new()
    {
        EnableMulticast = 0,
        NetbiosOptionsPerInterface = new[] { 2, 2 },
        EnableMdns = 0,
        DisableWpad = 1,
        WpadAutoDetect = 0,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_ReturnsFourFindings_AllInCategory()
    {
        var findings = Analyze(HardenedState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal("Name Resolution", f.Category));
    }

    [Fact]
    public void Analyze_HardenedState_HasNoWarnings()
    {
        var findings = Analyze(HardenedState());
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
    }

    // --- LLMNR ---

    [Fact]
    public void Llmnr_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeLlmnr(HardenedState() with { EnableMulticast = 0 }).Severity);
    }

    [Fact]
    public void Llmnr_AbsentOrOne_Warns_WithFix()
    {
        var absent = AnalyzeLlmnr(HardenedState() with { EnableMulticast = null });
        Assert.Equal(Severity.Warning, absent.Severity);
        Assert.Contains("EnableMulticast", absent.FixCommand);
        Assert.Equal(Severity.Warning, AnalyzeLlmnr(HardenedState() with { EnableMulticast = 1 }).Severity);
    }

    // --- NetBIOS / NBT-NS ---

    [Fact]
    public void Netbios_AllInterfacesDisabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeNetbios(HardenedState() with { NetbiosOptionsPerInterface = new[] { 2, 2, 2 } }).Severity);
    }

    [Fact]
    public void Netbios_OneInterfaceExposed_Warns_WithFix()
    {
        var f = AnalyzeNetbios(HardenedState() with { NetbiosOptionsPerInterface = new[] { 2, 0 } });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("NetbiosOptions", f.FixCommand);
    }

    [Fact]
    public void Netbios_ExplicitlyOn_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeNetbios(HardenedState() with { NetbiosOptionsPerInterface = new[] { 1 } }).Severity);
    }

    [Fact]
    public void Netbios_NoInterfacesReadable_Info()
    {
        Assert.Equal(Severity.Info, AnalyzeNetbios(HardenedState() with { NetbiosOptionsPerInterface = null }).Severity);
        Assert.Equal(Severity.Info, AnalyzeNetbios(HardenedState() with { NetbiosOptionsPerInterface = new int[0] }).Severity);
    }

    // --- mDNS ---

    [Fact]
    public void Mdns_Zero_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeMdns(HardenedState() with { EnableMdns = 0 }).Severity);
    }

    [Fact]
    public void Mdns_AbsentOrOne_Info()
    {
        Assert.Equal(Severity.Info, AnalyzeMdns(HardenedState() with { EnableMdns = null }).Severity);
        Assert.Equal(Severity.Info, AnalyzeMdns(HardenedState() with { EnableMdns = 1 }).Severity);
    }

    // --- WPAD ---

    [Fact]
    public void Wpad_DisabledByPolicy_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeWpad(HardenedState() with { DisableWpad = 1, WpadAutoDetect = 1 }).Severity);
    }

    [Fact]
    public void Wpad_DisabledByAutoDetectOff_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeWpad(HardenedState() with { DisableWpad = null, WpadAutoDetect = 0 }).Severity);
    }

    [Fact]
    public void Wpad_EnabledEverywhere_Warns_WithFix()
    {
        var f = AnalyzeWpad(HardenedState() with { DisableWpad = null, WpadAutoDetect = 1 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("WpadOverride", f.FixCommand);
    }

    [Fact]
    public void Analyze_WorstCase_ProducesExpectedSeverities()
    {
        // LLMNR on, NBT-NS on one NIC, mDNS on, WPAD on.
        var findings = Analyze(new NameResolutionState
        {
            EnableMulticast = 1,
            NetbiosOptionsPerInterface = new[] { 0 },
            EnableMdns = 1,
            DisableWpad = null,
            WpadAutoDetect = 1,
        });
        Assert.Equal(4, findings.Count);
        // LLMNR, NBT-NS and WPAD are warnings; mDNS is Info.
        Assert.Equal(3, findings.Count(f => f.Severity == Severity.Warning));
    }
}
