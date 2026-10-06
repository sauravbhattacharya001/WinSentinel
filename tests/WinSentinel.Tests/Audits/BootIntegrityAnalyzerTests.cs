using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.BootIntegrityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="BootIntegrityAnalyzer"/> -
/// the single-machine platform boot-integrity / kernel-protection checks
/// (Secure Boot, VBS, HVCI/Memory Integrity, Kernel DMA Protection, test
/// signing, kernel debugging). Every rule is exercised directly against a
/// synthetic <see cref="BootIntegrityState"/>; no firmware/WMI/boot-config I/O is touched.
/// </summary>
public class BootIntegrityAnalyzerTests
{
    private static BootIntegrityState HardenedState() => new()
    {
        SecureBootEnabled = true,
        VbsStatus = 2,
        HvciRunning = true,
        KernelDmaProtectionOn = true,
        TestSigningEnabled = false,
        KernelDebugEnabled = false,
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
        Assert.Equal(6, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Boot Integrity", f.Category));
    }

    // ---- Secure Boot ------------------------------------------------------

    [Fact]
    public void SecureBoot_Enabled_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeSecureBoot(HardenedState()).Severity);
    }

    [Fact]
    public void SecureBoot_Disabled_Warns()
    {
        var f = AnalyzeSecureBoot(HardenedState() with { SecureBootEnabled = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("disabled", f.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SecureBoot_Unknown_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeSecureBoot(HardenedState() with { SecureBootEnabled = null }).Severity);
    }

    // ---- VBS --------------------------------------------------------------

    [Fact]
    public void Vbs_Running_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeVbs(HardenedState() with { VbsStatus = 2 }).Severity);
    }

    [Fact]
    public void Vbs_EnabledNotRunning_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeVbs(HardenedState() with { VbsStatus = 1 }).Severity);
    }

    [Fact]
    public void Vbs_NotEnabled_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeVbs(HardenedState() with { VbsStatus = 0 }).Severity);
    }

    [Fact]
    public void Vbs_Unknown_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeVbs(HardenedState() with { VbsStatus = null }).Severity);
    }

    // ---- HVCI -------------------------------------------------------------

    [Fact]
    public void Hvci_Running_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeHvci(HardenedState()).Severity);
    }

    [Fact]
    public void Hvci_NotRunning_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeHvci(HardenedState() with { HvciRunning = false }).Severity);
        Assert.Equal(Severity.Warning, AnalyzeHvci(HardenedState() with { HvciRunning = null }).Severity);
    }

    // ---- Kernel DMA Protection -------------------------------------------

    [Fact]
    public void KernelDma_On_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeKernelDmaProtection(HardenedState()).Severity);
    }

    [Fact]
    public void KernelDma_Off_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeKernelDmaProtection(HardenedState() with { KernelDmaProtectionOn = false }).Severity);
    }

    [Fact]
    public void KernelDma_Unknown_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeKernelDmaProtection(HardenedState() with { KernelDmaProtectionOn = null }).Severity);
    }

    // ---- Test Signing -----------------------------------------------------

    [Fact]
    public void TestSigning_Off_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeTestSigning(HardenedState()).Severity);
        Assert.Equal(Severity.Pass, AnalyzeTestSigning(HardenedState() with { TestSigningEnabled = null }).Severity);
    }

    [Fact]
    public void TestSigning_On_IsCritical()
    {
        var f = AnalyzeTestSigning(HardenedState() with { TestSigningEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("bcdedit /set testsigning off", f.FixCommand);
    }

    // ---- Kernel Debug -----------------------------------------------------

    [Fact]
    public void KernelDebug_Off_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeKernelDebug(HardenedState()).Severity);
        Assert.Equal(Severity.Pass, AnalyzeKernelDebug(HardenedState() with { KernelDebugEnabled = null }).Severity);
    }

    [Fact]
    public void KernelDebug_On_IsCritical()
    {
        var f = AnalyzeKernelDebug(HardenedState() with { KernelDebugEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("bcdedit /debug off", f.FixCommand);
    }
}
