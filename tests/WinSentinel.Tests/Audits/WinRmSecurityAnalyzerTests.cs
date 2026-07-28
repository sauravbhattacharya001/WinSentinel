using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WinRmSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="WinRmSecurityAnalyzer"/> - the
/// single-machine Windows Remote Management (WinRM / WS-Man) hardening checks
/// (unencrypted transport, Basic/Digest auth, channel-binding hardening, and the
/// TrustedHosts wildcard) on both the service and client side. Every rule is
/// exercised directly against a synthetic <see cref="WinRmState"/>; no WSMan drive
/// or I/O is touched.
/// </summary>
public class WinRmSecurityAnalyzerTests
{
    private static WinRmState HardenedState() => new()
    {
        ServiceRunning = true,
        ServiceAllowUnencrypted = false,
        ServiceAllowBasic = false,
        ServiceAllowDigest = false,
        ServiceCbtHardeningLevel = "Strict",
        ClientAllowUnencrypted = false,
        ClientAllowBasic = false,
        ClientAllowDigest = false,
        ClientTrustedHosts = "",
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_HardenedRunningState_IsAllPass()
    {
        var findings = Analyze(HardenedState());
        // 4 service + 4 client checks when the service is running.
        Assert.Equal(8, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Remote Management", f.Category));
    }

    [Fact]
    public void Analyze_ServiceStopped_SkipsServiceChecks_KeepsClientChecks()
    {
        var findings = Analyze(HardenedState() with { ServiceRunning = false });
        // 1 informational "not running" + 4 client checks.
        Assert.Equal(5, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Info && f.Title.Contains("not running"));
        // No service-side hardening checks present (only the informational "not running").
        Assert.DoesNotContain(findings, f => f.Title.Contains("WinRM service accepts")
            || f.Title.Contains("WinRM service allows")
            || f.Title.Contains("WinRM service requires")
            || f.Title.Contains("WinRM service disallows")
            || f.Title.Contains("channel-binding"));
    }

    // ---- Service: unencrypted ---------------------------------------------

    [Fact]
    public void ServiceUnencrypted_On_IsCritical()
    {
        var f = AnalyzeServiceUnencrypted(HardenedState() with { ServiceAllowUnencrypted = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("AllowUnencrypted", f.FixCommand);
    }

    [Fact]
    public void ServiceUnencrypted_Off_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeServiceUnencrypted(HardenedState()).Severity);
    }

    // ---- Service: Basic / Digest ------------------------------------------

    [Fact]
    public void ServiceBasic_On_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeServiceBasic(HardenedState() with { ServiceAllowBasic = true }).Severity);
    }

    [Fact]
    public void ServiceDigest_On_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeServiceDigest(HardenedState() with { ServiceAllowDigest = true }).Severity);
    }

    // ---- Service: CBT hardening -------------------------------------------

    [Fact]
    public void Cbt_Strict_Passes_CaseInsensitive()
    {
        Assert.Equal(Severity.Pass, AnalyzeCbtHardening(HardenedState() with { ServiceCbtHardeningLevel = "strict" }).Severity);
    }

    [Fact]
    public void Cbt_Relaxed_Warns()
    {
        var f = AnalyzeCbtHardening(HardenedState() with { ServiceCbtHardeningLevel = "Relaxed" });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Relaxed", f.Description);
    }

    [Fact]
    public void Cbt_Null_Warns_ShownAsUnset()
    {
        var f = AnalyzeCbtHardening(HardenedState() with { ServiceCbtHardeningLevel = null });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("unset", f.Description);
    }

    // ---- Client: unencrypted ----------------------------------------------

    [Fact]
    public void ClientUnencrypted_On_IsCritical()
    {
        Assert.Equal(Severity.Critical, AnalyzeClientUnencrypted(HardenedState() with { ClientAllowUnencrypted = true }).Severity);
    }

    [Fact]
    public void ClientBasic_On_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeClientBasic(HardenedState() with { ClientAllowBasic = true }).Severity);
    }

    [Fact]
    public void ClientDigest_On_Warns()
    {
        Assert.Equal(Severity.Warning, AnalyzeClientDigest(HardenedState() with { ClientAllowDigest = true }).Severity);
    }

    // ---- Client: TrustedHosts ---------------------------------------------

    [Fact]
    public void TrustedHosts_Empty_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeTrustedHosts(HardenedState() with { ClientTrustedHosts = "" }).Severity);
    }

    [Fact]
    public void TrustedHosts_Null_Passes()
    {
        Assert.Equal(Severity.Pass, AnalyzeTrustedHosts(HardenedState() with { ClientTrustedHosts = null }).Severity);
    }

    [Fact]
    public void TrustedHosts_Wildcard_IsCritical()
    {
        var f = AnalyzeTrustedHosts(HardenedState() with { ClientTrustedHosts = "*" });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("all hosts", f.Title, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TrustedHosts_WildcardInList_IsCritical()
    {
        var f = AnalyzeTrustedHosts(HardenedState() with { ClientTrustedHosts = "host1, *, host2" });
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void TrustedHosts_ExplicitList_Passes()
    {
        var f = AnalyzeTrustedHosts(HardenedState() with { ClientTrustedHosts = "server01,server02" });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("server01", f.Description);
    }
}
