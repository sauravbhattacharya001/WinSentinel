using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.SmbSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="SmbSecurityAnalyzer"/> - the
/// single-machine SMB (Server Message Block) hardening checks: server/client
/// signing (require + enable), SMBv1 server/client protocol, server encryption,
/// null-session access, and the insecure guest-logon fallback. Every rule is
/// exercised directly against a synthetic <see cref="SmbSecurityState"/>; no
/// registry or SMB cmdlet I/O is touched.
/// </summary>
public class SmbSecurityAnalyzerTests
{
    private static SmbSecurityState HardenedState() => new()
    {
        ServerRequireSigning = true,
        ServerEnableSigning = true,
        Smb1ServerEnabled = false,
        ServerEncryptData = true,
        RestrictNullSessionAccess = true,
        ClientRequireSigning = true,
        ClientEnableSigning = true,
        Smb1ClientEnabled = false,
        InsecureGuestAuthEnabled = false,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => SmbSecurityAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Fully_Hardened_Is_All_Pass()
    {
        var findings = SmbSecurityAnalyzer.Analyze(HardenedState());
        Assert.Equal(9, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var state = HardenedState();
        var a = SmbSecurityAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        var b = SmbSecurityAnalyzer.Analyze(state).Select(f => f.Title).ToArray();
        Assert.Equal(a, b);
    }

    [Fact]
    public void ServerRequireSigning_Off_Is_Warning()
    {
        var f = AnalyzeServerRequireSigning(HardenedState() with { ServerRequireSigning = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("does not require signing", f.Title);
        Assert.NotNull(f.FixCommand);
    }

    [Fact]
    public void ServerRequireSigning_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeServerRequireSigning(HardenedState()).Severity);
    }

    [Fact]
    public void ServerEnableSigning_Off_Is_Warning()
    {
        Assert.Equal(Severity.Warning, AnalyzeServerEnableSigning(HardenedState() with { ServerEnableSigning = false }).Severity);
    }

    [Fact]
    public void Smb1Server_Enabled_Is_Critical()
    {
        var f = AnalyzeSmb1Server(HardenedState() with { Smb1ServerEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("SMBv1", f.Title);
        Assert.Contains("EnableSMB1Protocol", f.FixCommand);
    }

    [Fact]
    public void Smb1Server_Disabled_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeSmb1Server(HardenedState()).Severity);
    }

    [Fact]
    public void ServerEncryption_Off_Is_Info_Not_Failure()
    {
        // Encryption is advisory (signing already covers integrity), so its absence
        // is Info, not a hard Warning/Critical.
        var f = AnalyzeServerEncryption(HardenedState() with { ServerEncryptData = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void ServerEncryption_On_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeServerEncryption(HardenedState()).Severity);
    }

    [Fact]
    public void NullSessionAccess_Restricted_Is_Pass()
    {
        var f = AnalyzeNullSessionAccess(HardenedState());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("restricts null-session", f.Title);
    }

    [Fact]
    public void NullSessionAccess_Allowed_Is_Warning()
    {
        var f = AnalyzeNullSessionAccess(HardenedState() with { RestrictNullSessionAccess = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("allows null-session", f.Title);
        Assert.Contains("RestrictNullSessAccess", f.FixCommand);
    }

    [Fact]
    public void ClientRequireSigning_Off_Is_Warning()
    {
        Assert.Equal(Severity.Warning, AnalyzeClientRequireSigning(HardenedState() with { ClientRequireSigning = false }).Severity);
    }

    [Fact]
    public void ClientEnableSigning_Off_Is_Warning()
    {
        Assert.Equal(Severity.Warning, AnalyzeClientEnableSigning(HardenedState() with { ClientEnableSigning = false }).Severity);
    }

    [Fact]
    public void Smb1Client_Enabled_Is_Critical()
    {
        var f = AnalyzeSmb1Client(HardenedState() with { Smb1ClientEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("SMB1Protocol-Client", f.FixCommand);
    }

    [Fact]
    public void InsecureGuestAuth_Enabled_Is_Critical()
    {
        var f = AnalyzeInsecureGuestAuth(HardenedState() with { InsecureGuestAuthEnabled = true });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("guest", f.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AllowInsecureGuestAuth", f.FixCommand);
    }

    [Fact]
    public void InsecureGuestAuth_Disabled_Is_Pass()
    {
        Assert.Equal(Severity.Pass, AnalyzeInsecureGuestAuth(HardenedState()).Severity);
    }

    [Fact]
    public void Worst_Case_State_Flags_Two_Critical_Smb1_Plus_Guest()
    {
        var worst = new SmbSecurityState
        {
            ServerRequireSigning = false,
            ServerEnableSigning = false,
            Smb1ServerEnabled = true,
            ServerEncryptData = false,
            RestrictNullSessionAccess = false,
            ClientRequireSigning = false,
            ClientEnableSigning = false,
            Smb1ClientEnabled = true,
            InsecureGuestAuthEnabled = true,
        };
        var findings = SmbSecurityAnalyzer.Analyze(worst);
        var criticals = findings.Count(f => f.Severity == Severity.Critical);
        Assert.Equal(3, criticals); // SMBv1 server, SMBv1 client, insecure guest
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
        // Null-session access is off -> its own Warning is present in the aggregate.
        Assert.Contains(findings, f => f.Title.Contains("allows null-session"));
    }
}
