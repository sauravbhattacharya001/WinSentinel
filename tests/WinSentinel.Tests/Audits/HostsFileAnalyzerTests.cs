using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.HostsFileAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="HostsFileAnalyzer"/> - the
/// single-machine hosts-file integrity checks (blackholed security/update
/// domains, public-IP redirects, unusually large blocklists, unreadable file)
/// plus the shared <see cref="HostsFileAnalyzer.ParseHosts"/> parser. Every rule
/// is exercised against a synthetic <see cref="HostsFileState"/>; no disk is
/// touched.
/// </summary>
public class HostsFileAnalyzerTests
{
    private static HostsFileState State(params HostMapping[] entries) => new()
    {
        Path = "C:\\Windows\\System32\\drivers\\etc\\hosts",
        FileExists = true,
        Readable = true,
        Entries = entries,
    };

    [Fact]
    public void Analyze_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_CleanHosts_IsAllPass()
    {
        var findings = Analyze(State(
            new HostMapping("127.0.0.1", "localhost"),
            new HostMapping("::1", "localhost")));
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal("Network", f.Category));
    }

    [Fact]
    public void Analyze_EmptyHosts_IsAllPass()
    {
        var findings = Analyze(State());
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    [Fact]
    public void UnreadableFile_ReportsInfo()
    {
        var f = AnalyzeReadable(new HostsFileState { Path = "x", FileExists = true, Readable = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void MissingFile_IsReadablePass()
    {
        var f = AnalyzeReadable(new HostsFileState { Path = "x", FileExists = false, Readable = true });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("No hosts file", f.Description);
    }

    [Fact]
    public void BlackholedWindowsUpdate_IsCritical()
    {
        var f = AnalyzeBlackholedSecurityDomains(State(
            new HostMapping("0.0.0.0", "windowsupdate.microsoft.com")));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("windowsupdate.microsoft.com", f.Description);
    }

    [Fact]
    public void BlackholedAvSubdomain_IsCritical()
    {
        var f = AnalyzeBlackholedSecurityDomains(State(
            new HostMapping("127.0.0.1", "definitions.mcafee.com")));
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void SecurityDomainToPublicIp_IsNotBlackholed()
    {
        // Redirecting an AV domain to a public IP is a hijack, not a blackhole -
        // it must NOT trip the blackhole (non-routable) rule.
        var f = AnalyzeBlackholedSecurityDomains(State(
            new HostMapping("203.0.113.9", "windowsupdate.com")));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void NonSecurityDomainBlackholed_Passes()
    {
        var f = AnalyzeBlackholedSecurityDomains(State(
            new HostMapping("0.0.0.0", "ads.example.com")));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void PublicIpRedirect_IsWarning()
    {
        var f = AnalyzePublicRedirects(State(
            new HostMapping("203.0.113.5", "login.mybank.com")));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("login.mybank.com", f.Description);
    }

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.4.4")]
    [InlineData("192.168.1.10")]
    [InlineData("169.254.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("100.64.0.1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    public void PrivateOrNonRoutableRedirect_DoesNotWarn(string address)
    {
        var f = AnalyzePublicRedirects(State(new HostMapping(address, "internal.example.com")));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void PublicIpv6Redirect_IsWarning()
    {
        var f = AnalyzePublicRedirects(State(new HostMapping("2606:4700:4700::1111", "cf.example.com")));
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void NonIpTarget_DoesNotWarn()
    {
        var f = AnalyzePublicRedirects(State(new HostMapping("notanip", "weird.example.com")));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void LargeHostsFile_IsInfo()
    {
        var entries = Enumerable.Range(0, 1200)
            .Select(i => new HostMapping("0.0.0.0", $"ad{i}.tracker.example"))
            .ToArray();
        var f = AnalyzeEntryCount(State(entries));
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void SmallHostsFile_EntryCountPasses()
    {
        Assert.Equal(Severity.Pass, AnalyzeEntryCount(State(new HostMapping("0.0.0.0", "a.b"))).Severity);
    }

    [Fact]
    public void ParseHosts_SkipsCommentsAndBlanks()
    {
        var content = "# comment\n\n127.0.0.1 localhost\n0.0.0.0 ads.example.com # trailing\n   \n";
        var entries = ParseHosts(content);
        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Address == "127.0.0.1" && e.Hostname == "localhost");
        Assert.Contains(entries, e => e.Address == "0.0.0.0" && e.Hostname == "ads.example.com");
    }

    [Fact]
    public void ParseHosts_MultipleHostnamesPerLine()
    {
        var entries = ParseHosts("127.0.0.1  localhost  loopback  myhost");
        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal("127.0.0.1", e.Address));
    }

    [Fact]
    public void ParseHosts_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Empty(ParseHosts(null));
        Assert.Empty(ParseHosts(string.Empty));
    }

    [Fact]
    public void Analyze_TamperedHosts_ProducesCriticalAndWarning()
    {
        var findings = Analyze(State(
            new HostMapping("0.0.0.0", "update.microsoft.com"),
            new HostMapping("203.0.113.7", "login.bank.example")));
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
    }
}
