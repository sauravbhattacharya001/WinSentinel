using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.FirewallLoggingAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="FirewallLoggingAnalyzer"/> -
/// the single-machine Windows Firewall logging checks (dropped-packet logging,
/// successful-connection logging, log file size, and log file path) evaluated per
/// profile (Domain / Private / Public). Every rule is exercised directly against a
/// synthetic <see cref="FirewallLoggingState"/>; no registry or I/O is touched.
/// </summary>
public class FirewallLoggingAnalyzerTests
{
    private static FirewallProfileLogging HardenedProfile() => new()
    {
        LogDroppedPackets = 1,
        LogSuccessfulConnections = 1,
        LogFileSizeKb = MinLogFileSizeKb,
        LogFilePath = @"%systemroot%\system32\LogFiles\Firewall\pfirewall.log",
    };

    private static FirewallLoggingState HardenedState() => new()
    {
        Domain = HardenedProfile(),
        Private = HardenedProfile(),
        Public = HardenedProfile(),
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
        // 4 checks x 3 profiles.
        Assert.Equal(12, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    [Fact]
    public void Analyze_CoversAllThreeProfiles()
    {
        var findings = Analyze(HardenedState());
        foreach (var profile in Profiles)
        {
            Assert.Contains(findings, f => f.Title.StartsWith(profile, System.StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Analyze_AllFindings_UseFirewallCategory()
    {
        var findings = Analyze(HardenedState());
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void LogDropped_DisabledOrUnset_Warns(int? value)
    {
        var p = HardenedProfile();
        p.LogDroppedPackets = value;
        var finding = AnalyzeLogDropped("Public", p);
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.StartsWith("Public", finding.Title);
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void LogDropped_Enabled_Passes()
    {
        var finding = AnalyzeLogDropped("Domain", HardenedProfile());
        Assert.Equal(Severity.Pass, finding.Severity);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void LogAllowed_DisabledOrUnset_Warns(int? value)
    {
        var p = HardenedProfile();
        p.LogSuccessfulConnections = value;
        var finding = AnalyzeLogAllowed("Private", p);
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void LogAllowed_Enabled_Passes()
    {
        var finding = AnalyzeLogAllowed("Private", HardenedProfile());
        Assert.Equal(Severity.Pass, finding.Severity);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(4096)]
    [InlineData(16383)]
    public void LogSize_BelowMinimum_Warns(int? size)
    {
        var p = HardenedProfile();
        p.LogFileSizeKb = size;
        var finding = AnalyzeLogSize("Domain", p);
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Theory]
    [InlineData(16384)]
    [InlineData(32768)]
    public void LogSize_AtOrAboveMinimum_Passes(int size)
    {
        var p = HardenedProfile();
        p.LogFileSizeKb = size;
        var finding = AnalyzeLogSize("Domain", p);
        Assert.Equal(Severity.Pass, finding.Severity);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void LogPath_MissingOrBlank_Warns(string? path)
    {
        var p = HardenedProfile();
        p.LogFilePath = path;
        var finding = AnalyzeLogPath("Public", p);
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void LogPath_Configured_Passes()
    {
        var finding = AnalyzeLogPath("Public", HardenedProfile());
        Assert.Equal(Severity.Pass, finding.Severity);
    }

    [Fact]
    public void GetProfile_UnknownName_ReturnsEmptyNotNull()
    {
        var state = new FirewallLoggingState();
        var p = state.GetProfile("Nonexistent");
        Assert.NotNull(p);
        Assert.Null(p.LogDroppedPackets);
    }

    [Fact]
    public void Analyze_EmptyState_AllWarnAndCountsMatch()
    {
        var findings = Analyze(new FirewallLoggingState());
        Assert.Equal(12, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Warning, f.Severity));
    }
}
