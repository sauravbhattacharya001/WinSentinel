using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.TimeSyncSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="TimeSyncSecurityAnalyzer"/> - the single-machine
/// Windows time-synchronization security checks: W32Time service running, sync source type
/// (NTP / NT5DS / NoSync), the NTP peer relative to domain role, and bounded clock phase-correction
/// caps. Every rule is exercised directly against a synthetic <see cref="TimeSyncState"/>; no
/// registry, service, or w32tm I/O is touched.
/// </summary>
public class TimeSyncSecurityAnalyzerTests
{
    private static TimeSyncState SecureState() => new()
    {
        ServiceRunning = true,
        SyncType = "NT5DS",
        NtpPeer = null,
        DomainJoined = true,
        MaxPosPhaseCorrectionSeconds = 172_800L,
        MaxNegPhaseCorrectionSeconds = 172_800L,
    };

    [Fact]
    public void Analyze_Throws_On_Null_State()
    {
        Assert.Throws<ArgumentNullException>(() => TimeSyncSecurityAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_Secure_State_Is_All_Pass()
    {
        var findings = TimeSyncSecurityAnalyzer.Analyze(SecureState());
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.All(findings, f => Assert.Equal(Category, f.Category));
    }

    [Fact]
    public void Analyze_Is_Deterministic_And_Ordered()
    {
        var a = TimeSyncSecurityAnalyzer.Analyze(SecureState());
        var b = TimeSyncSecurityAnalyzer.Analyze(SecureState());
        Assert.Equal(a.Select(f => f.Title), b.Select(f => f.Title));
    }

    // --- Service running ---

    [Fact]
    public void Service_Stopped_Is_Warning_With_Fix()
    {
        var f = AnalyzeServiceRunning(SecureState() with { ServiceRunning = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal(Category, f.Category);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Service_Running_Is_Pass()
    {
        var f = AnalyzeServiceRunning(SecureState() with { ServiceRunning = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // --- Sync type ---

    [Fact]
    public void SyncType_NoSync_Is_Warning_With_Fix()
    {
        var f = AnalyzeSyncType(SecureState() with { SyncType = "NoSync" });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData("NTP")]
    [InlineData("NT5DS")]
    [InlineData("AllSync")]
    [InlineData("nt5ds")]
    public void SyncType_Known_Values_Are_Pass(string type)
    {
        // Use a non-domain state so NTP does not trip the empty-peer rule (irrelevant here anyway).
        var f = AnalyzeSyncType(SecureState() with { SyncType = type });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("Weird")]
    public void SyncType_Unknown_Or_Unset_Is_Info(string? type)
    {
        var f = AnalyzeSyncType(SecureState() with { SyncType = type });
        Assert.Equal(Severity.Info, f.Severity);
    }

    // --- NTP peer ---

    [Fact]
    public void NtpMode_With_Empty_Peer_Is_Warning()
    {
        var f = AnalyzeNtpPeer(SecureState() with { SyncType = "NTP", NtpPeer = "", DomainJoined = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void DomainJoined_With_Manual_Ntp_Peer_Is_Info()
    {
        var f = AnalyzeNtpPeer(SecureState() with { SyncType = "NTP", NtpPeer = "pool.ntp.org,0x9", DomainJoined = true });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void Standalone_With_Manual_Ntp_Peer_Is_Pass()
    {
        var f = AnalyzeNtpPeer(SecureState() with { SyncType = "NTP", NtpPeer = "time.windows.com,0x9", DomainJoined = false });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Domain_NT5DS_Peer_Is_Pass()
    {
        // NT5DS domain member: manual-peer rule does not apply -> pass.
        var f = AnalyzeNtpPeer(SecureState() with { SyncType = "NT5DS", NtpPeer = null, DomainJoined = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // --- Phase correction ---

    [Fact]
    public void PhaseCorrection_Bounded_Is_Pass()
    {
        var f = AnalyzePhaseCorrection(SecureState());
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void PhaseCorrection_Positive_Unbounded_Sentinel_Is_Warning()
    {
        var f = AnalyzePhaseCorrection(SecureState() with { MaxPosPhaseCorrectionSeconds = UnlimitedPhaseCorrection });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void PhaseCorrection_Negative_Unbounded_Sentinel_Is_Warning()
    {
        var f = AnalyzePhaseCorrection(SecureState() with { MaxNegPhaseCorrectionSeconds = UnlimitedPhaseCorrection });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void PhaseCorrection_Effectively_Unlimited_Is_Warning()
    {
        var f = AnalyzePhaseCorrection(SecureState() with { MaxPosPhaseCorrectionSeconds = EffectivelyUnlimitedSeconds });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void PhaseCorrection_Negative_Value_Is_Warning_Defensively()
    {
        var f = AnalyzePhaseCorrection(SecureState() with { MaxPosPhaseCorrectionSeconds = -5 });
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void PhaseCorrection_Just_Below_Cap_Is_Pass()
    {
        var f = AnalyzePhaseCorrection(SecureState() with
        {
            MaxPosPhaseCorrectionSeconds = EffectivelyUnlimitedSeconds - 1,
            MaxNegPhaseCorrectionSeconds = EffectivelyUnlimitedSeconds - 1,
        });
        Assert.Equal(Severity.Pass, f.Severity);
    }
}
