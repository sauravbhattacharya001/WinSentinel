using WinSentinel.Core.Audits;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the <see cref="SmbSecurityAudit"/> I/O module that wires the pure
/// <see cref="SmbSecurityAnalyzer"/> into a live <c>--audit</c> run. The analyzer's
/// decision logic is covered exhaustively in <see cref="SmbSecurityAnalyzerTests"/>;
/// these tests pin the module's identity/wiring: category matches the analyzer, and
/// running it produces exactly one finding per analyzer check under the SMB category
/// (the collector reads the real local registry but always yields a full finding set).
/// </summary>
public class SmbSecurityAuditTests
{
    private readonly SmbSecurityAudit _audit = new();

    [Fact]
    public void Category_MatchesAnalyzer()
    {
        Assert.Equal(SmbSecurityAnalyzer.Category, _audit.Category);
        Assert.Equal("SMB / File Sharing", _audit.Category);
    }

    [Fact]
    public void Name_And_Description_AreProvided()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Name));
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public async Task RunAudit_ProducesOneFindingPerAnalyzerCheck()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, result.Error);
        // The analyzer emits exactly 9 findings (server require/enable signing,
        // SMBv1 server, server encryption, null-session access, client require/enable
        // signing, SMBv1 client, insecure guest auth); the module surfaces all of them.
        Assert.Equal(9, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(SmbSecurityAnalyzer.Category, f.Category));
    }

    [Fact]
    public void CollectState_DoesNotThrow_AndReturnsState()
    {
        var state = SmbSecurityAudit.CollectState();
        Assert.NotNull(state);
    }
}
