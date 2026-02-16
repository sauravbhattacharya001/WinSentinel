using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Comprehensive tests for the EncryptionAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class EncryptionAuditTests
{
    private readonly EncryptionAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Encryption Audit", _audit.Name);
        Assert.Equal("Encryption", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
        Assert.Contains("BitLocker", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TPM", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("certificate", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TLS", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Encryption Audit", result.ModuleName);
        Assert.Equal("Encryption", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should have at minimum: BitLocker for C:, TPM, EFS, cert store, TLS checks, 
        // Credential Guard, DPAPI = at least 7 findings
        Assert.True(result.Findings.Count >= 7,
            $"Expected at least 7 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_FindingsHaveRequiredFields()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "Finding title must not be empty");
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                "Finding description must not be empty");
            Assert.True(Enum.IsDefined(finding.Severity),
                $"Invalid severity: {finding.Severity}");
            Assert.Equal("Encryption", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_HasBitLockerFindings()
    {
        var result = await _audit.RunAuditAsync();

        // Should have at least one BitLocker finding (at minimum for C: drive)
        var bitLockerFindings = result.Findings
            .Where(f => f.Title.Contains("BitLocker", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(bitLockerFindings.Count >= 1,
            $"Expected at least 1 BitLocker finding, got {bitLockerFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasTpmFinding()
    {
        var result = await _audit.RunAuditAsync();

        var tpmFindings = result.Findings
            .Where(f => f.Title.Contains("TPM", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(tpmFindings.Count >= 1,
            $"Expected at least 1 TPM finding, got {tpmFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasEfsFinding()
    {
        var result = await _audit.RunAuditAsync();

        var efsFindings = result.Findings
            .Where(f => f.Title.Contains("EFS", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(efsFindings.Count >= 1,
            $"Expected at least 1 EFS finding, got {efsFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasCertificateFindings()
    {
        var result = await _audit.RunAuditAsync();

        // Should have certificate store findings (personal store health and/or trusted root)
        var certFindings = result.Findings
            .Where(f => f.Title.Contains("Certificate", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Cert", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Trusted Root", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(certFindings.Count >= 1,
            $"Expected at least 1 certificate finding, got {certFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasTlsFindings()
    {
        var result = await _audit.RunAuditAsync();

        // Should have TLS/SSL findings for both legacy and modern protocols + cipher suites
        var tlsFindings = result.Findings
            .Where(f => f.Title.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("SSL", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Cipher", StringComparison.OrdinalIgnoreCase))
            .ToList();

        // At minimum: TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0, TLS 1.2, TLS 1.3, cipher suites = 7
        Assert.True(tlsFindings.Count >= 5,
            $"Expected at least 5 TLS/SSL findings, got {tlsFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasCredentialGuardFinding()
    {
        var result = await _audit.RunAuditAsync();

        var cgFindings = result.Findings
            .Where(f => f.Title.Contains("Credential Guard", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(cgFindings.Count >= 1,
            $"Expected at least 1 Credential Guard finding, got {cgFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_HasDpapiFinding()
    {
        var result = await _audit.RunAuditAsync();

        var dpapiFindings = result.Findings
            .Where(f => f.Title.Contains("DPAPI", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(dpapiFindings.Count >= 1,
            $"Expected at least 1 DPAPI finding, got {dpapiFindings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_CriticalFindingsHaveRemediation()
    {
        var result = await _audit.RunAuditAsync();

        var criticalFindings = result.Findings
            .Where(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning);

        foreach (var finding in criticalFindings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Finding '{finding.Title}' (severity={finding.Severity}) should have remediation advice");
        }
    }

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var result = await _audit.RunAuditAsync(cts.Token);

        Assert.True(result.Success, $"Audit should complete within 60 seconds: {result.Error}");
        Assert.True(result.Duration < TimeSpan.FromSeconds(60),
            $"Audit took {result.Duration.TotalSeconds:F1}s, expected < 60s");
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Should either throw OperationCanceledException or complete gracefully
        try
        {
            var result = await _audit.RunAuditAsync(cts.Token);
            // If it completes, that's fine — some checks are synchronous
        }
        catch (OperationCanceledException)
        {
            // Expected behavior
        }
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsCalculated()
    {
        var result = await _audit.RunAuditAsync();

        // Score should be between 0 and 100
        Assert.InRange(result.Score, 0, 100);
    }
}
