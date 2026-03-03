using System.Security.Cryptography.X509Certificates;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.CertificateAudit;

namespace WinSentinel.Tests.Audits;

public class CertificateAuditTests
{
    private readonly CertificateAudit _audit;

    public CertificateAuditTests()
    {
        _audit = new CertificateAudit();
    }

    private static CertificateInfo MakeValidCert(
        string subject = "CN=example.com",
        int daysUntilExpiry = 365,
        string algorithm = "sha256RSA",
        int keySize = 2048,
        string storeLabel = "Personal (Current User)",
        StoreName storeName = StoreName.My)
    {
        return new CertificateInfo
        {
            Subject = subject,
            Issuer = "CN=Trusted CA",
            Thumbprint = Guid.NewGuid().ToString("N").ToUpper(),
            NotBefore = DateTimeOffset.UtcNow.AddDays(-30),
            NotAfter = DateTimeOffset.UtcNow.AddDays(daysUntilExpiry),
            SignatureAlgorithm = algorithm,
            KeyAlgorithm = "RSA",
            KeySize = keySize,
            IsSelfSigned = false,
            StoreLabel = storeLabel,
            StoreName = storeName,
            DaysUntilExpiry = daysUntilExpiry,
            IsExpired = daysUntilExpiry < 0,
        };
    }

    // ─── Expired Certificates ──────────────────────────────────

    [Fact]
    public void AnalyzeCertificates_ExpiredCert_CreatesCriticalFinding()
    {
        var cert = MakeValidCert(daysUntilExpiry: -10);
        cert.IsExpired = true;
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Expired certificate"));
    }

    [Fact]
    public void AnalyzeCertificates_ExpiredCert_IncludesRemovalCommand()
    {
        var cert = MakeValidCert(daysUntilExpiry: -5);
        cert.IsExpired = true;
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        var finding = result.Findings.First(f => f.Title.Contains("Expired certificate"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("certutil", finding.FixCommand);
    }

    [Fact]
    public void AnalyzeCertificates_ExpiredCert_NotDoubleFlagged()
    {
        // An expired cert with weak algorithm should only be flagged as expired,
        // not additionally for weak algorithm
        var cert = MakeValidCert(daysUntilExpiry: -10, algorithm: "sha1RSA");
        cert.IsExpired = true;
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        var criticals = result.Findings.Where(f =>
            f.Severity == Severity.Critical && f.Title.Contains(FormatSubject(cert.Subject))).ToList();
        Assert.Single(criticals); // Only the expired finding, not also weak algo
    }

    // ─── Expiring Soon ─────────────────────────────────────────

    [Fact]
    public void AnalyzeCertificates_ExpiringWithin7Days_CreatesCriticalFinding()
    {
        var cert = MakeValidCert(daysUntilExpiry: 5);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("expiring in 5 day(s)"));
    }

    [Fact]
    public void AnalyzeCertificates_ExpiringWithin30Days_CreatesWarningFinding()
    {
        var cert = MakeValidCert(daysUntilExpiry: 20);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("expiring in 20 day(s)"));
    }

    [Fact]
    public void AnalyzeCertificates_NotExpiringSoon_NoExpiryFindings()
    {
        var cert = MakeValidCert(daysUntilExpiry: 365);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("expiring in"));
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("No expired"));
    }

    // ─── Weak Algorithms ───────────────────────────────────────

    [Theory]
    [InlineData("sha1RSA")]
    [InlineData("md5RSA")]
    [InlineData("md2RSA")]
    [InlineData("1.2.840.113549.1.1.5")]
    public void AnalyzeCertificates_WeakAlgorithm_CreatesWarning(string algo)
    {
        var cert = MakeValidCert(algorithm: algo);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Weak signature algorithm"));
    }

    [Theory]
    [InlineData("sha256RSA")]
    [InlineData("sha384RSA")]
    [InlineData("sha512RSA")]
    public void AnalyzeCertificates_StrongAlgorithm_NoWeakAlgoWarning(string algo)
    {
        var cert = MakeValidCert(algorithm: algo);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Weak signature algorithm"));
    }

    [Fact]
    public void IsWeakAlgorithm_CaseInsensitive()
    {
        Assert.True(CertificateAudit.IsWeakAlgorithm("SHA1RSA"));
        Assert.True(CertificateAudit.IsWeakAlgorithm("Sha1Rsa"));
        Assert.False(CertificateAudit.IsWeakAlgorithm("sha256RSA"));
    }

    // ─── Weak Key Size ─────────────────────────────────────────

    [Fact]
    public void AnalyzeCertificates_SmallRsaKey_CreatesWarning()
    {
        var cert = MakeValidCert(keySize: 1024);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Weak RSA key (1024 bits)"));
    }

    [Fact]
    public void AnalyzeCertificates_AdequateRsaKey_NoWeakKeyWarning()
    {
        var cert = MakeValidCert(keySize: 4096);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Weak RSA key"));
    }

    [Fact]
    public void AnalyzeCertificates_NonRsaKey_NoWeakKeyWarning()
    {
        var cert = MakeValidCert(keySize: 256);
        cert.KeyAlgorithm = "ECC"; // ECC 256 is fine
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Weak RSA key"));
    }

    // ─── Self-Signed in Trusted Store ──────────────────────────

    [Fact]
    public void AnalyzeCertificates_SelfSignedInTrustedPublishers_CreatesWarning()
    {
        var cert = MakeValidCert(storeName: StoreName.TrustedPublisher, storeLabel: "Trusted Publishers");
        cert.IsSelfSigned = true;
        cert.Issuer = cert.Subject;
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Self-signed certificate in Trusted Publishers"));
    }

    [Fact]
    public void AnalyzeCertificates_SelfSignedInPersonalStore_NoSelfSignedWarning()
    {
        // Self-signed in Personal store is normal (e.g., dev certs)
        var cert = MakeValidCert(storeName: StoreName.My);
        cert.IsSelfSigned = true;
        cert.Issuer = cert.Subject;
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Self-signed certificate in Trusted"));
    }

    // ─── Summary Findings ──────────────────────────────────────

    [Fact]
    public void AnalyzeCertificates_AllClean_ProducesPassAndInfoFindings()
    {
        var certs = new List<CertificateInfo>
        {
            MakeValidCert(subject: "CN=cert1.example.com"),
            MakeValidCert(subject: "CN=cert2.example.com"),
        };
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(certs, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("No expired"));
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("No weak cryptographic"));
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("2 certificates scanned"));
    }

    [Fact]
    public void AnalyzeCertificates_EmptyList_ProducesPassAndZeroCountSummary()
    {
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo>(), result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("0 certificates scanned"));
    }

    // ─── FormatSubject ─────────────────────────────────────────

    [Theory]
    [InlineData("CN=example.com, O=Example Inc", "example.com")]
    [InlineData("CN=My Certificate", "My Certificate")]
    [InlineData("O=No Common Name", "O=No Common Name")]
    [InlineData("", "(no subject)")]
    [InlineData(null, "(no subject)")]
    public void FormatSubject_ExtractsCommonName(string? subject, string expected)
    {
        var result = CertificateAudit.FormatSubject(subject!);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void FormatSubject_TruncatesLongNames()
    {
        var longCn = "CN=" + new string('A', 100);
        var result = CertificateAudit.FormatSubject(longCn);
        Assert.True(result.Length <= 60);
        Assert.EndsWith("...", result);
    }

    // ─── Configuration ─────────────────────────────────────────

    [Fact]
    public void CustomExpiryThresholds_AreRespected()
    {
        var audit = new CertificateAudit
        {
            ExpiryWarningDays = 60,
            ExpiryCriticalDays = 14
        };

        // 10 days: within custom critical (14) but outside default (7)
        var cert = MakeValidCert(daysUntilExpiry: 10);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("expiring"));
    }

    [Fact]
    public void CustomMinKeySize_IsRespected()
    {
        var audit = new CertificateAudit { MinimumRsaKeySize = 4096 };

        // 2048 is below the custom minimum
        var cert = MakeValidCert(keySize: 2048);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Weak RSA key (2048 bits)"));
    }

    // ─── Multiple Issues on One Cert ───────────────────────────

    [Fact]
    public void AnalyzeCertificates_MultipleIssues_AllFlagged()
    {
        // Cert with both weak algorithm AND small key — both should be flagged
        var cert = MakeValidCert(algorithm: "sha1RSA", keySize: 1024);
        var result = new AuditResult { ModuleName = "Certificate Audit", Category = "Certificates" };

        _audit.AnalyzeCertificates(new List<CertificateInfo> { cert }, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Weak signature algorithm"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Weak RSA key"));
    }

    // ─── RunAuditAsync ─────────────────────────────────────────

    [Fact]
    public async Task RunAuditAsync_ReturnsResult()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotNull(result);
        Assert.Equal("Certificate Audit", result.ModuleName);
        Assert.Equal("Certificates", result.Category);
        Assert.True(result.Success);
        Assert.True(result.EndTime >= result.StartTime);
        // Should have at least the summary Info finding
        Assert.Contains(result.Findings, f => f.Severity == Severity.Info);
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _audit.RunAuditAsync(cts.Token));
    }

    // ─── Module Properties ─────────────────────────────────────

    [Fact]
    public void ModuleProperties_AreSet()
    {
        Assert.Equal("Certificate Audit", _audit.Name);
        Assert.Equal("Certificates", _audit.Category);
        Assert.False(string.IsNullOrEmpty(_audit.Description));
    }
}
