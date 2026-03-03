using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits the Windows certificate store for security issues including
/// expired certificates, soon-to-expire certificates, weak signature
/// algorithms, untrusted root CAs, and self-signed certificates in
/// trusted stores.
/// </summary>
public class CertificateAudit : IAuditModule
{
    public string Name => "Certificate Audit";
    public string Category => "Certificates";
    public string Description => "Checks Windows certificate stores for expired, weak, or untrusted certificates.";

    /// <summary>
    /// Days before expiry to raise a warning. Defaults to 30.
    /// </summary>
    public int ExpiryWarningDays { get; set; } = 30;

    /// <summary>
    /// Days before expiry to raise a critical alert. Defaults to 7.
    /// </summary>
    public int ExpiryCriticalDays { get; set; } = 7;

    /// <summary>
    /// Minimum acceptable RSA key size in bits. Defaults to 2048.
    /// </summary>
    public int MinimumRsaKeySize { get; set; } = 2048;

    /// <summary>
    /// Signature algorithms considered weak or deprecated.
    /// </summary>
    public static readonly HashSet<string> WeakAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "sha1RSA", "md5RSA", "md2RSA",
        "1.2.840.113549.1.1.5",  // sha1WithRSAEncryption OID
        "1.2.840.113549.1.1.4",  // md5WithRSAEncryption OID
        "1.2.840.113549.1.1.2",  // md2WithRSAEncryption OID
    };

    /// <summary>
    /// Certificate stores to scan. Can be overridden for testing.
    /// </summary>
    public IReadOnlyList<(StoreName Store, StoreLocation Location, string Label)> StoresToScan { get; set; } =
        new List<(StoreName, StoreLocation, string)>
        {
            (StoreName.My, StoreLocation.CurrentUser, "Personal (Current User)"),
            (StoreName.My, StoreLocation.LocalMachine, "Personal (Local Machine)"),
            (StoreName.Root, StoreLocation.CurrentUser, "Trusted Root CAs (Current User)"),
            (StoreName.Root, StoreLocation.LocalMachine, "Trusted Root CAs (Local Machine)"),
            (StoreName.CertificateAuthority, StoreLocation.CurrentUser, "Intermediate CAs (Current User)"),
            (StoreName.CertificateAuthority, StoreLocation.LocalMachine, "Intermediate CAs (Local Machine)"),
            (StoreName.TrustedPublisher, StoreLocation.LocalMachine, "Trusted Publishers (Local Machine)"),
        };

    public Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            var allCerts = new List<CertificateInfo>();

            foreach (var (storeName, location, label) in StoresToScan)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var certs = ScanStore(storeName, location, label);
                allCerts.AddRange(certs);
            }

            AnalyzeCertificates(allCerts, result);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return Task.FromResult(result);
    }

    /// <summary>
    /// Scans a single certificate store and extracts certificate metadata.
    /// </summary>
    public List<CertificateInfo> ScanStore(StoreName storeName, StoreLocation location, string label)
    {
        var certs = new List<CertificateInfo>();

        try
        {
            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            foreach (var cert in store.Certificates)
            {
                try
                {
                    certs.Add(ExtractCertInfo(cert, label, storeName));
                }
                catch
                {
                    // Skip malformed certificates
                }
                finally
                {
                    cert.Dispose();
                }
            }
        }
        catch
        {
            // Store may not exist or be inaccessible — skip
        }

        return certs;
    }

    /// <summary>
    /// Extracts relevant metadata from an X509Certificate2 instance.
    /// </summary>
    public CertificateInfo ExtractCertInfo(X509Certificate2 cert, string storeLabel, StoreName storeName)
    {
        var now = DateTimeOffset.UtcNow;
        int? keySize = null;
        string? keyAlgorithm = null;

        try
        {
            var pubKey = cert.PublicKey;
            keyAlgorithm = pubKey.Oid.FriendlyName ?? pubKey.Oid.Value;

            if (pubKey.Key is RSA rsa)
                keySize = rsa.KeySize;
            else if (pubKey.Key is ECDsa ecdsa)
                keySize = ecdsa.KeySize;
            else if (pubKey.Key is DSA dsa)
                keySize = dsa.KeySize;
        }
        catch
        {
            // Key extraction may fail for some certificate types
        }

        return new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            NotBefore = new DateTimeOffset(cert.NotBefore, TimeSpan.Zero),
            NotAfter = new DateTimeOffset(cert.NotAfter, TimeSpan.Zero),
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "Unknown",
            KeyAlgorithm = keyAlgorithm ?? "Unknown",
            KeySize = keySize,
            IsSelfSigned = cert.Subject == cert.Issuer,
            StoreLabel = storeLabel,
            StoreName = storeName,
            DaysUntilExpiry = (int)(cert.NotAfter.ToUniversalTime() - now.UtcDateTime).TotalDays,
            IsExpired = now.UtcDateTime > cert.NotAfter.ToUniversalTime(),
        };
    }

    /// <summary>
    /// Analyzes collected certificate metadata and produces findings.
    /// </summary>
    public void AnalyzeCertificates(List<CertificateInfo> certs, AuditResult result)
    {
        int expired = 0, expiringSoon = 0, weakAlgo = 0, weakKey = 0;
        int selfSignedInTrust = 0, totalScanned = 0;

        foreach (var cert in certs)
        {
            totalScanned++;

            // 1. Expired certificates
            if (cert.IsExpired)
            {
                expired++;
                result.Findings.Add(Finding.Critical(
                    $"Expired certificate: {FormatSubject(cert.Subject)}",
                    $"Certificate in '{cert.StoreLabel}' expired {Math.Abs(cert.DaysUntilExpiry)} days ago " +
                    $"(expired {cert.NotAfter:yyyy-MM-dd}). Thumbprint: {cert.Thumbprint}.",
                    Category,
                    "Remove the expired certificate from the store or renew it.",
                    $"certutil -delstore \"{cert.StoreName}\" \"{cert.Thumbprint}\""));
                continue; // Don't double-flag expired certs for other issues
            }

            // 2. Expiring soon (critical: within 7 days)
            if (cert.DaysUntilExpiry <= ExpiryCriticalDays)
            {
                expiringSoon++;
                result.Findings.Add(Finding.Critical(
                    $"Certificate expiring in {cert.DaysUntilExpiry} day(s): {FormatSubject(cert.Subject)}",
                    $"Certificate in '{cert.StoreLabel}' expires {cert.NotAfter:yyyy-MM-dd} " +
                    $"({cert.DaysUntilExpiry} days remaining). Thumbprint: {cert.Thumbprint}.",
                    Category,
                    "Renew or replace this certificate immediately."));
            }
            // Warning: within 30 days
            else if (cert.DaysUntilExpiry <= ExpiryWarningDays)
            {
                expiringSoon++;
                result.Findings.Add(Finding.Warning(
                    $"Certificate expiring in {cert.DaysUntilExpiry} day(s): {FormatSubject(cert.Subject)}",
                    $"Certificate in '{cert.StoreLabel}' expires {cert.NotAfter:yyyy-MM-dd} " +
                    $"({cert.DaysUntilExpiry} days remaining). Thumbprint: {cert.Thumbprint}.",
                    Category,
                    "Plan to renew or replace this certificate before it expires."));
            }

            // 3. Weak signature algorithm
            if (IsWeakAlgorithm(cert.SignatureAlgorithm))
            {
                weakAlgo++;
                result.Findings.Add(Finding.Warning(
                    $"Weak signature algorithm: {FormatSubject(cert.Subject)}",
                    $"Certificate in '{cert.StoreLabel}' uses {cert.SignatureAlgorithm} which is " +
                    "considered cryptographically weak. Thumbprint: {cert.Thumbprint}.",
                    Category,
                    "Replace with a certificate using SHA-256 or stronger signature algorithm."));
            }

            // 4. Small RSA key size
            if (cert.KeyAlgorithm?.Contains("RSA", StringComparison.OrdinalIgnoreCase) == true
                && cert.KeySize.HasValue && cert.KeySize.Value < MinimumRsaKeySize)
            {
                weakKey++;
                result.Findings.Add(Finding.Warning(
                    $"Weak RSA key ({cert.KeySize} bits): {FormatSubject(cert.Subject)}",
                    $"Certificate in '{cert.StoreLabel}' has a {cert.KeySize}-bit RSA key. " +
                    $"Minimum recommended is {MinimumRsaKeySize} bits. Thumbprint: {cert.Thumbprint}.",
                    Category,
                    $"Replace with a certificate using at least {MinimumRsaKeySize}-bit RSA or ECC key."));
            }

            // 5. Self-signed certificate in a trusted store
            if (cert.IsSelfSigned && cert.StoreName == System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher)
            {
                selfSignedInTrust++;
                result.Findings.Add(Finding.Warning(
                    $"Self-signed certificate in Trusted Publishers: {FormatSubject(cert.Subject)}",
                    $"A self-signed certificate was found in the Trusted Publishers store. " +
                    $"This could allow unsigned or malicious code to be treated as trusted. " +
                    $"Thumbprint: {cert.Thumbprint}.",
                    Category,
                    "Verify this certificate is intentional. Remove if not recognized."));
            }
        }

        // Summary findings
        if (expired == 0 && expiringSoon == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No expired or expiring certificates",
                $"All {totalScanned} certificates across all stores are valid and not expiring within {ExpiryWarningDays} days.",
                Category));
        }

        if (weakAlgo == 0 && weakKey == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No weak cryptographic algorithms detected",
                $"All scanned certificates use acceptable signature algorithms and key sizes.",
                Category));
        }

        result.Findings.Add(Finding.Info(
            $"Certificate store summary: {totalScanned} certificates scanned",
            $"Scanned {StoresToScan.Count} certificate stores. " +
            $"Found: {expired} expired, {expiringSoon} expiring soon, " +
            $"{weakAlgo} weak algorithms, {weakKey} weak keys, " +
            $"{selfSignedInTrust} self-signed in trusted stores.",
            Category));
    }

    /// <summary>
    /// Checks whether a signature algorithm is considered weak.
    /// </summary>
    public static bool IsWeakAlgorithm(string algorithm)
    {
        return WeakAlgorithms.Contains(algorithm);
    }

    /// <summary>
    /// Formats a certificate subject for display, extracting the CN if present.
    /// </summary>
    public static string FormatSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return "(no subject)";

        // Extract CN= value
        var cnStart = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (cnStart < 0) return Truncate(subject, 60);

        var valueStart = cnStart + 3;
        var end = subject.IndexOf(',', valueStart);
        var cn = end >= 0 ? subject[valueStart..end] : subject[valueStart..];
        return Truncate(cn.Trim(), 60);
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";
    }

    /// <summary>
    /// Metadata extracted from a certificate for analysis.
    /// </summary>
    public class CertificateInfo
    {
        public string Subject { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string Thumbprint { get; set; } = "";
        public DateTimeOffset NotBefore { get; set; }
        public DateTimeOffset NotAfter { get; set; }
        public string SignatureAlgorithm { get; set; } = "";
        public string? KeyAlgorithm { get; set; }
        public int? KeySize { get; set; }
        public bool IsSelfSigned { get; set; }
        public string StoreLabel { get; set; } = "";
        public StoreName StoreName { get; set; }
        public int DaysUntilExpiry { get; set; }
        public bool IsExpired { get; set; }
    }
}
