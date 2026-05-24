// Tests for WinSentinel.Core.Licensing.LicenseVerifier.
//
// All keypairs here are generated in-process per test and never persisted.

using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using WinSentinel.Core.Licensing;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

public class LicenseVerifierTests : IDisposable
{
    private readonly string _tmpDir;

    public LicenseVerifierTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "winsentinel-lictests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    private static (byte[] pub, byte[] priv) GenerateKeypair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        return (
            ((Ed25519PublicKeyParameters)pair.Public).GetEncoded(),
            ((Ed25519PrivateKeyParameters)pair.Private).GetEncoded()
        );
    }

    private static string SignLicenseJson(byte[] priv, LicenseInfo info)
    {
        info.Signature = "";
        var sig = Ed25519Crypto.Sign(priv, info.CanonicalPayload());
        info.Signature = Convert.ToBase64String(sig);
        return JsonSerializer.Serialize(info);
    }

    [Fact]
    public void MissingLicenseFile_NotActivated()
    {
        var (pub, _) = GenerateKeypair();
        var v = new LicenseVerifier(pub, Path.Combine(_tmpDir, "absent.dat"));

        Assert.False(v.IsActivated);
        Assert.Null(v.Current);
        Assert.False(v.HasEntitlement("report.pdf"));
        Assert.False(v.HasEntitlement(""));
    }

    [Fact]
    public void TamperedLicense_Rejected()
    {
        var (pub, priv) = GenerateKeypair();
        var info = new LicenseInfo
        {
            Customer = "Acme",
            Plan = "pro",
            Entitlements = new() { "report.pdf" },
            Issued = DateTimeOffset.UtcNow.AddDays(-1),
            Expires = DateTimeOffset.UtcNow.AddYears(1),
        };
        var json = SignLicenseJson(priv, info);

        // Tamper: swap customer name after signing.
        var tampered = json.Replace("Acme", "Mallory");
        var path = Path.Combine(_tmpDir, "tampered.dat");
        File.WriteAllText(path, tampered);

        var v = new LicenseVerifier(pub, path);
        Assert.False(v.IsActivated);
        Assert.Null(v.Current);
    }

    [Fact]
    public void ExpiredLicense_Rejected()
    {
        var (pub, priv) = GenerateKeypair();
        var info = new LicenseInfo
        {
            Customer = "Acme",
            Plan = "pro",
            Entitlements = new() { "report.pdf" },
            Issued = DateTimeOffset.UtcNow.AddYears(-2),
            Expires = DateTimeOffset.UtcNow.AddDays(-1),
        };
        var json = SignLicenseJson(priv, info);
        var path = Path.Combine(_tmpDir, "expired.dat");
        File.WriteAllText(path, json);

        var v = new LicenseVerifier(pub, path);
        Assert.False(v.IsActivated);
    }

    [Fact]
    public void ValidLicense_EntitlementsQueryable()
    {
        var (pub, priv) = GenerateKeypair();
        var info = new LicenseInfo
        {
            Customer = "Acme",
            Plan = "team",
            Entitlements = new() { "report.pdf", "monitor.realtime" },
            Issued = DateTimeOffset.UtcNow.AddDays(-1),
            Expires = DateTimeOffset.UtcNow.AddYears(1),
        };
        var json = SignLicenseJson(priv, info);
        var path = Path.Combine(_tmpDir, "valid.dat");
        File.WriteAllText(path, json);

        var v = new LicenseVerifier(pub, path);

        Assert.True(v.IsActivated);
        Assert.NotNull(v.Current);
        Assert.Equal("Acme", v.Current!.Customer);
        Assert.Equal("team", v.Current.Plan);
        Assert.True(v.HasEntitlement("report.pdf"));
        Assert.True(v.HasEntitlement("REPORT.PDF")); // case-insensitive
        Assert.True(v.HasEntitlement("monitor.realtime"));
        Assert.False(v.HasEntitlement("scan.scheduled"));
    }

    [Fact]
    public void Activate_PersistsAndReloads()
    {
        var (pub, priv) = GenerateKeypair();
        var info = new LicenseInfo
        {
            Customer = "Acme",
            Plan = "pro",
            Entitlements = new() { "scan.scheduled" },
            Issued = DateTimeOffset.UtcNow.AddDays(-1),
            Expires = DateTimeOffset.UtcNow.AddYears(1),
        };
        var json = SignLicenseJson(priv, info);

        var path = Path.Combine(_tmpDir, "store.dat");
        var v = new LicenseVerifier(pub, path);

        var result = v.Activate(json);
        Assert.Equal("Acme", result.Customer);
        Assert.True(File.Exists(path));

        // Fresh verifier should load it back.
        var v2 = new LicenseVerifier(pub, path);
        Assert.True(v2.IsActivated);
        Assert.True(v2.HasEntitlement("scan.scheduled"));

        v2.Deactivate();
        Assert.False(File.Exists(path));
        Assert.False(v2.IsActivated);
    }

    [Fact]
    public void PlaceholderPublicKey_DisablesVerification()
    {
        // Sanity: while the embedded constant is still the placeholder
        // string, PublicKeyConfigured must be false. This guards against
        // accidentally turning on verification with a non-key string.
        Assert.False(LicenseVerifier.PublicKeyConfigured);
    }
}
