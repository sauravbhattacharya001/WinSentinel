using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Tests for Ed25519Crypto.Fingerprint and FingerprintShort methods.
/// Issue: #197
/// </summary>
[Trait("Category", "BVT")]
public class FingerprintTests
{
    [Fact]
    public void Fingerprint_ValidKey_ReturnsSha256ColonSeparated()
    {
        var (pub, _) = Ed25519Crypto.GenerateKeypair();
        var b64 = Convert.ToBase64String(pub);

        var fp = Ed25519Crypto.Fingerprint(b64);

        Assert.NotNull(fp);
        Assert.StartsWith("SHA256:", fp);
        // Full SHA-256 = 32 bytes = 64 hex chars + 31 colons = 95 chars + "SHA256:" prefix
        Assert.Equal(7 + 95, fp!.Length);
        // All lowercase hex + colons
        Assert.Matches(@"^SHA256:[0-9a-f:]+$", fp);
    }

    [Fact]
    public void FingerprintShort_ValidKey_Returns8BytePrefix()
    {
        var (pub, _) = Ed25519Crypto.GenerateKeypair();
        var b64 = Convert.ToBase64String(pub);

        var fp = Ed25519Crypto.FingerprintShort(b64);

        Assert.NotNull(fp);
        Assert.StartsWith("SHA256:", fp);
        // 8 bytes = 16 hex chars + 7 colons = 23 chars + "SHA256:" prefix
        Assert.Equal(7 + 23, fp!.Length);
    }

    [Fact]
    public void Fingerprint_NullInput_ReturnsNull()
    {
        Assert.Null(Ed25519Crypto.Fingerprint(null));
        Assert.Null(Ed25519Crypto.FingerprintShort(null));
    }

    [Fact]
    public void Fingerprint_InvalidBase64_ReturnsNull()
    {
        Assert.Null(Ed25519Crypto.Fingerprint("not-valid-base64!!!"));
        Assert.Null(Ed25519Crypto.FingerprintShort("not-valid-base64!!!"));
    }

    [Fact]
    public void Fingerprint_WrongKeyLength_ReturnsNull()
    {
        var shortKey = Convert.ToBase64String(new byte[16]);
        Assert.Null(Ed25519Crypto.Fingerprint(shortKey));
    }

    [Fact]
    public void Fingerprint_Deterministic()
    {
        var (pub, _) = Ed25519Crypto.GenerateKeypair();
        var b64 = Convert.ToBase64String(pub);

        var fp1 = Ed25519Crypto.Fingerprint(b64);
        var fp2 = Ed25519Crypto.Fingerprint(b64);

        Assert.Equal(fp1, fp2);
    }

    [Fact]
    public void FingerprintShort_IsPrefixOfFull()
    {
        var (pub, _) = Ed25519Crypto.GenerateKeypair();
        var b64 = Convert.ToBase64String(pub);

        var full = Ed25519Crypto.Fingerprint(b64)!;
        var short_ = Ed25519Crypto.FingerprintShort(b64)!;

        Assert.StartsWith(short_, full);
    }
}
