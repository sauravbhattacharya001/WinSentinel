using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Minimal Ed25519 helpers built on BouncyCastle (Ed25519 is not yet
/// available in the .NET 8 BCL). Used by <see cref="PluginHost"/> and
/// <see cref="Licensing.LicenseVerifier"/> to verify signatures.
/// </summary>
public static class Ed25519Crypto
{
    /// <summary>SHA-256 of <paramref name="bytes"/>.</summary>
    public static byte[] Sha256(byte[] bytes) => SHA256.HashData(bytes);

    /// <summary>
    /// Verify an Ed25519 signature.
    /// </summary>
    /// <param name="publicKey">32-byte raw Ed25519 public key.</param>
    /// <param name="message">Bytes that were signed.</param>
    /// <param name="signature">64-byte Ed25519 signature.</param>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Sign <paramref name="message"/> with a raw Ed25519 private key.
    /// Used by tests and by the offline key-generation tooling — never
    /// called from the shipped CLI.
    /// </summary>
    public static byte[] Sign(byte[] privateKey, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Decode a base64 string, returning null on any failure.</summary>
    public static byte[]? TryDecodeBase64(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        try { return Convert.FromBase64String(s); }
        catch { return null; }
    }
}
