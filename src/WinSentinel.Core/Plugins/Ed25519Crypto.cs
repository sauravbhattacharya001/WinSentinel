using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Thin wrapper around BouncyCastle's Ed25519 implementation. Only exposes
/// the operations the plugin host (and tests) need. Private-key code paths
/// are <c>internal</c> so production callers cannot accidentally invoke
/// signing — that lives in the offline tooling / private signing pipeline.
/// </summary>
public static class Ed25519Crypto
{
    public const int PublicKeySize = 32;
    public const int PrivateKeySize = 32;
    public const int SignatureSize = 64;

    /// <summary>
    /// Verifies an Ed25519 signature. Returns <c>false</c> on any failure
    /// (wrong length, malformed key, signature mismatch, exception).
    /// </summary>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey is null || message is null || signature is null) return false;
        if (publicKey.Length != PublicKeySize) return false;
        if (signature.Length != SignatureSize) return false;
        try
        {
            var pub = new Ed25519PublicKeyParameters(publicKey, 0);
            var verifier = new Ed25519Signer();
            verifier.Init(false, pub);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Decodes a base64-encoded blob, returning <c>null</c> on malformed input.
    /// Trims surrounding whitespace so manifests / constants tolerate copy-paste.
    /// </summary>
    public static byte[]? TryDecodeBase64(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        try
        {
            return Convert.FromBase64String(value.Trim());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Generates a fresh Ed25519 keypair using a cryptographically secure RNG.
    /// <para>Used by the offline <c>tools/GenerateKeypair</c> console app and
    /// by unit tests that need ephemeral keys. NEVER persisted to disk by
    /// this method.</para>
    /// </summary>
    internal static (byte[] PublicKey, byte[] PrivateKey) GenerateKeypair()
    {
        var random = new SecureRandom();
        var priv = new Ed25519PrivateKeyParameters(random);
        var pub = priv.GeneratePublicKey();
        return (pub.GetEncoded(), priv.GetEncoded());
    }

    /// <summary>
    /// Signs <paramref name="message"/> with the given Ed25519 private key.
    /// Internal because production code must never sign — only verify.
    /// </summary>
    internal static byte[] Sign(byte[] privateKey, byte[] message)
    {
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));
        if (message is null) throw new ArgumentNullException(nameof(message));
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException($"Private key must be {PrivateKeySize} bytes.", nameof(privateKey));

        var priv = new Ed25519PrivateKeyParameters(privateKey, 0);
        var signer = new Ed25519Signer();
        signer.Init(true, priv);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }
}
