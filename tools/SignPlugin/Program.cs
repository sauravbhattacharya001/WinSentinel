// WinSentinel plugin signing helper — OFFLINE, MANUAL.
//
// SECURITY NOTES:
//   * This tool reads an Ed25519 private key from a file you specify.
//   * It NEVER writes the private key anywhere. It reads, signs, and forgets.
//   * The private key file should live in a password-manager-exported temp file
//     that you shred immediately after use.
//   * The .sig sidecar produced by --output-sidecar is the ONLY artifact. The
//     DLL bytes are never modified.
//
// USAGE:
//   dotnet run --project tools/SignPlugin -- <dll-path> <privkey-file> [--output-sidecar]
//
//   <dll-path>         Path to the plugin DLL to sign.
//   <privkey-file>     Path to a file containing the base64-encoded Ed25519
//                      private key (32 bytes decoded). May also contain the
//                      "private: " prefix from GenerateKeypair output.
//   --output-sidecar   Write signature to <dll-path>.sig (raw 64 bytes).
//                      Without this flag, signature is only printed to stdout.
//
// EXIT CODES:
//   0  Success
//   1  Usage error / file not found
//   2  Invalid key (wrong size, malformed base64)
//   3  Signing failed

using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: SignPlugin <dll-path> <privkey-file> [--output-sidecar]");
    return 1;
}

var dllPath = args[0];
var privkeyPath = args[1];
bool outputSidecar = args.Length > 2 && args[2] == "--output-sidecar";

if (!File.Exists(dllPath))
{
    Console.Error.WriteLine($"Error: DLL not found: {dllPath}");
    return 1;
}

if (!File.Exists(privkeyPath))
{
    Console.Error.WriteLine($"Error: Private key file not found: {privkeyPath}");
    return 1;
}

// Read and parse private key.
byte[] privKeyBytes;
try
{
    var raw = File.ReadAllText(privkeyPath).Trim();
    // Strip "private: " prefix if present (from GenerateKeypair output).
    if (raw.StartsWith("private:", StringComparison.OrdinalIgnoreCase))
        raw = raw.Substring(raw.IndexOf(':') + 1).Trim();
    privKeyBytes = Convert.FromBase64String(raw);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: Cannot parse private key: {ex.Message}");
    return 2;
}

if (privKeyBytes.Length != 32)
{
    Console.Error.WriteLine($"Error: Private key must be 32 bytes, got {privKeyBytes.Length}.");
    return 2;
}

// Compute SHA-256 of DLL.
byte[] dllBytes = File.ReadAllBytes(dllPath);
byte[] hash = SHA256.HashData(dllBytes);

// Sign.
byte[] signature;
try
{
    var priv = new Ed25519PrivateKeyParameters(privKeyBytes, 0);
    var signer = new Ed25519Signer();
    signer.Init(true, priv);
    signer.BlockUpdate(hash, 0, hash.Length);
    signature = signer.GenerateSignature();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: Signing failed: {ex.Message}");
    return 3;
}

var signatureB64 = Convert.ToBase64String(signature);
Console.WriteLine(signatureB64);

if (outputSidecar)
{
    var sidecarPath = dllPath + ".sig";
    File.WriteAllBytes(sidecarPath, signature);
    Console.Error.WriteLine($"Wrote {signature.Length}-byte signature to {sidecarPath}");
}

return 0;
