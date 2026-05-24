// WinSentinel plugin keypair generator — OFFLINE, MANUAL, ONE-TIME.
//
// SECURITY NOTES — READ BEFORE RUNNING:
//   * This tool prints a fresh Ed25519 keypair to STDOUT exactly once and exits.
//   * The PRIVATE KEY grants the ability to sign plugins that any WinSentinel
//     build with the matching embedded public key will trust. Treat it like a
//     root signing key: copy it into a password manager IMMEDIATELY and never
//     paste it into chat logs, status files, shell history, screen shares,
//     issue trackers, screenshots, cloud notes, or git.
//   * This tool NEVER writes to disk. There is no flag to make it. Re-run it
//     if you lose the keys — there is no recovery.
//   * The matching public key is embedded into the product by editing
//     LicenseManager.EmbeddedPublicKeyBase64 (see docs/plugin-key-setup.md).
//
// USAGE:
//   dotnet run --project tools/GenerateKeypair
//
// The csproj is deliberately NOT in WinSentinel.sln so CI does not build it.

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

var random = new SecureRandom();
var priv = new Ed25519PrivateKeyParameters(random);
var pub = priv.GeneratePublicKey();

var publicB64 = Convert.ToBase64String(pub.GetEncoded());
var privateB64 = Convert.ToBase64String(priv.GetEncoded());

Console.WriteLine("# WinSentinel plugin signing keypair");
Console.WriteLine("# Generated: " + DateTimeOffset.UtcNow.ToString("o"));
Console.WriteLine("# Copy the PRIVATE key into a password manager NOW. This tool does not persist it.");
Console.WriteLine();
Console.WriteLine("public:  " + publicB64);
Console.WriteLine("private: " + privateB64);

return 0;
