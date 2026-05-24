// One-shot Ed25519 keypair generator for WinSentinel plugin signing.
//
// Prints both halves to stdout and exits. Nothing is ever written to
// disk by this program. The OPERATOR is responsible for moving the
// private half into a password manager immediately and not leaving it
// in shell history.
//
// Run from this directory with:  dotnet run
//
// See ../../docs/plugin-key-setup.md for full instructions.

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

var gen = new Ed25519KeyPairGenerator();
gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
var pair = gen.GenerateKeyPair();

var priv = (Ed25519PrivateKeyParameters)pair.Private;
var pub = (Ed25519PublicKeyParameters)pair.Public;

var pubBase64 = Convert.ToBase64String(pub.GetEncoded());
var privBase64 = Convert.ToBase64String(priv.GetEncoded());

Console.WriteLine("WinSentinel Ed25519 keypair (generated in-memory; nothing written to disk)");
Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine();
Console.WriteLine("Public  (embed in source as LicenseVerifier.EmbeddedPublicKeyBase64):");
Console.WriteLine($"  {pubBase64}");
Console.WriteLine();
Console.WriteLine("Private (store in password manager; NEVER commit, NEVER paste into chat):");
Console.WriteLine($"  {privBase64}");
Console.WriteLine();
Console.WriteLine("Next steps: see docs/plugin-key-setup.md");
