// WinSentinel test license issuer — DEV/TEST ONLY.
//
// Generates a well-formed license key + record that LicenseManager will
// accept when the environment variable WINSENTINEL_DEV_MODE=1 is set.
//
// This tool uses a HARDCODED dev-only Ed25519 keypair. The corresponding
// dev public key is recognized by LicenseManager only in dev mode.
//
// USAGE:
//   dotnet run --project tools/IssueTestLicense -- [options]
//
//   --tier <individual|team>   License tier (default: individual)
//   --days <N>                 Validity in days (default: 30)
//   --email <addr>             Contact email (default: dev@test.local)
//   --output <path>            Write license.json to this path instead of stdout
//
// OUTPUT:
//   Prints the license.json content (ready to drop into %APPDATA%\WinSentinel\)
//   and the license key to stderr for use with `winsentinel pro activate`.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// ═══════════════════════════════════════════════════════════════════════
// DEV KEYPAIR — NEVER use these for production. They exist solely so
// end-to-end plugin tests can activate a license without standing up
// the full Stripe→license-issuer pipeline.
//
// These are the well-known WinSentinel dev signing keys. LicenseManager
// will only honor envelopes signed by this key when WINSENTINEL_DEV_MODE=1.
// ═══════════════════════════════════════════════════════════════════════
const string DevPrivateKeyB64 = "xJ3r0fN7y2kLwBqM5DvHmT8sAeGpYcKjRgUiWnOlZdQ=";
const string DevPublicKeyB64 = "Ht9bWfK3jRmCxN5vQyE8pLsAuDgZoTk2nJhYeXwVrMc=";

// Parse args
string tier = "individual";
int days = 30;
string email = "dev@test.local";
string? outputPath = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--tier" when i + 1 < args.Length: tier = args[++i]; break;
        case "--days" when i + 1 < args.Length: days = int.Parse(args[++i]); break;
        case "--email" when i + 1 < args.Length: email = args[++i]; break;
        case "--output" when i + 1 < args.Length: outputPath = args[++i]; break;
    }
}

if (tier != "individual" && tier != "team")
{
    Console.Error.WriteLine("Error: --tier must be 'individual' or 'team'");
    return 1;
}

// Generate a deterministic-looking but random test key
var rng = RandomNumberGenerator.Create();
var keyBytes = new byte[12];
rng.GetBytes(keyBytes);
string CrockfordGroup(byte[] b, int offset)
{
    const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    var sb = new StringBuilder(4);
    for (int j = 0; j < 4; j++)
        sb.Append(alphabet[b[offset + j] % 32]);
    return sb.ToString();
}
var licenseKey = $"WSP-{CrockfordGroup(keyBytes, 0)}-{CrockfordGroup(keyBytes, 4)}-{CrockfordGroup(keyBytes, 8)}";

var now = DateTimeOffset.UtcNow;
var expiresAt = now.AddDays(days);

var record = new
{
    schema_version = 1,
    tier,
    key = licenseKey,
    email,
    issued_at = now.ToString("o"),
    expires_at = expiresAt.ToString("o"),
    dev_mode = true,
    dev_public_key = DevPublicKeyB64,
};

var jsonOpts = new JsonSerializerOptions { WriteIndented = true };
var json = JsonSerializer.Serialize(record, jsonOpts);

if (outputPath != null)
{
    var dir = Path.GetDirectoryName(outputPath);
    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    File.WriteAllText(outputPath, json);
    Console.Error.WriteLine($"License written to: {outputPath}");
}
else
{
    Console.WriteLine(json);
}

Console.Error.WriteLine();
Console.Error.WriteLine("═══════════════════════════════════════════════════════════");
Console.Error.WriteLine("  TEST LICENSE ISSUED (dev mode only)");
Console.Error.WriteLine($"  Key:     {licenseKey}");
Console.Error.WriteLine($"  Tier:    {tier}");
Console.Error.WriteLine($"  Expires: {expiresAt:yyyy-MM-dd}");
Console.Error.WriteLine();
Console.Error.WriteLine("  To activate:");
Console.Error.WriteLine($"    set WINSENTINEL_DEV_MODE=1");
Console.Error.WriteLine($"    winsentinel pro activate --key {licenseKey} --allow-test-license");
Console.Error.WriteLine("═══════════════════════════════════════════════════════════");

return 0;
