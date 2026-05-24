// Tests for WinSentinel.Core.Plugins.PluginHost.
//
// All keypairs in this file are generated in-process for the duration of
// a single test and never persisted. They are not the production key
// (the production key remains a placeholder in source until the founder
// generates one out-of-band per docs/plugin-key-setup.md).

using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using WinSentinel.Core.Licensing;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

public class PluginHostTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly List<string> _logs = new();
    private readonly Action<string> _log;

    public PluginHostTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "winsentinel-plugintests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        _log = msg => _logs.Add(msg);
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

    private LicenseVerifier MakeLicenseVerifier(byte[] publicKey, params string[] entitlements)
    {
        // Returns a verifier with a synthetic, valid, non-expired license
        // signed with a private key derived from `publicKey` is NOT possible —
        // tests own the private key, so pass it through MakeSignedLicense.
        throw new NotSupportedException("Use MakeSignedLicense + Activate.");
    }

    private LicenseVerifier MakeLicenseWith(byte[] pub, byte[] priv, params string[] entitlements)
    {
        var info = new LicenseInfo
        {
            Customer = "Test Customer",
            Plan = "pro",
            Entitlements = entitlements.ToList(),
            Issued = DateTimeOffset.UtcNow.AddDays(-1),
            Expires = DateTimeOffset.UtcNow.AddYears(1),
            Signature = "",
        };
        var sig = Ed25519Crypto.Sign(priv, info.CanonicalPayload());
        info.Signature = Convert.ToBase64String(sig);

        var json = JsonSerializer.Serialize(info);
        var path = Path.Combine(_tmpDir, "license-" + Guid.NewGuid().ToString("N") + ".dat");
        File.WriteAllText(path, json);

        var v = new LicenseVerifier(pub, path);
        return v;
    }

    private void CopyTestPluginDll(string destDir, out string dllPath)
    {
        // The test plugin project is referenced; its DLL sits next to the
        // test DLL in the test output directory.
        var here = AppContext.BaseDirectory;
        var src = Path.Combine(here, "WinSentinel.TestPlugin.dll");
        Assert.True(File.Exists(src), $"TestPlugin not found at {src}; ProjectReference should have copied it.");
        dllPath = Path.Combine(destDir, "WinSentinel.TestPlugin.dll");
        File.Copy(src, dllPath, overwrite: true);
    }

    private void WriteManifest(string dllPath, byte[]? priv, string entitlement = "winsentinel.test.stub", string? overrideSignatureBase64 = null)
    {
        var name = Path.GetFileNameWithoutExtension(dllPath);
        var manifestPath = Path.Combine(Path.GetDirectoryName(dllPath)!, name + ".plugin.json");

        string sigBase64;
        if (overrideSignatureBase64 != null)
        {
            sigBase64 = overrideSignatureBase64;
        }
        else
        {
            var hash = Ed25519Crypto.Sha256(File.ReadAllBytes(dllPath));
            sigBase64 = Convert.ToBase64String(Ed25519Crypto.Sign(priv!, hash));
        }

        var manifest = new PluginManifest
        {
            FeatureId = "winsentinel.test.stub",
            Version = "0.0.1",
            MinCoreVersion = "0.0",
            Signature = sigBase64,
            RequiredEntitlement = entitlement,
        };
        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest));
    }

    // ── empty plugin dir → 0 plugins loaded ─────────────────────────
    [Fact]
    public void EmptyPluginDirectory_LoadsZeroPlugins()
    {
        var (pub, _) = GenerateKeypair();
        var v = new LicenseVerifier(pub, Path.Combine(_tmpDir, "no-license"));
        var host = new PluginHost(pub, _tmpDir, v, _log);

        var loaded = host.LoadAll();

        Assert.Equal(0, loaded);
        Assert.Empty(host.GetExporters());
    }

    // ── malformed dll → logged + skipped, no exception ──────────────
    [Fact]
    public void MalformedDll_LoggedAndSkipped()
    {
        var (pub, priv) = GenerateKeypair();
        var pluginDir = Path.Combine(_tmpDir, "plugins");
        Directory.CreateDirectory(pluginDir);

        var fakeDll = Path.Combine(pluginDir, "garbage.dll");
        File.WriteAllText(fakeDll, "this is not a dll");
        WriteManifest(fakeDll, priv); // signature is over the garbage bytes -> valid

        var v = MakeLicenseWith(pub, priv, "winsentinel.test.stub");
        var host = new PluginHost(pub, pluginDir, v, _log);

        var loaded = host.LoadAll();

        Assert.Equal(0, loaded);
        Assert.Contains(_logs, l => l.Contains("garbage") && l.Contains("failed to load"));
    }

    // ── valid dll but bad signature → rejected ──────────────────────
    [Fact]
    public void BadSignature_Rejected()
    {
        var (pub, priv) = GenerateKeypair();
        var (_, wrongPriv) = GenerateKeypair();

        var pluginDir = Path.Combine(_tmpDir, "plugins");
        Directory.CreateDirectory(pluginDir);
        CopyTestPluginDll(pluginDir, out var dll);
        WriteManifest(dll, wrongPriv); // signed with wrong key

        var v = MakeLicenseWith(pub, priv, "winsentinel.test.stub");
        var host = new PluginHost(pub, pluginDir, v, _log);

        var loaded = host.LoadAll();

        Assert.Equal(0, loaded);
        Assert.Contains(_logs, l => l.Contains("signature verification failed"));
    }

    // ── valid signature but missing entitlement → rejected ──────────
    [Fact]
    public void MissingEntitlement_Rejected()
    {
        var (pub, priv) = GenerateKeypair();
        var pluginDir = Path.Combine(_tmpDir, "plugins");
        Directory.CreateDirectory(pluginDir);
        CopyTestPluginDll(pluginDir, out var dll);
        WriteManifest(dll, priv, entitlement: "report.pdf");

        // License grants a different entitlement.
        var v = MakeLicenseWith(pub, priv, "something.else");
        var host = new PluginHost(pub, pluginDir, v, _log);

        var loaded = host.LoadAll();

        Assert.Equal(0, loaded);
        Assert.Contains(_logs, l => l.Contains("requires entitlement 'report.pdf'"));
    }

    // ── valid signature + valid license + matching entitlement → loaded ─
    [Fact]
    public void ValidSignatureAndEntitlement_PluginLoaded()
    {
        var (pub, priv) = GenerateKeypair();
        var pluginDir = Path.Combine(_tmpDir, "plugins");
        Directory.CreateDirectory(pluginDir);
        CopyTestPluginDll(pluginDir, out var dll);
        WriteManifest(dll, priv, entitlement: "winsentinel.test.stub");

        var v = MakeLicenseWith(pub, priv, "winsentinel.test.stub");
        var host = new PluginHost(pub, pluginDir, v, _log);

        var loaded = host.LoadAll();

        Assert.Equal(1, loaded);
        Assert.Single(host.GetExporters());
        Assert.Equal("test-noop", host.GetExporters()[0].Format);
    }
}
