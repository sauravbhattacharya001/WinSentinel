using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Tests.Plugins;

/// <summary>
/// Verifies <see cref="PluginHost"/> across the multi-publisher trust model.
/// Every test uses an in-memory keypair generated at runtime via
/// <see cref="Ed25519Crypto"/>; nothing is ever persisted on disk outside
/// of the per-test temporary directory.
/// </summary>
public sealed class PluginHostTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _pluginDir;

    public PluginHostTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "winsentinel-tests-" + Guid.NewGuid().ToString("N"));
        _pluginDir = Path.Combine(_tempRoot, "plugins");
        Directory.CreateDirectory(_pluginDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempRoot)) Directory.Delete(_tempRoot, recursive: true); }
        catch { /* best effort */ }
    }

    private static string TestPluginDllPath()
    {
        // The test plugin DLL is built alongside the tests via the
        // WinSentinel.TestPlugin project reference. Locate it next to the
        // test assembly.
        var here = Path.GetDirectoryName(typeof(PluginHostTests).Assembly.Location)!;
        var candidate = Path.Combine(here, "WinSentinel.TestPlugin.dll");
        if (File.Exists(candidate)) return candidate;
        // Fallback search.
        var found = Directory.GetFiles(here, "WinSentinel.TestPlugin.dll", SearchOption.AllDirectories);
        if (found.Length == 0) throw new FileNotFoundException("WinSentinel.TestPlugin.dll not found near tests.");
        return found[0];
    }

    private string StagePlugin(string? publisherKeyB64, string? signatureB64)
    {
        var src = TestPluginDllPath();
        var dst = Path.Combine(_pluginDir, "WinSentinel.TestPlugin.dll");
        File.Copy(src, dst, overwrite: true);
        if (!string.IsNullOrEmpty(publisherKeyB64))
            File.WriteAllText(dst + ".pub", publisherKeyB64);
        if (!string.IsNullOrEmpty(signatureB64))
            File.WriteAllText(dst + ".sig", signatureB64);
        return dst;
    }

    private static string SignDll(string dllPath, byte[] privateKey)
    {
        var bytes = File.ReadAllBytes(dllPath);
        var hash = SHA256.HashData(bytes);
        var sig = typeof(Ed25519Crypto)
            .GetMethod("Sign", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, new object[] { privateKey, hash })!;
        return Convert.ToBase64String((byte[])sig);
    }

    private static (byte[] Pub, byte[] Priv) NewKeypair()
    {
        var t = typeof(Ed25519Crypto).GetMethod("GenerateKeypair", BindingFlags.Static | BindingFlags.NonPublic)!;
        var tuple = t.Invoke(null, null)!;
        // Returns ValueTuple<byte[], byte[]> — unpack via reflection.
        var item1 = (byte[])tuple.GetType().GetField("Item1")!.GetValue(tuple)!;
        var item2 = (byte[])tuple.GetType().GetField("Item2")!.GetValue(tuple)!;
        return (item1, item2);
    }

    private PluginHost NewHost(TrustedPublisherConfig trust, Func<string, bool>? entitled = null)
    {
        return new PluginHost(
            trust,
            _pluginDir,
            entitled ?? (_ => true),
            log: (_, _) => { },
            reportProvider: null);
    }

    [Fact]
    public void EmptyDirectory_Returns_NoResults()
    {
        var host = NewHost(new TrustedPublisherConfig());
        host.LoadAll();
        Assert.Empty(host.LoadResults);
    }

    [Fact]
    public void Malformed_Dll_Is_Skipped()
    {
        File.WriteAllBytes(Path.Combine(_pluginDir, "junk.dll"), new byte[] { 0, 1, 2, 3, 4 });
        var host = NewHost(new TrustedPublisherConfig());
        host.LoadAll();
        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.SkippedNotAnAssembly, r.Status);
    }

    [Fact]
    public void Plugin_Signed_By_Trusted_Key_Loads()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, signatureB64: null);
        File.WriteAllText(dll + ".sig", SignDll(dll, priv));

        var trust = new TrustedPublisherConfig
        {
            TrustedPublishers = { new TrustedPublisher { Name = "test", PublicKey = pubB64, AutoTrusted = false } }
        };
        var host = NewHost(trust);
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.Loaded, r.Status);
    }

    [Fact]
    public void Plugin_Signed_By_Official_Key_Loads()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, null);
        File.WriteAllText(dll + ".sig", SignDll(dll, priv));

        // Same shape as auto-trusted official entry.
        var trust = new TrustedPublisherConfig
        {
            TrustedPublishers = { new TrustedPublisher { Name = TrustedPublisherStore.OfficialPublisherName, PublicKey = pubB64, AutoTrusted = true } }
        };
        var host = NewHost(trust);
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.Loaded, r.Status);
    }

    [Fact]
    public void Plugin_Signed_By_Unknown_Key_Is_Rejected()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, null);
        File.WriteAllText(dll + ".sig", SignDll(dll, priv));

        // Trust store empty -> publisher unknown.
        var host = NewHost(new TrustedPublisherConfig());
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.SkippedUntrustedPublisher, r.Status);
    }

    [Fact]
    public void Tampered_Signature_Is_Rejected_Even_If_Publisher_Trusted()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, null);

        // Sign, then flip one bit.
        var sig = Convert.FromBase64String(SignDll(dll, priv));
        sig[0] ^= 0xFF;
        File.WriteAllText(dll + ".sig", Convert.ToBase64String(sig));

        var trust = new TrustedPublisherConfig
        {
            TrustedPublishers = { new TrustedPublisher { Name = "test", PublicKey = pubB64 } }
        };
        var host = NewHost(trust);
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.SkippedBadSignature, r.Status);
    }

    [Fact]
    public void Unsigned_Plugin_Rejected_By_Default()
    {
        // Stage with no publisher key + no signature.
        StagePlugin(publisherKeyB64: null, signatureB64: null);

        var host = NewHost(new TrustedPublisherConfig { AllowUnsigned = false });
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.SkippedUnsignedDisallowed, r.Status);
    }

    [Fact]
    public void Unsigned_Plugin_Loads_When_AllowUnsigned_True()
    {
        // The embedded plugin.json has publisher_key="AAAA..." (32 zero bytes)
        // and signature="". To make it truly "unsigned" we need to override
        // publisher_key to empty via a sidecar — but our sidecar only adds,
        // doesn't remove. Instead, write a `.pub` with empty content and rely
        // on isUnsigned logic: publisher key present but no signature.
        // Use a fresh staging that mirrors "no signature":
        StagePlugin(publisherKeyB64: null, signatureB64: null);
        // Embedded manifest has publisher_key + empty signature. allow_unsigned=true
        // should bypass.
        var host = NewHost(new TrustedPublisherConfig { AllowUnsigned = true });
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.Loaded, r.Status);
    }

    [Fact]
    public void Trusted_Plugin_Rejected_When_Not_Entitled()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, null);
        File.WriteAllText(dll + ".sig", SignDll(dll, priv));

        var trust = new TrustedPublisherConfig
        {
            TrustedPublishers = { new TrustedPublisher { Name = "test", PublicKey = pubB64 } }
        };
        var host = NewHost(trust, entitled: _ => false);
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.SkippedNotEntitled, r.Status);
    }

    [Fact]
    public void Trusted_Plugin_Loads_When_Entitled()
    {
        var (pub, priv) = NewKeypair();
        var pubB64 = Convert.ToBase64String(pub);
        var dll = StagePlugin(pubB64, null);
        File.WriteAllText(dll + ".sig", SignDll(dll, priv));

        var trust = new TrustedPublisherConfig
        {
            TrustedPublishers = { new TrustedPublisher { Name = "test", PublicKey = pubB64 } }
        };
        var host = NewHost(trust, entitled: id => id == "test-stub");
        host.LoadAll();

        var r = Assert.Single(host.LoadResults);
        Assert.Equal(PluginLoadStatus.Loaded, r.Status);
        Assert.Equal("test-stub", r.FeatureId);
    }
}
