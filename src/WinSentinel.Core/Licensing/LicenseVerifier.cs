using System.Text.Json;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Core.Licensing;

/// <summary>
/// Verifies and tracks the on-disk WinSentinel license.
/// </summary>
/// <remarks>
/// <para><b>Hard isolation rule:</b> nothing in this repo outside
/// <see cref="WinSentinel.Core.Plugins.PluginHost"/> may call
/// <see cref="HasEntitlement"/>. The license only gates which plugin DLLs
/// are loaded. Audit modules, formatters, and CLI commands must behave
/// identically whether or not a license is present — they may only see
/// extra capabilities through the plugin interfaces in
/// <see cref="WinSentinel.Core.Plugins"/>.</para>
///
/// <para><b>Offline by design.</b> Verification uses an embedded Ed25519
/// public key; no network call is ever made from this code path.
/// "Grace period" simply means: if the file is valid and not expired,
/// it's accepted, regardless of network reachability.</para>
/// </remarks>
public sealed class LicenseVerifier
{
    // ── Embedded Ed25519 PUBLIC key ──────────────────────────────────
    // TODO(license): replace with production Ed25519 public key generated
    // out-of-band by founder. See docs/plugin-key-setup.md for the runbook.
    // While this placeholder is in place, LicenseVerifier refuses every
    // license file and PluginHost loads zero plugins — the free CLI works
    // exactly as it does today.
    internal const string EmbeddedPublicKeyBase64 =
        "REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64";

    /// <summary>
    /// True once the founder has replaced <see cref="EmbeddedPublicKeyBase64"/>
    /// with a real key. While false, license verification is disabled.
    /// </summary>
    public static bool PublicKeyConfigured =>
        EmbeddedPublicKeyBase64 != "REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64"
        && GetEmbeddedPublicKeyOrEmpty().Length == 32;

    private static readonly string DefaultLicenseDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel");

    private static readonly string DefaultLicensePath =
        Path.Combine(DefaultLicenseDir, "license.dat");

    private readonly byte[] _publicKey;
    private readonly string _licensePath;
    private LicenseInfo? _current;
    private bool _loaded;

    /// <summary>
    /// Construct with default (embedded) public key and default license
    /// path under <c>%LOCALAPPDATA%\WinSentinel\license.dat</c>.
    /// </summary>
    public LicenseVerifier()
        : this(GetEmbeddedPublicKeyOrEmpty(), DefaultLicensePath)
    {
        if (!PublicKeyConfigured)
        {
            Console.Error.WriteLine(
                "WARNING: License verification disabled: production public key not yet configured. No plugins will be loaded.");
        }
    }

    /// <summary>
    /// Test-only constructor: inject a custom public key + license file
    /// location so tests can sign fixtures with a throwaway keypair.
    /// </summary>
    public LicenseVerifier(byte[] publicKey, string licensePath)
    {
        _publicKey = publicKey;
        _licensePath = licensePath;
    }

    private static byte[] GetEmbeddedPublicKeyOrEmpty()
    {
        var decoded = Ed25519Crypto.TryDecodeBase64(EmbeddedPublicKeyBase64);
        return decoded ?? Array.Empty<byte>();
    }

    /// <summary>True if a valid, non-expired license file is on disk.</summary>
    public bool IsActivated
    {
        get
        {
            EnsureLoaded();
            return _current != null;
        }
    }

    /// <summary>The currently active license, or <c>null</c> on free tier.</summary>
    public LicenseInfo? Current
    {
        get
        {
            EnsureLoaded();
            return _current;
        }
    }

    /// <summary>
    /// True if the currently active license includes <paramref name="entitlementId"/>.
    /// Returns false on free tier or for unknown entitlement ids.
    /// </summary>
    public bool HasEntitlement(string entitlementId)
    {
        if (string.IsNullOrWhiteSpace(entitlementId)) return false;
        EnsureLoaded();
        return _current?.Entitlements
            .Any(e => string.Equals(e, entitlementId, StringComparison.OrdinalIgnoreCase))
            ?? false;
    }

    /// <summary>
    /// Verify the supplied license, persist it to the verifier's license
    /// path, and refresh internal state. Throws
    /// <see cref="InvalidOperationException"/> on any verification failure.
    /// </summary>
    /// <param name="licenseBlobOrPath">
    /// Either a path to an existing license file or the raw JSON contents
    /// (auto-detected: if the string parses as JSON it's treated as the
    /// blob, otherwise as a path).
    /// </param>
    public LicenseInfo Activate(string licenseBlobOrPath)
    {
        if (string.IsNullOrWhiteSpace(licenseBlobOrPath))
            throw new InvalidOperationException("License input is empty.");

        string json;
        var trimmed = licenseBlobOrPath.TrimStart();
        if (trimmed.StartsWith("{"))
        {
            json = licenseBlobOrPath;
        }
        else if (File.Exists(licenseBlobOrPath))
        {
            json = File.ReadAllText(licenseBlobOrPath);
        }
        else
        {
            throw new InvalidOperationException(
                $"License input is neither valid JSON nor an existing file path: {licenseBlobOrPath}");
        }

        var info = TryParseAndVerify(json, _publicKey, DateTimeOffset.UtcNow)
            ?? throw new InvalidOperationException(
                "License verification failed (bad signature, malformed JSON, or expired).");

        var dir = Path.GetDirectoryName(_licensePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_licensePath, json);

        _current = info;
        _loaded = true;
        return info;
    }

    /// <summary>Remove the persisted license file (best-effort) and reset state.</summary>
    public void Deactivate()
    {
        try { if (File.Exists(_licensePath)) File.Delete(_licensePath); }
        catch { /* best-effort */ }
        _current = null;
        _loaded = true;
    }

    /// <summary>Force a reload from disk on next access.</summary>
    public void Invalidate()
    {
        _current = null;
        _loaded = false;
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        _current = null;

        if (!File.Exists(_licensePath)) return;
        if (_publicKey.Length == 0) return; // no embedded key configured

        try
        {
            var json = File.ReadAllText(_licensePath);
            _current = TryParseAndVerify(json, _publicKey, DateTimeOffset.UtcNow);
        }
        catch
        {
            _current = null;
        }
    }

    private static LicenseInfo? TryParseAndVerify(string json, byte[] publicKey, DateTimeOffset now)
    {
        LicenseInfo? info;
        try { info = JsonSerializer.Deserialize<LicenseInfo>(json); }
        catch { return null; }

        if (info == null) return null;
        if (string.IsNullOrWhiteSpace(info.Signature)) return null;

        var sig = Ed25519Crypto.TryDecodeBase64(info.Signature);
        if (sig == null || sig.Length != 64) return null;

        var payload = info.CanonicalPayload();
        if (!Ed25519Crypto.Verify(publicKey, payload, sig)) return null;

        if (info.Expires <= now) return null;

        return info;
    }
}
