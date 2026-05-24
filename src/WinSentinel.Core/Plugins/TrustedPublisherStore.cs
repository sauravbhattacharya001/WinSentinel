using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// A single trusted publisher entry. The Ed25519 <see cref="PublicKey"/> is
/// the actual trust anchor; <see cref="Name"/> is informational only and
/// surfaced in <c>winsentinel plugin list</c> output.
/// </summary>
public sealed class TrustedPublisher
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Base64-encoded 32-byte Ed25519 public key.</summary>
    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>True iff this entry was seeded by the product (the official WinSentinel project key).</summary>
    [JsonPropertyName("auto_trusted")]
    public bool AutoTrusted { get; set; }
}

/// <summary>
/// On-disk shape of <c>%LOCALAPPDATA%\WinSentinel\trusted-publishers.json</c>.
/// </summary>
public sealed class TrustedPublisherConfig
{
    [JsonPropertyName("trusted_publishers")]
    public List<TrustedPublisher> TrustedPublishers { get; set; } = new();

    /// <summary>
    /// When true, plugins with no <c>publisher_key</c> / no signature are
    /// loaded anyway (dev mode). The host logs a loud warning every startup.
    /// </summary>
    [JsonPropertyName("allow_unsigned")]
    public bool AllowUnsigned { get; set; }
}

/// <summary>
/// Read / write the WinSentinel trusted-publishers configuration. The store
/// is the sole source of truth for "which Ed25519 public keys may sign plugins
/// that this WinSentinel install will load".
///
/// <para>The OFFICIAL WinSentinel publisher key (from
/// <see cref="LicenseManager.OfficialPublisherPublicKeyBase64"/>) is always
/// merged into the in-memory list as <see cref="TrustedPublisher.AutoTrusted"/>=true
/// when the constant has been replaced with a real key. Third-party
/// publishers are added by the user via <c>winsentinel plugin trust</c>.</para>
///
/// <para>This class never throws on a corrupt file \u2014 it returns a fresh
/// empty config so a damaged file cannot brick plugin loading.</para>
/// </summary>
public static class TrustedPublisherStore
{
    private const string Placeholder = "REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64";
    public const string OfficialPublisherName = "WinSentinel (official)";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Default config path: <c>%LOCALAPPDATA%\WinSentinel\trusted-publishers.json</c>.</summary>
    public static string DefaultConfigPath
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) local = Path.GetTempPath();
            return Path.Combine(local, "WinSentinel", "trusted-publishers.json");
        }
    }

    /// <summary>
    /// Loads the configuration. If the file is missing or malformed, returns
    /// an empty config (NOT null). The official publisher entry is merged in
    /// automatically when the embedded constant has been replaced with a real
    /// 32-byte Ed25519 key.
    /// </summary>
    public static TrustedPublisherConfig Load(string? path = null)
    {
        var p = path ?? DefaultConfigPath;
        TrustedPublisherConfig cfg;
        if (!File.Exists(p))
        {
            cfg = new TrustedPublisherConfig();
        }
        else
        {
            try
            {
                cfg = JsonSerializer.Deserialize<TrustedPublisherConfig>(File.ReadAllText(p), JsonOpts)
                      ?? new TrustedPublisherConfig();
            }
            catch
            {
                cfg = new TrustedPublisherConfig();
            }
        }

        // Always merge the official key when configured. If the user has
        // already added an entry with the same key, leave theirs alone.
        var official = LicenseManager.OfficialPublisherPublicKeyBase64;
        if (!string.IsNullOrWhiteSpace(official) && official != Placeholder)
        {
            var decoded = Ed25519Crypto.TryDecodeBase64(official);
            if (decoded is { Length: 32 })
            {
                bool present = false;
                foreach (var pub in cfg.TrustedPublishers)
                {
                    if (string.Equals((pub.PublicKey ?? string.Empty).Trim(), official.Trim(), StringComparison.Ordinal))
                    {
                        present = true;
                        break;
                    }
                }
                if (!present)
                {
                    cfg.TrustedPublishers.Insert(0, new TrustedPublisher
                    {
                        Name = OfficialPublisherName,
                        PublicKey = official,
                        AutoTrusted = true,
                    });
                }
            }
        }

        return cfg;
    }

    /// <summary>Persists the configuration. Creates the parent directory if missing.</summary>
    public static void Save(TrustedPublisherConfig config, string? path = null)
    {
        if (config is null) throw new ArgumentNullException(nameof(config));
        var p = path ?? DefaultConfigPath;
        var dir = Path.GetDirectoryName(p);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        // Strip auto-trusted entries before writing \u2014 they're re-merged on Load.
        var toWrite = new TrustedPublisherConfig
        {
            AllowUnsigned = config.AllowUnsigned,
            TrustedPublishers = new List<TrustedPublisher>(),
        };
        foreach (var pub in config.TrustedPublishers)
        {
            if (pub.AutoTrusted) continue;
            toWrite.TrustedPublishers.Add(pub);
        }
        File.WriteAllText(p, JsonSerializer.Serialize(toWrite, JsonOpts));
    }

    /// <summary>
    /// Adds (or replaces by name) a user-trusted publisher. Validates the
    /// key is base64 and 32 bytes. Returns the normalized entry, or throws
    /// <see cref="ArgumentException"/> on malformed input.
    /// </summary>
    public static TrustedPublisher Trust(string name, string publicKeyBase64, string? path = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Publisher name is required.", nameof(name));
        var decoded = Ed25519Crypto.TryDecodeBase64(publicKeyBase64);
        if (decoded is null || decoded.Length != Ed25519Crypto.PublicKeySize)
            throw new ArgumentException("Public key must be a base64-encoded 32-byte Ed25519 key.", nameof(publicKeyBase64));

        var cfg = Load(path);
        cfg.TrustedPublishers.RemoveAll(p =>
            string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && !p.AutoTrusted);

        var entry = new TrustedPublisher
        {
            Name = name.Trim(),
            PublicKey = publicKeyBase64.Trim(),
            AutoTrusted = false,
        };
        cfg.TrustedPublishers.Add(entry);
        Save(cfg, path);
        return entry;
    }

    /// <summary>
    /// Removes a user-trusted publisher by name. Refuses to remove the
    /// auto-trusted official entry. Returns <c>true</c> if removed.
    /// </summary>
    public static bool Untrust(string name, string? path = null)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var cfg = Load(path);
        var removed = cfg.TrustedPublishers.RemoveAll(p =>
            !p.AutoTrusted &&
            string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (removed > 0)
        {
            Save(cfg, path);
            return true;
        }
        return false;
    }

    /// <summary>Toggles unsigned-plugin loading (developer mode).</summary>
    public static void SetAllowUnsigned(bool allow, string? path = null)
    {
        var cfg = Load(path);
        cfg.AllowUnsigned = allow;
        Save(cfg, path);
    }
}
