using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Discovers, verifies, and loads WinSentinel plugin DLLs. The host enforces
/// three gates before instantiating anything from a plugin assembly:
/// <list type="number">
///   <item>The DLL must embed a <c>plugin.json</c> manifest (see <see cref="PluginManifest"/>).</item>
///   <item>The manifest's <c>signature</c> must be a valid Ed25519 signature of the DLL's
///         SHA-256 hash, verifiable against <see cref="LicenseManager.EmbeddedPublicKeyBase64"/>.</item>
///   <item>The local <see cref="LicenseManager"/> must report <c>IsEntitled</c> for the manifest's
///         <see cref="PluginManifest.RequiredEntitlement"/>.</item>
/// </list>
/// Any failure on a given DLL is logged and skipped; the host never throws
/// out of <see cref="LoadAll"/>. While the embedded public key is the
/// placeholder, <see cref="PublicKeyConfigured"/> is false and
/// <see cref="LoadAll"/> returns zero plugins after emitting a single warning.
/// </summary>
public sealed class PluginHost
{
    /// <summary>Environment variable that overrides the default plugin directory.</summary>
    public const string PluginDirEnvVar = "WINSENTINEL_PLUGIN_DIR";

    private readonly string _pluginDir;
    private readonly byte[]? _publicKey;
    private readonly Func<string, bool> _entitlementCheck;
    private readonly Action<string, PluginLogLevel> _log;
    private readonly Func<SecurityReportSnapshot?> _reportProvider;

    private readonly List<IReportExporter> _exporters = new();
    private IMonitorDaemon? _monitor;
    private IFleetSink? _fleetSink;
    private IComplianceMapper? _complianceMapper;
    private IScheduledScan? _scheduledScan;

    private bool _loaded;

    /// <summary>
    /// True iff <see cref="LicenseManager.EmbeddedPublicKeyBase64"/> has been
    /// replaced with a real key that base64-decodes to exactly 32 bytes.
    /// </summary>
    public static bool PublicKeyConfigured
    {
        get
        {
            const string placeholder = "REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64";
            var s = LicenseManager.EmbeddedPublicKeyBase64;
            if (string.IsNullOrWhiteSpace(s) || s == placeholder) return false;
            var bytes = Ed25519Crypto.TryDecodeBase64(s);
            return bytes is not null && bytes.Length == Ed25519Crypto.PublicKeySize;
        }
    }

    /// <summary>Default plugin directory: <c>%LOCALAPPDATA%\WinSentinel\plugins</c>, overridable via env var.</summary>
    public static string DefaultPluginDir
    {
        get
        {
            var fromEnv = Environment.GetEnvironmentVariable(PluginDirEnvVar);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local))
            {
                local = Path.GetTempPath();
            }
            return Path.Combine(local, "WinSentinel", "plugins");
        }
    }

    /// <summary>
    /// Production constructor — uses the embedded public key, real
    /// <see cref="LicenseManager"/>, and the default plugin directory.
    /// </summary>
    public PluginHost(Action<string, PluginLogLevel>? log = null)
        : this(
            publicKey: TryGetEmbeddedKey(),
            pluginDir: DefaultPluginDir,
            entitlementCheck: id => LicenseManager.IsEntitled(id),
            log: log,
            reportProvider: null)
    {
        if (!PublicKeyConfigured)
        {
            _log(
                "Plugin public key is not configured (placeholder still in place). " +
                "Plugin loading is disabled. See docs/plugin-key-setup.md.",
                PluginLogLevel.Warning);
        }
    }

    /// <summary>
    /// Test-only constructor: injects the public key, plugin directory, and
    /// entitlement predicate so tests never touch real on-disk state.
    /// </summary>
    public PluginHost(
        byte[]? publicKey,
        string pluginDir,
        Func<string, bool> entitlementCheck,
        Action<string, PluginLogLevel>? log,
        Func<SecurityReportSnapshot?>? reportProvider)
    {
        _publicKey = publicKey;
        _pluginDir = pluginDir ?? throw new ArgumentNullException(nameof(pluginDir));
        _entitlementCheck = entitlementCheck ?? throw new ArgumentNullException(nameof(entitlementCheck));
        _log = log ?? ((msg, level) => Console.Error.WriteLine($"[plugin:{level}] {msg}"));
        _reportProvider = reportProvider ?? (() => null);
    }

    private static byte[]? TryGetEmbeddedKey()
    {
        if (!PublicKeyConfigured) return null;
        return Ed25519Crypto.TryDecodeBase64(LicenseManager.EmbeddedPublicKeyBase64);
    }

    /// <summary>
    /// Scans the plugin directory and loads every DLL that passes the three
    /// gates (manifest / signature / entitlement). Idempotent — repeated
    /// calls are no-ops after the first.
    /// </summary>
    public void LoadAll()
    {
        if (_loaded) return;
        _loaded = true;

        if (_publicKey is null)
        {
            // Already warned in ctor (production) or intentional (tests).
            return;
        }

        if (!Directory.Exists(_pluginDir))
        {
            _log($"Plugin directory '{_pluginDir}' does not exist; no plugins loaded.", PluginLogLevel.Debug);
            return;
        }

        foreach (var dll in Directory.EnumerateFiles(_pluginDir, "*.dll", SearchOption.TopDirectoryOnly))
        {
            try
            {
                TryLoadOne(dll);
            }
            catch (Exception ex)
            {
                _log($"Plugin '{Path.GetFileName(dll)}' threw during load: {ex.Message}", PluginLogLevel.Error);
            }
        }
    }

    private void TryLoadOne(string dllPath)
    {
        byte[] dllBytes;
        try
        {
            dllBytes = File.ReadAllBytes(dllPath);
        }
        catch (Exception ex)
        {
            _log($"Plugin '{Path.GetFileName(dllPath)}' unreadable: {ex.Message}", PluginLogLevel.Warning);
            return;
        }

        // Load into a collectible context first so we can pull the manifest out.
        Assembly asm;
        var alc = new AssemblyLoadContext($"WinSentinelPlugin:{Path.GetFileNameWithoutExtension(dllPath)}", isCollectible: true);
        try
        {
            using var ms = new MemoryStream(dllBytes);
            asm = alc.LoadFromStream(ms);
        }
        catch (Exception ex)
        {
            _log($"Plugin '{Path.GetFileName(dllPath)}' is not a valid .NET assembly: {ex.Message}", PluginLogLevel.Warning);
            alc.Unload();
            return;
        }

        var manifest = PluginManifest.TryLoadFromAssembly(asm);
        if (manifest is null)
        {
            _log($"Plugin '{Path.GetFileName(dllPath)}' is missing or has malformed plugin.json.", PluginLogLevel.Warning);
            alc.Unload();
            return;
        }

        // SHA-256 of DLL bytes is the message that was signed.
        byte[] hash = SHA256.HashData(dllBytes);
        var sigBytes = Ed25519Crypto.TryDecodeBase64(manifest.Signature);
        if (sigBytes is null || !Ed25519Crypto.Verify(_publicKey!, hash, sigBytes))
        {
            _log($"Plugin '{Path.GetFileName(dllPath)}' failed signature verification.", PluginLogLevel.Warning);
            alc.Unload();
            return;
        }

        if (!_entitlementCheck(manifest.RequiredEntitlement))
        {
            _log(
                $"Plugin '{Path.GetFileName(dllPath)}' requires entitlement '{manifest.RequiredEntitlement}' " +
                "which the current license does not cover.",
                PluginLogLevel.Info);
            alc.Unload();
            return;
        }

        // Instantiate every IWinSentinelPlugin in the assembly.
        Type[] types;
        try
        {
            types = asm.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            types = ex.Types.Where(t => t is not null).ToArray()!;
        }

        var ctx = new DefaultPluginContext(_log, _reportProvider);
        int instantiated = 0;
        foreach (var type in types)
        {
            if (type is null || type.IsAbstract || type.IsInterface) continue;
            if (!typeof(IWinSentinelPlugin).IsAssignableFrom(type)) continue;
            try
            {
                var instance = (IWinSentinelPlugin)Activator.CreateInstance(type)!;
                instance.Initialize(ctx);
                instantiated++;
                // Collect well-known facets the host exposes.
                if (instance is IReportExporter exp) _exporters.Add(exp);
                _monitor ??= instance as IMonitorDaemon;
                _fleetSink ??= instance as IFleetSink;
                _complianceMapper ??= instance as IComplianceMapper;
                _scheduledScan ??= instance as IScheduledScan;
            }
            catch (Exception ex)
            {
                _log($"Plugin '{Path.GetFileName(dllPath)}' type {type.FullName} failed to initialize: {ex.Message}", PluginLogLevel.Error);
            }
        }

        _log(
            $"Plugin '{Path.GetFileName(dllPath)}' loaded: feature={manifest.FeatureId} v={manifest.Version} types={instantiated}.",
            PluginLogLevel.Info);
    }

    public IReadOnlyList<IReportExporter> GetExporters() => _exporters;
    public IMonitorDaemon? GetMonitorDaemon() => _monitor;
    public IFleetSink? GetFleetSink() => _fleetSink;
    public IComplianceMapper? GetComplianceMapper() => _complianceMapper;
    public IScheduledScan? GetScheduledScan() => _scheduledScan;

    private sealed class DefaultPluginContext : IPluginContext
    {
        private readonly Func<SecurityReportSnapshot?> _provider;

        public DefaultPluginContext(Action<string, PluginLogLevel> log, Func<SecurityReportSnapshot?> provider)
        {
            Log = log;
            _provider = provider;
            // Plugin config = env vars prefixed WINSENTINEL_PLUGIN_.
            var cfg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
            {
                var k = e.Key?.ToString();
                if (k is null || !k.StartsWith("WINSENTINEL_PLUGIN_", StringComparison.OrdinalIgnoreCase)) continue;
                cfg[k] = e.Value?.ToString() ?? string.Empty;
            }
            Config = cfg;
        }

        public Action<string, PluginLogLevel> Log { get; }
        public Models.SecurityReport? CurrentReport => _provider()?.Report;
        public IReadOnlyDictionary<string, string> Config { get; }
    }
}

/// <summary>
/// Thin wrapper used to hand a current <see cref="Models.SecurityReport"/>
/// to the plugin context lazily, without making the host hold a long-lived
/// reference to host-owned report state.
/// </summary>
public sealed record SecurityReportSnapshot(Models.SecurityReport Report);
