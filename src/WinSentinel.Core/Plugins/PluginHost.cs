using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using WinSentinel.Core.Licensing;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Discovers, verifies, and loads WinSentinel plugins.
/// </summary>
/// <remarks>
/// <para>The host is the <b>only</b> place in the free core that consults
/// <see cref="LicenseVerifier"/>. Everything downstream sees plugins
/// purely through the interfaces in this namespace, so the free CLI
/// continues to work unchanged when no plugins are present.</para>
///
/// <para>Discovery order:</para>
/// <list type="number">
///   <item>Plugin directory = env var <c>WINSENTINEL_PLUGIN_DIR</c> if set,
///         else <c>%LOCALAPPDATA%\WinSentinel\plugins</c>.</item>
///   <item>For each <c>*.dll</c> in that directory, look for a sidecar
///         <c>&lt;name&gt;.plugin.json</c> manifest.</item>
///   <item>SHA-256 the DLL bytes, verify <see cref="PluginManifest.Signature"/>
///         against the embedded Ed25519 public key.</item>
///   <item>Check the manifest's <see cref="PluginManifest.RequiredEntitlement"/>
///         against the active license.</item>
///   <item>Load via a collectible <see cref="AssemblyLoadContext"/>,
///         instantiate every public type implementing
///         <see cref="IWinSentinelPlugin"/>, call <c>Initialize</c>.</item>
/// </list>
///
/// <para>Failures at any step are logged and skipped — a bad plugin must
/// not crash the CLI.</para>
/// </remarks>
public sealed class PluginHost
{
    // ── Embedded Ed25519 PUBLIC key (same constant as LicenseVerifier) ──
    // See docs/plugin-key-setup.md. While the placeholder is in place,
    // LoadAll() short-circuits and zero plugins are loaded.
    internal const string EmbeddedPublicKeyBase64 =
        LicenseVerifier.EmbeddedPublicKeyBase64;

    /// <summary>Default location plugins are loaded from.</summary>
    public static string DefaultPluginDir =>
        Environment.GetEnvironmentVariable("WINSENTINEL_PLUGIN_DIR")
        ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel",
            "plugins");

    private readonly byte[] _publicKey;
    private readonly string _pluginDir;
    private readonly LicenseVerifier _license;
    private readonly Action<string> _log;
    private readonly string _coreVersion;

    private readonly List<IWinSentinelPlugin> _loaded = new();
    private readonly List<IReportExporter> _exporters = new();
    private readonly List<IScheduledScan> _scheduledScans = new();
    private readonly List<IMonitorDaemon> _monitors = new();
    private readonly List<IFleetSink> _fleetSinks = new();
    private readonly List<IComplianceMapper> _complianceMappers = new();

    /// <summary>Default host — embedded key, default dir, default verifier.</summary>
    public PluginHost(Action<string>? log = null)
        : this(
            publicKey: GetEmbeddedPublicKeyOrEmpty(),
            pluginDir: DefaultPluginDir,
            license: new LicenseVerifier(),
            log: log,
            coreVersion: ResolveCoreVersion())
    {
        if (!LicenseVerifier.PublicKeyConfigured)
        {
            (log ?? Console.Error.WriteLine).Invoke(
                "WARNING: License verification disabled: production public key not yet configured. No plugins will be loaded.");
        }
    }

    /// <summary>
    /// Test-only constructor: inject a public key, plugin dir, and license
    /// verifier so tests can drive the host with synthetic fixtures and
    /// throwaway keypairs.
    /// </summary>
    public PluginHost(
        byte[] publicKey,
        string pluginDir,
        LicenseVerifier license,
        Action<string>? log = null,
        string? coreVersion = null)
    {
        _publicKey = publicKey;
        _pluginDir = pluginDir;
        _license = license;
        _log = log ?? (_ => { });
        _coreVersion = coreVersion ?? ResolveCoreVersion();
    }

    /// <summary>Loaded plugins (after <see cref="LoadAll"/>).</summary>
    public IReadOnlyList<IWinSentinelPlugin> Loaded => _loaded;

    public IReadOnlyList<IReportExporter> GetExporters() => _exporters;
    public IReadOnlyList<IScheduledScan> GetScheduledScans() => _scheduledScans;
    public IMonitorDaemon? GetMonitorDaemon() => _monitors.Count > 0 ? _monitors[0] : null;
    public IReadOnlyList<IMonitorDaemon> GetMonitorDaemons() => _monitors;
    public IReadOnlyList<IFleetSink> GetFleetSinks() => _fleetSinks;
    public IReadOnlyList<IComplianceMapper> GetComplianceMappers() => _complianceMappers;

    /// <summary>
    /// Scan the plugin directory and load everything that passes signature
    /// + entitlement checks. Safe to call multiple times (later calls clear
    /// previously-loaded state).
    /// </summary>
    /// <returns>Number of plugins successfully loaded.</returns>
    public int LoadAll()
    {
        _loaded.Clear();
        _exporters.Clear();
        _scheduledScans.Clear();
        _monitors.Clear();
        _fleetSinks.Clear();
        _complianceMappers.Clear();

        if (_publicKey.Length != 32)
        {
            _log("plugin host: production public key not configured; refusing to load any plugins.");
            return 0;
        }

        if (!Directory.Exists(_pluginDir))
        {
            _log($"plugin host: directory does not exist, skipping: {_pluginDir}");
            return 0;
        }

        var dlls = Directory.GetFiles(_pluginDir, "*.dll");
        foreach (var dll in dlls)
        {
            try
            {
                TryLoadOne(dll);
            }
            catch (Exception ex)
            {
                _log($"plugin host: unexpected error loading '{Path.GetFileName(dll)}': {ex.Message}");
            }
        }

        return _loaded.Count;
    }

    private void TryLoadOne(string dllPath)
    {
        var name = Path.GetFileNameWithoutExtension(dllPath);
        var manifestPath = Path.Combine(_pluginDir, name + ".plugin.json");

        if (!File.Exists(manifestPath))
        {
            _log($"plugin '{name}': missing sidecar manifest '{Path.GetFileName(manifestPath)}', skipping.");
            return;
        }

        PluginManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<PluginManifest>(
                File.ReadAllText(manifestPath));
        }
        catch (Exception ex)
        {
            _log($"plugin '{name}': manifest could not be parsed: {ex.Message}");
            return;
        }

        if (manifest == null || string.IsNullOrWhiteSpace(manifest.FeatureId))
        {
            _log($"plugin '{name}': manifest is empty or missing featureId.");
            return;
        }

        byte[] dllBytes;
        try { dllBytes = File.ReadAllBytes(dllPath); }
        catch (Exception ex)
        {
            _log($"plugin '{name}': could not read DLL bytes: {ex.Message}");
            return;
        }

        var hash = Ed25519Crypto.Sha256(dllBytes);
        var sig = Ed25519Crypto.TryDecodeBase64(manifest.Signature);
        if (sig == null || sig.Length != 64)
        {
            _log($"plugin '{name}': manifest signature is not a valid 64-byte Ed25519 signature.");
            return;
        }

        if (!Ed25519Crypto.Verify(_publicKey, hash, sig))
        {
            _log($"plugin '{name}': signature verification failed (DLL has been tampered with or was not signed by the official key).");
            return;
        }

        if (string.IsNullOrWhiteSpace(manifest.RequiredEntitlement))
        {
            _log($"plugin '{name}': manifest does not declare requiredEntitlement, skipping.");
            return;
        }

        if (!_license.HasEntitlement(manifest.RequiredEntitlement))
        {
            _log($"plugin '{name}' requires entitlement '{manifest.RequiredEntitlement}' not present in license; skipping.");
            return;
        }

        // Collectible context so a future hot-reload can drop a plugin.
        var alc = new AssemblyLoadContext($"WinSentinel.Plugin.{name}", isCollectible: true);
        Assembly asm;
        try
        {
            using var ms = new MemoryStream(dllBytes);
            asm = alc.LoadFromStream(ms);
        }
        catch (Exception ex)
        {
            _log($"plugin '{name}': failed to load assembly: {ex.Message}");
            return;
        }

        Type[] types;
        try { types = asm.GetTypes(); }
        catch (ReflectionTypeLoadException rtle)
        {
            types = rtle.Types.Where(t => t != null).Select(t => t!).ToArray();
        }

        var pluginTypes = types
            .Where(t => t.IsClass && !t.IsAbstract && typeof(IWinSentinelPlugin).IsAssignableFrom(t))
            .ToList();

        if (pluginTypes.Count == 0)
        {
            _log($"plugin '{name}': no public types implementing IWinSentinelPlugin found.");
            return;
        }

        var ctx = new PluginContext(_log, null, _coreVersion);

        foreach (var t in pluginTypes)
        {
            try
            {
                var instance = (IWinSentinelPlugin?)Activator.CreateInstance(t);
                if (instance == null)
                {
                    _log($"plugin '{name}': could not instantiate {t.FullName}.");
                    continue;
                }

                instance.Initialize(ctx);
                _loaded.Add(instance);

                if (instance is IReportExporter rx) _exporters.Add(rx);
                if (instance is IScheduledScan ss) _scheduledScans.Add(ss);
                if (instance is IMonitorDaemon md) _monitors.Add(md);
                if (instance is IFleetSink fs) _fleetSinks.Add(fs);
                if (instance is IComplianceMapper cm) _complianceMappers.Add(cm);

                _log($"plugin '{name}': loaded {t.FullName} (feature={instance.FeatureId}, v{instance.Version}).");
            }
            catch (Exception ex)
            {
                _log($"plugin '{name}': initialize failed for {t.FullName}: {ex.Message}");
            }
        }
    }

    private static byte[] GetEmbeddedPublicKeyOrEmpty()
    {
        var decoded = Ed25519Crypto.TryDecodeBase64(EmbeddedPublicKeyBase64);
        return decoded ?? Array.Empty<byte>();
    }

    private static string ResolveCoreVersion()
    {
        try
        {
            var asm = typeof(PluginHost).Assembly;
            var v = asm.GetName().Version;
            return v?.ToString(3) ?? "0.0.0";
        }
        catch { return "0.0.0"; }
    }
}
