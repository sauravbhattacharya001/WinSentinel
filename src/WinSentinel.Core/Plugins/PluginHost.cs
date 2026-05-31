using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Outcome of attempting to load a single plugin DLL. Surfaced by
/// <see cref="PluginHost.LoadResults"/> so the CLI's <c>plugin list</c>
/// command can show admins both what loaded and what was skipped, with
/// the reason for each skip.
/// </summary>
public sealed record PluginLoadResult(
    string DllPath,
    PluginLoadStatus Status,
    string? FeatureId,
    string? Version,
    string? PublisherName,
    string? PublisherKey,
    string Message);

public enum PluginLoadStatus
{
    Loaded,
    SkippedUnreadable,
    SkippedNotAnAssembly,
    SkippedNoManifest,
    SkippedUntrustedPublisher,
    SkippedUnsignedDisallowed,
    SkippedBadSignature,
    SkippedNotEntitled,
    SkippedNoTypes,
    SkippedInitFailed,
}

/// <summary>
/// Discovers, verifies, and loads WinSentinel plugin DLLs under a
/// multi-publisher trust model. Each plugin DLL embeds a <c>plugin.json</c>
/// manifest that names its <c>publisher_key</c>; the host loads it only if
/// (a) that key is in <see cref="TrustedPublisherStore"/>, (b) the manifest's
/// <c>signature</c> is a valid Ed25519 signature of <c>SHA256(dllBytes)</c>
/// under that key. Plugin loading is unconditional — no license or
/// entitlement check is required (community extensibility model).
///
/// <para>Unsigned plugins (empty publisher_key / signature) are rejected by
/// default. Setting <see cref="TrustedPublisherConfig.AllowUnsigned"/> = true
/// (via <c>winsentinel plugin trust --allow-unsigned</c>) opts in to loading
/// them, with a warning emitted on startup whenever the plugin directory
/// actually contains at least one DLL (and always from the
/// <c>winsentinel plugin list</c> trust dashboard).</para>
///
/// <para>Per-DLL failures never throw out of <see cref="LoadAll"/> \u2014
/// they're recorded into <see cref="LoadResults"/> and logged.</para>
/// </summary>
public sealed class PluginHost
{
    public const string PluginDirEnvVar = "WINSENTINEL_PLUGIN_DIR";
    public const string MachinePluginDirEnvVar = "WINSENTINEL_MACHINE_PLUGIN_DIR";

    private readonly string _pluginDir;
    private readonly string _machinePluginDir;
    private readonly TrustedPublisherConfig _trustConfig;
    private readonly Func<string, bool> _entitlementCheck;
    private readonly Action<string, PluginLogLevel> _log;
    private readonly Func<SecurityReportSnapshot?> _reportProvider;

    private readonly List<IReportExporter> _exporters = new();
    private readonly List<PluginLoadResult> _loadResults = new();
    private IMonitorDaemon? _monitor;
    private IFleetSink? _fleetSink;
    private IComplianceMapper? _complianceMapper;
    private IScheduledScan? _scheduledScan;

    private bool _loaded;

    /// <summary>Default plugin directory: <c>%LOCALAPPDATA%\WinSentinel\plugins</c>, overridable via env var.</summary>
    public static string DefaultPluginDir
    {
        get
        {
            var fromEnv = Environment.GetEnvironmentVariable(PluginDirEnvVar);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) local = Path.GetTempPath();
            return Path.Combine(local, "WinSentinel", "plugins");
        }
    }

    /// <summary>
    /// Machine-wide plugin directory: <c>%PROGRAMDATA%\WinSentinel\plugins</c>.
    /// Used for IT-deployed plugins. User-dir plugins take precedence over
    /// machine-dir plugins with the same filename.
    /// </summary>
    public static string DefaultMachinePluginDir
    {
        get
        {
            var fromEnv = Environment.GetEnvironmentVariable(MachinePluginDirEnvVar);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrEmpty(programData)) programData = @"C:\ProgramData";
            return Path.Combine(programData, "WinSentinel", "plugins");
        }
    }

    /// <summary>Production constructor \u2014 reads trust + plugin dir from on-disk defaults.</summary>
    public PluginHost(Action<string, PluginLogLevel>? log = null)
        : this(
            trustConfig: TrustedPublisherStore.Load(),
            pluginDir: DefaultPluginDir,
            machinePluginDir: DefaultMachinePluginDir,
            entitlementCheck: _ => true, // Community plugins: no license gating
            log: log,
            reportProvider: null)
    {
        // Only emit trust-config warnings when they're actionable for this run:
        // i.e. there is at least one .dll in the plugin dir. Otherwise the user
        // has no plugins at all and the noise pollutes every CLI invocation
        // (including JSON output). The `winsentinel plugin list` command path
        // calls MaybeWarnAboutTrustConfiguration(always: true) to keep the
        // trust dashboard fully verbose. Closes #222.
        MaybeWarnAboutTrustConfiguration(always: false);
    }

    /// <summary>
    /// Emits stderr warnings about trust configuration (no trusted publishers,
    /// or allow_unsigned=true). When <paramref name="always"/> is false, the
    /// warnings only fire if the plugin directory actually contains at least
    /// one <c>.dll</c> \u2014 in which case they're actionable. When true, they
    /// always fire (used by the explicit <c>winsentinel plugin list</c>
    /// command, which is the trust dashboard).
    /// </summary>
    public void MaybeWarnAboutTrustConfiguration(bool always)
    {
        bool gate = always || PluginsDirHasDlls();
        if (!gate) return;

        if (_trustConfig.TrustedPublishers.Count == 0)
        {
            _log(
                "No trusted plugin publishers configured. " +
                "Plugin loading is effectively disabled. " +
                "Add one with `winsentinel plugin trust <pubkey> --name <name>` " +
                "or see docs/plugin-key-setup.md.",
                PluginLogLevel.Warning);
        }
        if (_trustConfig.AllowUnsigned)
        {
            _log(
                "Unsigned plugins are ALLOWED (developer mode). Disable with " +
                "`winsentinel plugin trust --allow-unsigned=false`.",
                PluginLogLevel.Warning);
        }
    }

    /// <summary>True iff the plugin directory exists and contains at least one *.dll.</summary>
    internal bool PluginsDirHasDlls()
    {
        try
        {
            if (!Directory.Exists(_pluginDir)) return false;
            return Directory.EnumerateFiles(_pluginDir, "*.dll", SearchOption.TopDirectoryOnly).Any();
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Test-only constructor: injects everything.</summary>
    public PluginHost(
        TrustedPublisherConfig trustConfig,
        string pluginDir,
        Func<string, bool> entitlementCheck,
        Action<string, PluginLogLevel>? log,
        Func<SecurityReportSnapshot?>? reportProvider)
        : this(trustConfig, pluginDir, machinePluginDir: null, entitlementCheck, log, reportProvider)
    {
    }

    /// <summary>Full constructor: supports both user and machine plugin dirs.</summary>
    public PluginHost(
        TrustedPublisherConfig trustConfig,
        string pluginDir,
        string? machinePluginDir,
        Func<string, bool> entitlementCheck,
        Action<string, PluginLogLevel>? log,
        Func<SecurityReportSnapshot?>? reportProvider)
    {
        _trustConfig = trustConfig ?? throw new ArgumentNullException(nameof(trustConfig));
        _pluginDir = pluginDir ?? throw new ArgumentNullException(nameof(pluginDir));
        _machinePluginDir = machinePluginDir ?? string.Empty;
        _entitlementCheck = entitlementCheck ?? throw new ArgumentNullException(nameof(entitlementCheck));
        _log = log ?? ((msg, level) => Console.Error.WriteLine($"[plugin:{level}] {msg}"));
        _reportProvider = reportProvider ?? (() => null);
    }

    /// <summary>Scans the plugin directory and loads every DLL that passes all gates. Idempotent.</summary>
    public void LoadAll()
    {
        if (_loaded) return;
        _loaded = true;

        // Pre-decode trusted publisher keys once.
        var trustedKeys = new List<(TrustedPublisher Pub, byte[] Bytes)>();
        foreach (var pub in _trustConfig.TrustedPublishers)
        {
            var b = Ed25519Crypto.TryDecodeBase64(pub.PublicKey);
            if (b is { Length: Ed25519Crypto.PublicKeySize }) trustedKeys.Add((pub, b));
        }

        // Collect DLLs from machine-wide dir first, then user dir.
        // User-dir plugins override machine-dir plugins with the same filename.
        var dllsToLoad = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(_machinePluginDir) && Directory.Exists(_machinePluginDir))
        {
            foreach (var dll in Directory.EnumerateFiles(_machinePluginDir, "*.dll", SearchOption.TopDirectoryOnly))
                dllsToLoad[Path.GetFileName(dll)] = dll;
        }

        if (Directory.Exists(_pluginDir))
        {
            foreach (var dll in Directory.EnumerateFiles(_pluginDir, "*.dll", SearchOption.TopDirectoryOnly))
                dllsToLoad[Path.GetFileName(dll)] = dll; // overwrites machine-dir entry
        }

        if (dllsToLoad.Count == 0)
        {
            _log($"No plugin DLLs found in '{_pluginDir}' or machine-wide dir.", PluginLogLevel.Debug);
            return;
        }

        foreach (var dll in dllsToLoad.Values)
        {
            try
            {
                TryLoadOne(dll, trustedKeys);
            }
            catch (Exception ex)
            {
                _loadResults.Add(new PluginLoadResult(dll, PluginLoadStatus.SkippedInitFailed,
                    null, null, null, null, $"unhandled error: {ex.Message}"));
                _log($"Plugin '{Path.GetFileName(dll)}' threw during load: {ex.Message}", PluginLogLevel.Error);
            }
        }
    }

    private void TryLoadOne(string dllPath, List<(TrustedPublisher Pub, byte[] Bytes)> trustedKeys)
    {
        byte[] dllBytes;
        try
        {
            dllBytes = File.ReadAllBytes(dllPath);
        }
        catch (Exception ex)
        {
            Record(dllPath, PluginLoadStatus.SkippedUnreadable, null, null, null, null, ex.Message);
            return;
        }

        Assembly asm;
        var alc = new AssemblyLoadContext($"WinSentinelPlugin:{Path.GetFileNameWithoutExtension(dllPath)}", isCollectible: true);
        try
        {
            using var ms = new MemoryStream(dllBytes);
            asm = alc.LoadFromStream(ms);
        }
        catch (Exception ex)
        {
            Record(dllPath, PluginLoadStatus.SkippedNotAnAssembly, null, null, null, null, ex.Message);
            alc.Unload();
            return;
        }

        var manifest = PluginManifest.TryLoadFromAssembly(asm);
        if (manifest is null)
        {
            Record(dllPath, PluginLoadStatus.SkippedNoManifest, null, null, null, null,
                "missing or malformed plugin.json");
            alc.Unload();
            return;
        }

        var hasPubSidecar = File.Exists(dllPath + ".pub");
        var hasSigSidecar = File.Exists(dllPath + ".sig");
        var hasManifestPub = !string.IsNullOrWhiteSpace(manifest.PublisherKey);
        var hasManifestSig = !string.IsNullOrWhiteSpace(manifest.Signature);
        var isUnsigned = !(hasManifestPub || hasPubSidecar) || !(hasManifestSig || hasSigSidecar);

        // Signature source priority: sidecar `<dll>.sig` (raw 64 bytes OR base64
        // text) wins over manifest.Signature. Sidecars are the practical signing
        // convention because embedding the signature inside the very bytes you're
        // signing creates a self-reference problem.
        string? effectiveSignatureB64 = null;
        var sidecarPath = dllPath + ".sig";
        if (File.Exists(sidecarPath))
        {
            try
            {
                var raw = File.ReadAllBytes(sidecarPath);
                if (raw.Length == Ed25519Crypto.SignatureSize)
                {
                    effectiveSignatureB64 = Convert.ToBase64String(raw);
                }
                else
                {
                    // Treat as text.
                    effectiveSignatureB64 = System.Text.Encoding.UTF8.GetString(raw).Trim();
                }
            }
            catch
            {
                effectiveSignatureB64 = null;
            }
        }
        if (string.IsNullOrWhiteSpace(effectiveSignatureB64))
            effectiveSignatureB64 = manifest.Signature;

        // Publisher key source: sidecar `<dll>.pub` (base64 text) wins over
        // manifest.PublisherKey. Useful for re-publishing a third-party DLL
        // under your own key without rebuilding it; also used by tests.
        string? effectivePublisherKeyB64 = null;
        var pubSidecar = dllPath + ".pub";
        if (File.Exists(pubSidecar))
        {
            try { effectivePublisherKeyB64 = File.ReadAllText(pubSidecar).Trim(); }
            catch { effectivePublisherKeyB64 = null; }
        }
        if (string.IsNullOrWhiteSpace(effectivePublisherKeyB64))
            effectivePublisherKeyB64 = manifest.PublisherKey;

        if (isUnsigned)
        {
            if (!_trustConfig.AllowUnsigned)
            {
                Record(dllPath, PluginLoadStatus.SkippedUnsignedDisallowed,
                    manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                    "plugin is unsigned and allow_unsigned=false");
                alc.Unload();
                return;
            }
            _log($"Loading UNSIGNED plugin '{Path.GetFileName(dllPath)}' (allow_unsigned=true).", PluginLogLevel.Warning);
        }
        else
        {
            // Trust check: publisher_key must appear in the trusted set.
            var publisherKeyBytes = Ed25519Crypto.TryDecodeBase64(effectivePublisherKeyB64);
            if (publisherKeyBytes is null || publisherKeyBytes.Length != Ed25519Crypto.PublicKeySize)
            {
                Record(dllPath, PluginLoadStatus.SkippedUntrustedPublisher,
                    manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                    "publisher_key is not a valid 32-byte Ed25519 key");
                alc.Unload();
                return;
            }

            bool isTrusted = false;
            foreach (var (_, bytes) in trustedKeys)
            {
                if (bytes.AsSpan().SequenceEqual(publisherKeyBytes))
                {
                    isTrusted = true;
                    break;
                }
            }
            if (!isTrusted)
            {
                Record(dllPath, PluginLoadStatus.SkippedUntrustedPublisher,
                    manifest.FeatureId, manifest.Version, manifest.PublisherName, effectivePublisherKeyB64,
                    $"publisher '{manifest.PublisherName}' is not trusted (add with `winsentinel plugin trust`)");
                alc.Unload();
                return;
            }

            // Signature check.
            var sigBytes = Ed25519Crypto.TryDecodeBase64(effectiveSignatureB64);
            byte[] hash = SHA256.HashData(dllBytes);
            if (sigBytes is null || !Ed25519Crypto.Verify(publisherKeyBytes, hash, sigBytes))
            {
                Record(dllPath, PluginLoadStatus.SkippedBadSignature,
                    manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                    "signature does not match DLL hash under the publisher key");
                alc.Unload();
                return;
            }
        }

        if (!_entitlementCheck(manifest.RequiredEntitlement))
        {
            Record(dllPath, PluginLoadStatus.SkippedNotEntitled,
                manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                $"current license does not cover entitlement '{manifest.RequiredEntitlement}'");
            alc.Unload();
            return;
        }

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
                if (instance is IReportExporter exp) _exporters.Add(exp);
                _monitor ??= instance as IMonitorDaemon;
                _fleetSink ??= instance as IFleetSink;
                _complianceMapper ??= instance as IComplianceMapper;
                _scheduledScan ??= instance as IScheduledScan;
            }
            catch (Exception ex)
            {
                Record(dllPath, PluginLoadStatus.SkippedInitFailed,
                    manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                    $"type {type.FullName} init failed: {ex.Message}");
                _log($"Plugin '{Path.GetFileName(dllPath)}' type {type.FullName} failed to initialize: {ex.Message}", PluginLogLevel.Error);
                // Don't return \u2014 other types in the same assembly may still load.
            }
        }

        if (instantiated == 0)
        {
            Record(dllPath, PluginLoadStatus.SkippedNoTypes,
                manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
                "no IWinSentinelPlugin types found in assembly");
            return;
        }

        Record(dllPath, PluginLoadStatus.Loaded,
            manifest.FeatureId, manifest.Version, manifest.PublisherName, manifest.PublisherKey,
            $"loaded {instantiated} type(s)");
        _log(
            $"Plugin '{Path.GetFileName(dllPath)}' loaded: feature={manifest.FeatureId} v={manifest.Version} publisher={manifest.PublisherName}.",
            PluginLogLevel.Info);
    }

    private void Record(string dll, PluginLoadStatus status, string? feature, string? version, string? pubName, string? pubKey, string msg)
        => _loadResults.Add(new PluginLoadResult(dll, status, feature, version, pubName, pubKey, msg));

    public IReadOnlyList<PluginLoadResult> LoadResults => _loadResults;
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

/// <summary>Snapshot wrapper for handing the current report to plugins via <see cref="IPluginContext.CurrentReport"/>.</summary>
public sealed record SecurityReportSnapshot(Models.SecurityReport Report);
