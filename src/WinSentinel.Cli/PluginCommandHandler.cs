using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using WinSentinel.Core.Licensing;
using WinSentinel.Core.Plugins;

namespace WinSentinel.Cli;

/// <summary>
/// Handles <c>winsentinel plugin {list|trust|untrust|help}</c>. Wraps the
/// <see cref="TrustedPublisherStore"/> + <see cref="PluginHost"/> with a
/// human-friendly text/json surface.
///
/// Exit codes:
/// <list type="bullet">
///   <item><c>0</c> \u2014 success</item>
///   <item><c>2</c> \u2014 user error (missing key/name, malformed pubkey)</item>
/// </list>
/// </summary>
internal static class PluginCommandHandler
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static int Handle(CliOptions options)
    {
        return options.PluginAction switch
        {
            PluginAction.List => HandleList(options),
            PluginAction.Trust => HandleTrust(options),
            PluginAction.Untrust => HandleUntrust(options),
            PluginAction.Install => HandleInstall(options),
            PluginAction.Search => HandleSearch(options),
            PluginAction.Show => HandleShow(options),
            PluginAction.Help => HandleHelp(),
            _ => HandleHelp(),
        };
    }

    private static int HandleList(CliOptions options)
    {
        // Spin up a quiet host so we can show what loads / what was skipped.
        // Capture warnings into a buffer so json output stays clean; emit
        // them on stderr only for the text format.
        var trust = TrustedPublisherStore.Load();
        var warnings = new System.Collections.Generic.List<string>();
        var host = new PluginHost(
            trust,
            PluginHost.DefaultPluginDir,
            id => string.IsNullOrEmpty(id) || LicenseManager.IsEntitled(id),
            log: (msg, level) =>
            {
                if (level >= PluginLogLevel.Warning) warnings.Add($"[plugin:{level.ToString().ToLowerInvariant()}] {msg}");
            },
            reportProvider: null);
        // `plugin list` is the trust dashboard \u2014 always show trust-config warnings here.
        host.MaybeWarnAboutTrustConfiguration(always: true);
        host.LoadAll();

        if (string.Equals(options.PluginFormat, "json", StringComparison.OrdinalIgnoreCase))
        {
            var payload = new
            {
                plugin_dir = PluginHost.DefaultPluginDir,
                allow_unsigned = trust.AllowUnsigned,
                trusted_publishers = trust.TrustedPublishers,
                results = host.LoadResults,
            };
            Console.WriteLine(JsonSerializer.Serialize(payload, JsonOpts));
            return 0;
        }

        Console.WriteLine($"Plugin directory: {PluginHost.DefaultPluginDir}");
        Console.WriteLine($"allow_unsigned:   {trust.AllowUnsigned}");
        Console.WriteLine();
        foreach (var w in warnings) Console.Error.WriteLine(w);
        Console.WriteLine("Trusted publishers:");
        if (trust.TrustedPublishers.Count == 0)
        {
            Console.WriteLine("  (none) \u2014 add one with `winsentinel plugin trust <pubkey> --name <name>`");
        }
        else
        {
            foreach (var p in trust.TrustedPublishers)
            {
                var tag = p.AutoTrusted ? " [official]" : string.Empty;
                var fp = Ed25519Crypto.FingerprintShort(p.PublicKey) ?? "(invalid key)";
                Console.WriteLine($"  - {p.Name}{tag}");
                Console.WriteLine($"      key:         {Short(p.PublicKey)}");
                Console.WriteLine($"      fingerprint: {fp}");
            }
        }
        Console.WriteLine();
        Console.WriteLine("Plugins:");
        if (host.LoadResults.Count == 0)
        {
            Console.WriteLine("  (no .dll files found in plugin directory)");
        }
        else
        {
            foreach (var r in host.LoadResults)
            {
                var name = Path.GetFileName(r.DllPath);
                Console.WriteLine($"  [{r.Status}] {name}");
                if (!string.IsNullOrEmpty(r.FeatureId)) Console.WriteLine($"      feature:   {r.FeatureId} v{r.Version}");
                if (!string.IsNullOrEmpty(r.PublisherName))
                {
                    var pfp = Ed25519Crypto.FingerprintShort(r.PublisherKey) ?? "";
                    Console.WriteLine($"      publisher: {r.PublisherName}  {Short(r.PublisherKey)}");
                    if (!string.IsNullOrEmpty(pfp)) Console.WriteLine($"      fp:        {pfp}");
                }
                Console.WriteLine($"      detail:    {r.Message}");
            }
        }
        return 0;
    }

    private static int HandleTrust(CliOptions options)
    {
        // `plugin trust --allow-unsigned` toggles dev mode without a key.
        if (options.PluginAllowUnsigned.HasValue && string.IsNullOrEmpty(options.PluginPublisherKey))
        {
            TrustedPublisherStore.SetAllowUnsigned(options.PluginAllowUnsigned.Value);
            Console.WriteLine($"allow_unsigned is now {options.PluginAllowUnsigned.Value}.");
            if (options.PluginAllowUnsigned.Value)
            {
                Console.WriteLine("WARNING: every WinSentinel run will load UNSIGNED plugins from " + PluginHost.DefaultPluginDir);
                Console.WriteLine("         Disable when you're done: winsentinel plugin trust --allow-unsigned=false");
            }
            return 0;
        }

        if (string.IsNullOrWhiteSpace(options.PluginPublisherKey))
        {
            Console.Error.WriteLine("Usage: winsentinel plugin trust <base64-pubkey> --name <publisher-name>");
            Console.Error.WriteLine("   or: winsentinel plugin trust --allow-unsigned");
            return 2;
        }
        if (string.IsNullOrWhiteSpace(options.PluginPublisherName))
        {
            Console.Error.WriteLine("Missing --name <publisher-name>.");
            return 2;
        }

        try
        {
            var entry = TrustedPublisherStore.Trust(options.PluginPublisherName!, options.PluginPublisherKey!);
            var fp = Ed25519Crypto.FingerprintShort(entry.PublicKey) ?? "(unknown)";
            Console.WriteLine($"Trusted publisher '{entry.Name}' added.");
            Console.WriteLine($"  key:         {Short(entry.PublicKey)}");
            Console.WriteLine($"  fingerprint: {fp}");
            if (options.PluginAllowUnsigned.HasValue)
            {
                TrustedPublisherStore.SetAllowUnsigned(options.PluginAllowUnsigned.Value);
                Console.WriteLine($"allow_unsigned set to {options.PluginAllowUnsigned.Value}.");
            }
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 2;
        }
    }

    private static int HandleUntrust(CliOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.PluginPublisherName))
        {
            Console.Error.WriteLine("Usage: winsentinel plugin untrust <publisher-name>");
            return 2;
        }
        var removed = TrustedPublisherStore.Untrust(options.PluginPublisherName!);
        if (removed)
        {
            Console.WriteLine($"Removed publisher '{options.PluginPublisherName}'.");
            return 0;
        }
        Console.Error.WriteLine($"No user-trusted publisher named '{options.PluginPublisherName}' found (the official entry cannot be removed).");
        return 2;
    }

    private const string RegistryUrl = "https://raw.githubusercontent.com/sauravbhattacharya001/WinSentinel/main/docs/registry.json";

    private static List<RegistryEntry>? FetchRegistry()
    {
        try
        {
            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("WinSentinel-CLI/1.0");
            var json = http.GetStringAsync(RegistryUrl).GetAwaiter().GetResult();
            return JsonSerializer.Deserialize<List<RegistryEntry>>(json, JsonOpts);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to fetch plugin registry: {ex.Message}");
            return null;
        }
    }

    private static int HandleSearch(CliOptions options)
    {
        var query = options.PluginSearchQuery;
        var registry = FetchRegistry();
        if (registry is null) return 1;

        var results = string.IsNullOrWhiteSpace(query)
            ? registry
            : registry.Where(e =>
                (e.FeatureId?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Name?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Description?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Tags?.Any(t => t.Contains(query, StringComparison.OrdinalIgnoreCase)) ?? false))
            .ToList();

        if (results.Count == 0)
        {
            Console.WriteLine(query is null ? "No plugins in registry." : $"No plugins matching '{query}'.");
            return 0;
        }

        Console.WriteLine($"Found {results.Count} plugin(s):");
        Console.WriteLine();
        foreach (var e in results)
        {
            Console.WriteLine($"  {e.FeatureId}  v{e.LatestVersion}");
            Console.WriteLine($"    {e.Name} — {e.Description}");
            Console.WriteLine($"    vendor: {e.Vendor}");
            if (!string.IsNullOrEmpty(e.Repo)) Console.WriteLine($"    repo:   {e.Repo}");
            Console.WriteLine();
        }
        return 0;
    }

    private static int HandleShow(CliOptions options)
    {
        var featureId = options.PluginSearchQuery;
        if (string.IsNullOrWhiteSpace(featureId))
        {
            Console.Error.WriteLine("Usage: winsentinel plugin show <featureId>");
            return 2;
        }

        var registry = FetchRegistry();
        if (registry is null) return 1;

        var entry = registry.FirstOrDefault(e =>
            string.Equals(e.FeatureId, featureId, StringComparison.OrdinalIgnoreCase));

        if (entry is null)
        {
            Console.Error.WriteLine($"Plugin '{featureId}' not found in registry.");
            return 1;
        }

        Console.WriteLine($"  Feature ID:  {entry.FeatureId}");
        Console.WriteLine($"  Name:        {entry.Name}");
        Console.WriteLine($"  Version:     {entry.LatestVersion}");
        Console.WriteLine($"  Vendor:      {entry.Vendor}");
        Console.WriteLine($"  Description: {entry.Description}");
        if (!string.IsNullOrEmpty(entry.Repo)) Console.WriteLine($"  Repository:  {entry.Repo}");
        if (!string.IsNullOrEmpty(entry.PublisherPubkey))
        {
            Console.WriteLine($"  Publisher:   {Short(entry.PublisherPubkey)}");
            var fp = Ed25519Crypto.FingerprintShort(entry.PublisherPubkey);
            if (fp != null) Console.WriteLine($"  Fingerprint: {fp}");
        }
        if (!string.IsNullOrEmpty(entry.SignedDllUrl))
            Console.WriteLine($"  Download:    {entry.SignedDllUrl}");
        if (entry.Tags is { Count: > 0 })
            Console.WriteLine($"  Tags:        {string.Join(", ", entry.Tags)}");

        if (!string.IsNullOrEmpty(entry.SignedDllUrl))
        {
            Console.WriteLine();
            Console.WriteLine($"  Install with: winsentinel plugin install {entry.SignedDllUrl}");
        }
        return 0;
    }

    private sealed class RegistryEntry
    {
        [System.Text.Json.Serialization.JsonPropertyName("featureId")]
        public string? FeatureId { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string? Name { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("vendor")]
        public string? Vendor { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("repo")]
        public string? Repo { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("latest_version")]
        public string? LatestVersion { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("signed_dll_url")]
        public string? SignedDllUrl { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("publisher_pubkey")]
        public string? PublisherPubkey { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("description")]
        public string? Description { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("tags")]
        public List<string>? Tags { get; set; }
    }

    private static int HandleInstall(CliOptions options)
    {
        var source = options.PluginInstallSource;
        if (string.IsNullOrWhiteSpace(source))
        {
            Console.Error.WriteLine("Usage: winsentinel plugin install <url-or-path>");
            Console.Error.WriteLine("  Downloads (or copies) the DLL, verifies its embedded plugin.json,");
            Console.Error.WriteLine("  displays the publisher fingerprint, and prompts for trust confirmation.");
            return 2;
        }

        // Resolve DLL bytes
        byte[] dllBytes;
        string fileName;
        if (Uri.TryCreate(source, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https"))
        {
            Console.WriteLine($"Downloading {source}...");
            try
            {
                using var http = new System.Net.Http.HttpClient();
                http.DefaultRequestHeaders.UserAgent.ParseAdd("WinSentinel-CLI/1.0");
                dllBytes = http.GetByteArrayAsync(uri).GetAwaiter().GetResult();
                fileName = Path.GetFileName(uri.LocalPath);
                if (string.IsNullOrEmpty(fileName) || !fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    fileName = "plugin.dll";
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Download failed: {ex.Message}");
                return 1;
            }
        }
        else if (File.Exists(source))
        {
            dllBytes = File.ReadAllBytes(source);
            fileName = Path.GetFileName(source);
        }
        else
        {
            Console.Error.WriteLine($"Source not found: {source}");
            return 1;
        }

        // Load into temp ALC to read manifest
        var tempPath = Path.Combine(Path.GetTempPath(), $"winsentinel-install-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(tempPath, dllBytes);
        System.Reflection.Assembly asm;
        try
        {
            var alc = new System.Runtime.Loader.AssemblyLoadContext("PluginInstallProbe", isCollectible: true);
            using var ms = new MemoryStream(dllBytes);
            asm = alc.LoadFromStream(ms);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Not a valid .NET assembly: {ex.Message}");
            try { File.Delete(tempPath); } catch { }
            return 1;
        }

        var manifest = PluginManifest.TryLoadFromAssembly(asm);
        if (manifest is null)
        {
            Console.Error.WriteLine("Error: DLL does not contain an embedded plugin.json manifest.");
            try { File.Delete(tempPath); } catch { }
            return 1;
        }

        // Display manifest info
        var fp = Ed25519Crypto.FingerprintShort(manifest.PublisherKey) ?? "(no key)";
        Console.WriteLine();
        Console.WriteLine("  Plugin manifest:");
        Console.WriteLine($"    Feature:    {manifest.FeatureId}");
        Console.WriteLine($"    Version:    {manifest.Version}");
        Console.WriteLine($"    Publisher:  {manifest.PublisherName}");
        Console.WriteLine($"    Key:        {Short(manifest.PublisherKey)}");
        Console.WriteLine($"    Fingerprint:{fp}");
        if (!string.IsNullOrEmpty(manifest.RequiredEntitlement))
            Console.WriteLine($"    Entitlement:{manifest.RequiredEntitlement}");
        Console.WriteLine();

        // Check if publisher is already trusted
        var trust = TrustedPublisherStore.Load();
        var pubBytes = Ed25519Crypto.TryDecodeBase64(manifest.PublisherKey);
        bool alreadyTrusted = false;
        if (pubBytes is { Length: Ed25519Crypto.PublicKeySize })
        {
            foreach (var tp in trust.TrustedPublishers)
            {
                var tpBytes = Ed25519Crypto.TryDecodeBase64(tp.PublicKey);
                if (tpBytes != null && tpBytes.AsSpan().SequenceEqual(pubBytes))
                {
                    alreadyTrusted = true;
                    break;
                }
            }
        }

        if (!alreadyTrusted)
        {
            Console.Write($"  Trust publisher '{manifest.PublisherName}' ({fp})? [y/N] ");
            var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (answer != "y" && answer != "yes")
            {
                Console.WriteLine("  Aborted. Publisher not trusted, plugin not installed.");
                try { File.Delete(tempPath); } catch { }
                return 1;
            }
            // Add trust
            TrustedPublisherStore.Trust(manifest.PublisherName, manifest.PublisherKey);
            Console.WriteLine($"  Publisher '{manifest.PublisherName}' trusted.");
        }
        else
        {
            Console.WriteLine($"  Publisher '{manifest.PublisherName}' is already trusted.");
        }

        // Verify signature
        if (!string.IsNullOrWhiteSpace(manifest.Signature) && pubBytes != null)
        {
            var sigBytes = Ed25519Crypto.TryDecodeBase64(manifest.Signature);
            var hash = System.Security.Cryptography.SHA256.HashData(dllBytes);
            if (sigBytes is null || !Ed25519Crypto.Verify(pubBytes, hash, sigBytes))
            {
                Console.Error.WriteLine("  ERROR: Signature verification FAILED. DLL may be tampered.");
                Console.Error.WriteLine("  Plugin NOT installed.");
                try { File.Delete(tempPath); } catch { }
                return 1;
            }
            Console.WriteLine("  Signature verified \u2713");
        }
        else if (!trust.AllowUnsigned)
        {
            Console.Error.WriteLine("  ERROR: Plugin is unsigned and allow_unsigned=false.");
            Console.Error.WriteLine("  Use `winsentinel plugin trust --allow-unsigned` to allow, or ask the publisher to sign.");
            try { File.Delete(tempPath); } catch { }
            return 1;
        }

        // Copy to plugin directory
        var pluginDir = PluginHost.DefaultPluginDir;
        Directory.CreateDirectory(pluginDir);
        var destPath = Path.Combine(pluginDir, fileName);
        if (File.Exists(destPath))
        {
            Console.Write($"  {fileName} already exists in plugin dir. Overwrite? [y/N] ");
            var ow = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (ow != "y" && ow != "yes")
            {
                Console.WriteLine("  Aborted.");
                try { File.Delete(tempPath); } catch { }
                return 1;
            }
        }
        File.Copy(tempPath, destPath, overwrite: true);
        try { File.Delete(tempPath); } catch { }

        Console.WriteLine($"  Installed: {destPath}");
        Console.WriteLine();
        Console.WriteLine($"  Run `winsentinel plugin list` to verify it loads.");
        return 0;
    }

    private static int HandleHelp()
    {
        Console.WriteLine("winsentinel plugin \u2014 manage signed plugin trust + see load status");
        Console.WriteLine();
        Console.WriteLine("USAGE");
        Console.WriteLine("  winsentinel plugin list [--plugin-format text|json]");
        Console.WriteLine("  winsentinel plugin search [<query>]");
        Console.WriteLine("  winsentinel plugin show <featureId>");
        Console.WriteLine("  winsentinel plugin install <url-or-path>");
        Console.WriteLine("  winsentinel plugin trust <base64-pubkey> --name <publisher-name>");
        Console.WriteLine("  winsentinel plugin trust --allow-unsigned[=false]");
        Console.WriteLine("  winsentinel plugin untrust <publisher-name>");
        Console.WriteLine();
        Console.WriteLine("Trust file: " + TrustedPublisherStore.DefaultConfigPath);
        Console.WriteLine("Plugin dir: " + PluginHost.DefaultPluginDir);
        Console.WriteLine("Docs:       docs/CREATING-PLUGINS.md");
        return 0;
    }

    private static string Short(string? base64)
    {
        if (string.IsNullOrEmpty(base64)) return "(none)";
        return base64.Length <= 12 ? base64 : base64.Substring(0, 8) + "\u2026" + base64.Substring(base64.Length - 4);
    }
}
