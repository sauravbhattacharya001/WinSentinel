using System;
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

    private static int HandleHelp()
    {
        Console.WriteLine("winsentinel plugin \u2014 manage signed plugin trust + see load status");
        Console.WriteLine();
        Console.WriteLine("USAGE");
        Console.WriteLine("  winsentinel plugin list [--plugin-format text|json]");
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
