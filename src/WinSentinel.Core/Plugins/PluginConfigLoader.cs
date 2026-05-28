using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Loads per-plugin configuration from JSON files at
/// <c>%LOCALAPPDATA%\WinSentinel\plugins-config\{featureId}.json</c>.
/// Falls back to environment variables prefixed
/// <c>WINSENTINEL_PLUGIN_{FEATUREID}_</c>.
///
/// The JSON file is a flat string→string object:
/// <code>{ "apiKey": "...", "outputDir": "C:\\Reports" }</code>
/// </summary>
public static class PluginConfigLoader
{
    /// <summary>Default config directory: <c>%LOCALAPPDATA%\WinSentinel\plugins-config</c>.</summary>
    public static string DefaultConfigDir
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) local = Path.GetTempPath();
            return Path.Combine(local, "WinSentinel", "plugins-config");
        }
    }

    /// <summary>
    /// Loads config for a given featureId. Priority:
    /// 1. JSON file at <paramref name="configDir"/>/{featureId}.json (each key)
    /// 2. Env vars matching WINSENTINEL_PLUGIN_{FEATUREID}_{KEY} (uppercased)
    /// JSON file keys win over env vars for same logical key.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Load(string featureId, string? configDir = null)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Env vars first (lowest priority — overridden by JSON file).
        var prefix = $"WINSENTINEL_PLUGIN_{featureId.Replace("-", "_").ToUpperInvariant()}_";
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            var k = e.Key?.ToString();
            if (k is null || !k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            var shortKey = k[prefix.Length..];
            result[shortKey] = e.Value?.ToString() ?? string.Empty;
        }

        // JSON file (higher priority).
        var dir = configDir ?? DefaultConfigDir;
        var file = Path.Combine(dir, $"{featureId}.json");
        if (File.Exists(file))
        {
            try
            {
                var json = File.ReadAllText(file);
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (dict is not null)
                {
                    foreach (var kv in dict)
                        result[kv.Key] = kv.Value ?? string.Empty;
                }
            }
            catch
            {
                // Malformed config file — silently use env vars only.
            }
        }

        return result;
    }
}
