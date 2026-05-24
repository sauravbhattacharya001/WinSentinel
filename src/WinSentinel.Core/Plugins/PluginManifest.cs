using System;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// On-disk shape of the <c>plugin.json</c> resource that every WinSentinel
/// plugin DLL must embed. Matches what the signing pipeline emits in the
/// (private) <c>winsentinel-pro</c> repo.
/// </summary>
public sealed class PluginManifest
{
    /// <summary>Stable feature identifier, e.g. <c>pdf-report</c>.</summary>
    [JsonPropertyName("featureId")]
    public string FeatureId { get; set; } = string.Empty;

    /// <summary>Plugin semver, e.g. <c>1.0.0</c>.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    /// <summary>Minimum required Core version (semver). Reserved for future compatibility gates.</summary>
    [JsonPropertyName("minCoreVersion")]
    public string MinCoreVersion { get; set; } = string.Empty;

    /// <summary>Base64-encoded Ed25519 signature of the DLL's SHA-256 hash.</summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;

    /// <summary>
    /// Entitlement name to look up via <c>LicenseManager.IsEntitled</c>.
    /// Typically equals <see cref="FeatureId"/>.
    /// </summary>
    [JsonPropertyName("requiredEntitlement")]
    public string RequiredEntitlement { get; set; } = string.Empty;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Reads <c>plugin.json</c> from the given assembly's embedded resources.
    /// Tolerant of the resource being named with or without a namespace prefix.
    /// Returns <c>null</c> on any failure (missing resource, malformed JSON).
    /// </summary>
    public static PluginManifest? TryLoadFromAssembly(Assembly assembly)
    {
        if (assembly is null) return null;
        try
        {
            string? name = null;
            foreach (var n in assembly.GetManifestResourceNames())
            {
                if (n.EndsWith("plugin.json", StringComparison.OrdinalIgnoreCase))
                {
                    name = n;
                    break;
                }
            }
            if (name is null) return null;

            using var stream = assembly.GetManifestResourceStream(name);
            if (stream is null) return null;
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            return JsonSerializer.Deserialize<PluginManifest>(json, JsonOpts);
        }
        catch
        {
            return null;
        }
    }
}
