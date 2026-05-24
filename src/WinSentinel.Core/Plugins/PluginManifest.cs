using System.Text.Json.Serialization;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Manifest describing a single WinSentinel plugin. Loaded from a sidecar
/// file <c>&lt;pluginName&gt;.plugin.json</c> next to the plugin DLL.
/// </summary>
/// <remarks>
/// <para>The <see cref="Signature"/> is a base64-encoded Ed25519 signature
/// over the raw SHA-256 hash of the DLL bytes, produced with the private
/// key whose public half is embedded in <see cref="PluginHost"/>.</para>
/// <para>Manifests themselves are <i>not</i> signed — tampering with the
/// manifest only changes which entitlement the plugin claims to need, and
/// the host re-checks entitlements against the user's signed license.
/// What matters is that the DLL bytes match the signed hash.</para>
/// </remarks>
public sealed class PluginManifest
{
    /// <summary>Stable feature id, must match <see cref="IWinSentinelPlugin.FeatureId"/>.</summary>
    [JsonPropertyName("featureId")]
    public string FeatureId { get; set; } = "";

    /// <summary>Plugin semantic version.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    /// <summary>Minimum core version required, e.g. <c>"1.16"</c>.</summary>
    [JsonPropertyName("minCoreVersion")]
    public string MinCoreVersion { get; set; } = "0.0";

    /// <summary>Base64 Ed25519 signature of SHA-256(DLL bytes).</summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    /// <summary>License entitlement id required to load this plugin.</summary>
    [JsonPropertyName("requiredEntitlement")]
    public string RequiredEntitlement { get; set; } = "";
}
