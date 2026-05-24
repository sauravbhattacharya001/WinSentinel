using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Licensing;

/// <summary>
/// Deserialized contents of a WinSentinel license file. The license is a
/// signed JSON blob — see <see cref="LicenseVerifier"/> for the format
/// and the signature scheme.
/// </summary>
public sealed class LicenseInfo
{
    /// <summary>Customer / organization name as it appears on the license.</summary>
    [JsonPropertyName("customer")]
    public string Customer { get; set; } = "";

    /// <summary>Plan tier: <c>"pro"</c> or <c>"team"</c>.</summary>
    [JsonPropertyName("plan")]
    public string Plan { get; set; } = "";

    /// <summary>Entitlement ids granted by this license.</summary>
    [JsonPropertyName("entitlements")]
    public List<string> Entitlements { get; set; } = new();

    /// <summary>UTC timestamp the license was issued.</summary>
    [JsonPropertyName("issued")]
    public DateTimeOffset Issued { get; set; }

    /// <summary>UTC timestamp after which the license is no longer valid.</summary>
    [JsonPropertyName("expires")]
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// Base64 Ed25519 signature over the canonical JSON of every other
    /// field (this property excluded). Validated by
    /// <see cref="LicenseVerifier"/>.
    /// </summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    /// <summary>
    /// Serialize the license without its signature, in a canonical form
    /// suitable for signing / verifying. Field order is stable because
    /// <see cref="JsonSerializer"/> writes declared-property order.
    /// </summary>
    public byte[] CanonicalPayload()
    {
        // Build an unsigned twin to avoid leaking the signature into the
        // verified bytes.
        var unsigned = new LicenseInfo
        {
            Customer = Customer,
            Plan = Plan,
            Entitlements = new List<string>(Entitlements),
            Issued = Issued,
            Expires = Expires,
            Signature = "",
        };

        // Lock down option set so the signing tool and the verifier agree
        // byte-for-byte.
        var opts = new JsonSerializerOptions
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };
        var json = JsonSerializer.Serialize(unsigned, opts);
        return System.Text.Encoding.UTF8.GetBytes(json);
    }
}
