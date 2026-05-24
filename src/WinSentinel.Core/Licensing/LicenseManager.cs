using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Licensing;

/// <summary>
/// Local persisted record of an activated WinSentinel license, trial, or grace state.
/// Lives at <c>%APPDATA%\WinSentinel\license.json</c> (Windows) or
/// <c>$XDG_CONFIG_HOME/WinSentinel/license.json</c> (other OS, for dev/test).
///
/// This is the on-disk shape produced by the CLI. It is NOT the signed wire envelope
/// the license server issues - that wire envelope (Ed25519-signed JSON) is stored
/// inside <see cref="Envelope"/> as the original raw text so we can re-verify or
/// refresh it later. A trial record has <see cref="Tier"/> = <c>"trial"</c> and no
/// envelope.
/// </summary>
public sealed class LicenseRecord
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; } = 1;

    /// <summary>License Tier: <c>trial</c>, <c>individual</c>, <c>team</c>.</summary>
    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "trial";

    /// <summary>License key, format <c>WSP-XXXX-XXXX-XXXX</c>. Empty for trials.</summary>
    [JsonPropertyName("key")]
    public string Key { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    /// <summary>UTC issuance timestamp (round-trip ISO-8601, e.g. <c>2026-05-24T09:15:00Z</c>).</summary>
    [JsonPropertyName("issued_at")]
    public DateTimeOffset IssuedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>UTC expiry timestamp. For trials this is <c>IssuedAt + 14 days</c>.</summary>
    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; set; } = DateTimeOffset.UtcNow.AddDays(14);

    /// <summary>Raw signed wire envelope from the license server, if available. Reserved for online refresh.</summary>
    [JsonPropertyName("envelope")]
    public string? Envelope { get; set; }

    /// <summary>Last time we successfully refreshed against the license server. <c>null</c> while offline-only.</summary>
    [JsonPropertyName("last_server_check")]
    public DateTimeOffset? LastServerCheck { get; set; }

    [JsonIgnore]
    public bool IsTrial => string.Equals(Tier, "trial", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when this record (trial or paid) has not yet expired.</summary>
    [JsonIgnore]
    public bool IsActive => DateTimeOffset.UtcNow < ExpiresAt;
}

/// <summary>
/// On-disk store + validation for the WinSentinel license. This is the SOLE
/// gateway used by Pro feature code to ask "is the user entitled to run this?".
///
/// Scope of this class (Day 2 of commercialization):
/// <list type="bullet">
///   <item>Read / write <see cref="LicenseRecord"/> to <see cref="DefaultLicensePath"/>.</item>
///   <item>Syntactic validation of <c>WSP-XXXX-XXXX-XXXX</c> keys.</item>
///   <item>14-day local trial issuance via <see cref="StartTrial"/>.</item>
///   <item>Status reporting via <see cref="GetStatus"/>.</item>
/// </list>
///
/// Out of scope (deliberate, gated on production Ed25519 keypair which is a
/// human-only step):
/// <list type="bullet">
///   <item>Cryptographic signature verification of <see cref="LicenseRecord.Envelope"/>.</item>
///   <item>Online refresh against <c>license.winsentinel.ai</c>.</item>
/// </list>
/// Both will be wired up once the production public key is embedded and the
/// Worker is deployed. The on-disk schema already carries the slots for them.
/// </summary>
public static class LicenseManager
{
    /// <summary>Resolves the default license file path. Returns Windows AppData path on Windows.</summary>
    public static string DefaultLicensePath
    {
        get
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrEmpty(appData))
            {
                // Cross-platform fallback (test/dev only - WinSentinel is Windows-only at runtime).
                var home = Environment.GetEnvironmentVariable("HOME") ?? Path.GetTempPath();
                appData = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") ?? home;
            }
            return Path.Combine(appData, "WinSentinel", "license.json");
        }
    }

    /// <summary>Maximum trial window we ever issue locally. The server can issue longer paid windows.</summary>
    public const int TrialDays = 14;

    // TODO(license): replace with production Ed25519 public key generated
    // out-of-band per docs/plugin-key-setup.md. This is the OFFICIAL
    // WinSentinel project publisher key — used to auto-trust plugins
    // published by the WinSentinel project itself (e.g. winsentinel-pro).
    // Third-party publishers add their own keys via
    // `winsentinel plugin trust <pubkey> --name <name>`. While this
    // placeholder is in place, the official slot contributes no trust and
    // license envelope verification short-circuits to "unverified".
    public const string OfficialPublisherPublicKeyBase64 =
        "REPLACE_ME_PRODUCTION_ED25519_PUBLIC_KEY_BASE64";

    /// <summary>Pricing / upgrade page shown in the friendly "feature requires Pro" message.</summary>
    public const string UpgradeUrl = "https://winsentinel.ai/pricing";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Validates the canonical WinSentinel license key format
    /// <c>WSP-XXXX-XXXX-XXXX</c>. Groups are 4 chars each from the
    /// Crockford base-32 alphabet (uppercase, no I/L/O/U).
    /// At least 3 groups are required; more groups (e.g. extended team keys)
    /// are accepted.
    /// </summary>
    /// <param name="key">The candidate key, e.g. <c>WSP-ABCD-EFGH-JKMN</c>.</param>
    /// <param name="normalized">Receives the upper-cased, trimmed key on success.</param>
    /// <returns><c>true</c> when the key is syntactically valid.</returns>
    public static bool TryNormalizeKey(string? key, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(key)) return false;
        var trimmed = key.Trim().ToUpperInvariant();
        if (!trimmed.StartsWith("WSP-", StringComparison.Ordinal)) return false;
        var parts = trimmed.Split('-');
        if (parts.Length < 4) return false; // "WSP" + at least 3 groups
        for (int i = 1; i < parts.Length; i++)
        {
            var g = parts[i];
            if (g.Length != 4) return false;
            foreach (var c in g)
            {
                // Crockford base-32: 0-9, A-Z minus I, L, O, U
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U')))
                    return false;
            }
        }
        normalized = trimmed;
        return true;
    }

    /// <summary>Reads the persisted license record, or <c>null</c> if none is present / unreadable.</summary>
    public static LicenseRecord? Load(string? path = null)
    {
        var p = path ?? DefaultLicensePath;
        if (!File.Exists(p)) return null;
        try
        {
            var text = File.ReadAllText(p);
            return JsonSerializer.Deserialize<LicenseRecord>(text, JsonOpts);
        }
        catch
        {
            return null; // corrupt file => treat as no license (status will surface this)
        }
    }

    /// <summary>Persists a license record, creating the parent directory if needed.</summary>
    public static void Save(LicenseRecord record, string? path = null)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        var p = path ?? DefaultLicensePath;
        var dir = Path.GetDirectoryName(p);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(record, JsonOpts);
        File.WriteAllText(p, json);
    }

    /// <summary>
    /// Activates a license key locally. Performs syntactic validation only;
    /// cryptographic verification of <paramref name="envelope"/> will land once
    /// the production public key is embedded. If a trial is currently active
    /// and a real key is activated, the trial record is overwritten.
    /// </summary>
    /// <param name="key">Canonical <c>WSP-XXXX-XXXX-XXXX</c> license key.</param>
    /// <param name="email">Buyer email - stored for support correlation only.</param>
    /// <param name="tier"><c>individual</c> or <c>team</c>.</param>
    /// <param name="expiresAt">UTC expiry. Use 1 month from now for monthly subs, 1 year for annual.</param>
    /// <param name="envelope">Optional raw signed wire envelope from the license server. Stored verbatim for later refresh.</param>
    /// <param name="path">Override license file path (tests).</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is malformed or <paramref name="tier"/> is unknown.</exception>
    public static LicenseRecord Activate(
        string key,
        string email,
        string tier,
        DateTimeOffset expiresAt,
        string? envelope = null,
        string? path = null)
    {
        if (!TryNormalizeKey(key, out var normalizedKey))
            throw new ArgumentException($"Invalid license key format: '{key}'. Expected WSP-XXXX-XXXX-XXXX.", nameof(key));
        var normalizedTier = (tier ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedTier != "individual" && normalizedTier != "team")
            throw new ArgumentException($"Unknown tier '{tier}'. Expected 'individual' or 'team'.", nameof(tier));
        if (expiresAt <= DateTimeOffset.UtcNow)
            throw new ArgumentException("expires_at must be in the future.", nameof(expiresAt));

        var record = new LicenseRecord
        {
            Tier = normalizedTier,
            Key = normalizedKey,
            Email = (email ?? string.Empty).Trim(),
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            Envelope = envelope,
        };
        Save(record, path);
        return record;
    }

    /// <summary>
    /// Starts a 14-day local trial. Refuses to overwrite an existing record
    /// (paid or trial) unless <paramref name="force"/> is true.
    /// </summary>
    /// <param name="email">Optional contact email captured at trial start.</param>
    /// <param name="force">When true, overwrites any existing license record.</param>
    /// <param name="path">Override license file path (tests).</param>
    /// <returns>The freshly created trial record.</returns>
    /// <exception cref="InvalidOperationException">When a record already exists and <paramref name="force"/> is false.</exception>
    public static LicenseRecord StartTrial(string? email = null, bool force = false, string? path = null)
    {
        var existing = Load(path);
        if (existing != null && !force)
        {
            throw new InvalidOperationException(
                $"A {existing.Tier} license is already on this machine (expires {existing.ExpiresAt:yyyy-MM-dd}). " +
                "Use --force to overwrite.");
        }
        var now = DateTimeOffset.UtcNow;
        var record = new LicenseRecord
        {
            Tier = "trial",
            Key = string.Empty,
            Email = (email ?? string.Empty).Trim(),
            IssuedAt = now,
            ExpiresAt = now.AddDays(TrialDays),
        };
        Save(record, path);
        return record;
    }

    /// <summary>Removes the persisted license. No-op if absent.</summary>
    public static bool Deactivate(string? path = null)
    {
        var p = path ?? DefaultLicensePath;
        if (!File.Exists(p)) return false;
        File.Delete(p);
        return true;
    }

    /// <summary>
    /// Combines an on-disk record with an in-process override (e.g. <c>--license</c> flag)
    /// to decide whether Pro features should run for this invocation.
    /// </summary>
    public static LicenseStatus GetStatus(string? path = null, string? transientKey = null)
    {
        var record = Load(path);
        if (record == null)
        {
            return new LicenseStatus(
                IsPro: false,
                Tier: "free",
                State: LicenseState.NoLicense,
                ExpiresAt: null,
                DaysRemaining: null,
                Key: null,
                Email: null,
                Message: "Free tier. Run `winsentinel pro start-trial` for a 14-day Pro trial, or buy at " + UpgradeUrl + ".");
        }

        var now = DateTimeOffset.UtcNow;
        var remaining = (record.ExpiresAt - now).TotalDays;
        var daysRemaining = remaining > 0 ? (int)Math.Ceiling(remaining) : 0;

        if (record.ExpiresAt <= now)
        {
            return new LicenseStatus(
                IsPro: false,
                Tier: record.Tier,
                State: record.IsTrial ? LicenseState.TrialExpired : LicenseState.Expired,
                ExpiresAt: record.ExpiresAt,
                DaysRemaining: 0,
                Key: string.IsNullOrEmpty(record.Key) ? null : record.Key,
                Email: string.IsNullOrEmpty(record.Email) ? null : record.Email,
                Message: record.IsTrial
                    ? "Trial expired " + record.ExpiresAt.ToString("yyyy-MM-dd") + ". Upgrade at " + UpgradeUrl + "."
                    : "License expired " + record.ExpiresAt.ToString("yyyy-MM-dd") + ". Renew at " + UpgradeUrl + ".");
        }

        var state = record.IsTrial ? LicenseState.TrialActive : LicenseState.Active;
        var transient = !string.IsNullOrWhiteSpace(transientKey)
            ? " (in-process key override applied)"
            : string.Empty;
        return new LicenseStatus(
            IsPro: true,
            Tier: record.Tier,
            State: state,
            ExpiresAt: record.ExpiresAt,
            DaysRemaining: daysRemaining,
            Key: string.IsNullOrEmpty(record.Key) ? null : record.Key,
            Email: string.IsNullOrEmpty(record.Email) ? null : record.Email,
            Message: (record.IsTrial ? "Pro trial" : "Pro " + record.Tier) +
                     " active, " + daysRemaining + " day" + (daysRemaining == 1 ? "" : "s") + " remaining" + transient + ".");
    }

    /// <summary>
    /// Lightweight entitlement check used by the plugin host. Returns true
    /// iff there is an active (non-expired) <see cref="LicenseRecord"/> on
    /// disk whose tier covers <paramref name="featureId"/>. The current
    /// matrix is intentionally dumb: every paid tier (and an active trial)
    /// is entitled to every plugin. Refine here when SKU-specific gating
    /// arrives — Pro callers should not need to change.
    /// </summary>
    /// <param name="featureId">Feature/plugin id from <c>plugin.json</c>. Currently unused for matching but reserved.</param>
    /// <param name="path">Override license file path (tests).</param>
    public static bool IsEntitled(string featureId, string? path = null)
    {
        // featureId is reserved for future per-feature gating. Today,
        // entitlement is purely a function of having an active license.
        _ = featureId;
        var record = Load(path);
        if (record is null) return false;
        if (!record.IsActive) return false;
        var tier = (record.Tier ?? string.Empty).Trim().ToLowerInvariant();
        return tier is "trial" or "individual" or "team";
    }

    /// <summary>
    /// Single check Pro features call before doing anything: returns
    /// <c>true</c> when the user is entitled, <c>false</c> with a friendly
    /// upgrade message in <paramref name="message"/> otherwise.
    /// </summary>
    public static bool TryRequirePro(string featureName, out string message, string? path = null, string? transientKey = null)
    {
        var status = GetStatus(path, transientKey);
        if (status.IsPro)
        {
            message = status.Message;
            return true;
        }
        var sb = new StringBuilder();
        sb.AppendLine($"  This is a Pro feature: {featureName}");
        sb.AppendLine();
        sb.AppendLine("  " + status.Message);
        sb.AppendLine();
        sb.AppendLine("  Start a free 14-day trial:  winsentinel pro start-trial");
        sb.AppendLine("  Buy a license:               " + UpgradeUrl);
        sb.AppendLine("  Already paid? Activate:      winsentinel pro activate WSP-XXXX-XXXX-XXXX");
        message = sb.ToString();
        return false;
    }
}

/// <summary>Coarse state machine for the local license record.</summary>
public enum LicenseState
{
    /// <summary>No license file on disk.</summary>
    NoLicense,
    /// <summary>Trial record present and not expired.</summary>
    TrialActive,
    /// <summary>Trial record present but past expiry.</summary>
    TrialExpired,
    /// <summary>Paid license present and not expired.</summary>
    Active,
    /// <summary>Paid license present but past expiry.</summary>
    Expired,
}

/// <summary>Result of <see cref="LicenseManager.GetStatus(string?, string?)"/>.</summary>
public sealed record LicenseStatus(
    bool IsPro,
    string Tier,
    LicenseState State,
    DateTimeOffset? ExpiresAt,
    int? DaysRemaining,
    string? Key,
    string? Email,
    string Message);

