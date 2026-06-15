using System.Globalization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="DefenderAudit"/> module.
///
/// All Windows Defender posture decisions live here — parsing the raw text that
/// <c>Get-MpPreference</c> / <c>Get-MpComputerStatus</c> emit and turning it into
/// <see cref="Finding"/> objects: real-time protection on/off, antivirus
/// definition freshness (with the 24h/72h staleness thresholds), cloud-protection
/// (MAPS) level, Tamper Protection on/off, and quick-scan recency (14-day
/// threshold).
///
/// Nothing here runs PowerShell, touches the registry, or reads the clock — the
/// time-relative checks (definition age, scan age) take an injected "now" so the
/// staleness boundaries can be unit tested deterministically. The audit module
/// owns only the collection of raw PowerShell output and delegates every
/// classification to this class.
///
/// Mirrors the established <see cref="EncryptionAnalyzer"/> /
/// <see cref="EventLogAnalyzer"/> / <see cref="IdentityCredentialAnalyzer"/>
/// pattern. Several <c>Build*Finding</c> methods return <c>null</c> to mean
/// "emit no finding" — this preserves the audit's original behavior of staying
/// silent when a value can't be determined (e.g. a third-party AV is managing
/// protection, so <c>Get-MpComputerStatus</c> returns nothing parseable).
/// </summary>
public static class DefenderAnalyzer
{
    /// <summary>Category label shared with <see cref="DefenderAudit"/>.</summary>
    public const string Category = "Defender";

    // ──────────────────────────────────────────────────────────────────────
    // Thresholds (documented + testable in one place)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Definitions older than this many hours are Critical.</summary>
    public const double DefinitionCriticalHours = 72;

    /// <summary>Definitions older than this many hours (but within Critical) are a Warning.</summary>
    public const double DefinitionWarningHours = 24;

    /// <summary>Quick scans older than this many days raise a Warning.</summary>
    public const int QuickScanWarningDays = 14;

    /// <summary>Timestamp format the audit requests from PowerShell (sortable, fixed).</summary>
    public const string TimestampFormat = "yyyy-MM-dd HH:mm:ss";

    // ──────────────────────────────────────────────────────────────────────
    // Tri-state for boolean Defender flags
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Result of parsing a "True"/"False"/other boolean PowerShell value.</summary>
    public enum BoolState
    {
        /// <summary>PowerShell returned "True".</summary>
        True,
        /// <summary>PowerShell returned "False".</summary>
        False,
        /// <summary>Empty / non-boolean output (status could not be determined).</summary>
        Unknown,
    }

    /// <summary>
    /// Parse a PowerShell boolean value ("True"/"False", case-insensitive, trimmed).
    /// Anything else (blank, error text, a third-party-AV "null") is <see cref="BoolState.Unknown"/>.
    /// </summary>
    public static BoolState ParseBool(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        if (t.Equals("True", StringComparison.OrdinalIgnoreCase)) return BoolState.True;
        if (t.Equals("False", StringComparison.OrdinalIgnoreCase)) return BoolState.False;
        return BoolState.Unknown;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Real-time protection — value is (Get-MpPreference).DisableRealtimeMonitoring
    // so True == protection DISABLED.
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the real-time-protection finding from the raw
    /// <c>DisableRealtimeMonitoring</c> value. Always returns a finding (the audit
    /// emits an Info "status unknown" line when the value is indeterminate).
    /// </summary>
    public static Finding BuildRealtimeProtectionFinding(string? disableRealtimeOutput)
        => BuildRealtimeProtectionFinding(ParseBool(disableRealtimeOutput));

    /// <inheritdoc cref="BuildRealtimeProtectionFinding(string?)"/>
    public static Finding BuildRealtimeProtectionFinding(BoolState disableRealtime)
    {
        return disableRealtime switch
        {
            // DisableRealtimeMonitoring == True  -> real-time protection OFF.
            BoolState.True => Finding.Critical(
                "Real-Time Protection Disabled",
                "Windows Defender real-time protection is DISABLED. Malware can run without detection.",
                Category,
                "Enable real-time protection immediately.",
                "Set-MpPreference -DisableRealtimeMonitoring $false"),
            // DisableRealtimeMonitoring == False -> real-time protection ON.
            BoolState.False => Finding.Pass(
                "Real-Time Protection Enabled",
                "Windows Defender real-time protection is active.",
                Category),
            _ => Finding.Info(
                "Real-Time Protection Status Unknown",
                "Could not determine real-time protection status. A third-party antivirus may be managing protection.",
                Category),
        };
    }

    // ──────────────────────────────────────────────────────────────────────
    // Tamper protection — value is (Get-MpComputerStatus).IsTamperProtected.
    // True == protected (Pass), False == Warning, anything else == no finding.
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the Tamper-Protection finding from the raw <c>IsTamperProtected</c>
    /// value. Returns <c>null</c> for an indeterminate value (the audit emits no
    /// finding in that case).
    /// </summary>
    public static Finding? BuildTamperProtectionFinding(string? isTamperProtectedOutput)
        => BuildTamperProtectionFinding(ParseBool(isTamperProtectedOutput));

    /// <inheritdoc cref="BuildTamperProtectionFinding(string?)"/>
    public static Finding? BuildTamperProtectionFinding(BoolState isTamperProtected)
    {
        return isTamperProtected switch
        {
            BoolState.False => Finding.Warning(
                "Tamper Protection Disabled",
                "Tamper Protection is disabled. Malware could potentially modify or disable Windows Defender settings.",
                Category,
                "Enable Tamper Protection in Windows Security settings.",
                "Start-Process 'windowsdefender://ThreatSettings'"),
            BoolState.True => Finding.Pass(
                "Tamper Protection Enabled",
                "Tamper Protection is active, preventing unauthorized changes to security settings.",
                Category),
            _ => null,
        };
    }

    // ──────────────────────────────────────────────────────────────────────
    // Cloud protection (MAPS) — value is (Get-MpPreference).MAPSReporting (int).
    // 0 == disabled (Warning); any other parseable level == enabled (Pass);
    // unparseable == no finding.
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parse the MAPS reporting level. Returns the integer level, or <c>null</c>
    /// when the output is not an integer.
    /// </summary>
    public static int? ParseMapsReporting(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        return int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var level)
            ? level
            : (int?)null;
    }

    /// <summary>
    /// Build the cloud-protection finding from the raw MAPSReporting value. Returns
    /// <c>null</c> when the value is not an integer (the audit emits no finding).
    /// </summary>
    public static Finding? BuildCloudProtectionFinding(string? mapsReportingOutput)
        => BuildCloudProtectionFinding(ParseMapsReporting(mapsReportingOutput));

    /// <inheritdoc cref="BuildCloudProtectionFinding(string?)"/>
    public static Finding? BuildCloudProtectionFinding(int? mapsLevel)
    {
        if (mapsLevel is null) return null;
        if (mapsLevel == 0)
        {
            return Finding.Warning(
                "Cloud Protection Disabled",
                "Microsoft cloud-based protection (MAPS) is disabled. Cloud protection provides faster detection of new threats.",
                Category,
                "Enable cloud-based protection for better threat detection.",
                "Set-MpPreference -MAPSReporting Advanced");
        }
        return Finding.Pass(
            "Cloud Protection Enabled",
            $"Microsoft cloud-based protection is enabled (level: {mapsLevel}).",
            Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Timestamp parsing — shared by definition-freshness and quick-scan checks.
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parse a timestamp emitted by <c>.ToString('yyyy-MM-dd HH:mm:ss')</c>. Returns
    /// <c>null</c> when the output is blank or unparseable (matching the audit's
    /// <c>DateTime.TryParse</c> behavior). Parsing is invariant-culture and tolerant
    /// of the exact format plus a general parse fallback.
    /// </summary>
    public static DateTime? ParseTimestamp(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        if (t.Length == 0) return null;
        if (DateTime.TryParseExact(t, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var exact))
            return exact;
        if (DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return parsed;
        return null;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Definition freshness — (Get-MpComputerStatus).AntivirusSignatureLastUpdated.
    // Thresholds measured in *hours* relative to an injected "now".
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the definition-freshness finding from the raw timestamp output and a
    /// reference time. Returns <c>null</c> when the timestamp is unparseable.
    /// </summary>
    public static Finding? BuildDefinitionFreshnessFinding(string? lastUpdatedOutput, DateTime now)
    {
        var ts = ParseTimestamp(lastUpdatedOutput);
        return ts is null ? null : BuildDefinitionFreshnessFinding(ts.Value, now);
    }

    /// <inheritdoc cref="BuildDefinitionFreshnessFinding(string?, DateTime)"/>
    public static Finding BuildDefinitionFreshnessFinding(DateTime lastUpdated, DateTime now)
    {
        var hoursSinceUpdate = (now - lastUpdated).TotalHours;

        if (hoursSinceUpdate > DefinitionCriticalHours)
        {
            return Finding.Critical(
                "Antivirus Definitions Severely Outdated",
                $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}). System is vulnerable to new threats.",
                Category,
                "Update antivirus definitions immediately.",
                "Update-MpSignature");
        }
        if (hoursSinceUpdate > DefinitionWarningHours)
        {
            return Finding.Warning(
                "Antivirus Definitions Outdated",
                $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}).",
                Category,
                "Update antivirus definitions.",
                "Update-MpSignature");
        }
        return Finding.Pass(
            "Antivirus Definitions Current",
            $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}).",
            Category);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Quick-scan recency — (Get-MpComputerStatus).QuickScanEndTime.
    // Threshold measured in whole *days* relative to an injected "now"
    // (preserves the audit's original int-truncating .Days semantics).
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the quick-scan-recency finding from the raw timestamp output and a
    /// reference time. Returns <c>null</c> when the timestamp is unparseable.
    /// </summary>
    public static Finding? BuildQuickScanFinding(string? lastScanOutput, DateTime now)
    {
        var ts = ParseTimestamp(lastScanOutput);
        return ts is null ? null : BuildQuickScanFinding(ts.Value, now);
    }

    /// <inheritdoc cref="BuildQuickScanFinding(string?, DateTime)"/>
    public static Finding BuildQuickScanFinding(DateTime lastScan, DateTime now)
    {
        // Whole days, matching the original (DateTime.Now - lastScan).Days.
        var daysSinceScan = (now - lastScan).Days;

        if (daysSinceScan > QuickScanWarningDays)
        {
            return Finding.Warning(
                "No Recent Quick Scan",
                $"Last quick scan was {daysSinceScan} days ago ({lastScan:d}). Regular scans help detect dormant threats.",
                Category,
                "Run a quick scan to check for threats.",
                "Start-MpScan -ScanType QuickScan");
        }
        return Finding.Pass(
            "Recent Scan Completed",
            $"Last quick scan was {daysSinceScan} days ago ({lastScan:d}).",
            Category);
    }
}
