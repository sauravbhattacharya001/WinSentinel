using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Windows Firewall LOGGING configuration on a single
/// machine, evaluated per profile (Domain / Private / Public).
///
/// The firewall's block/allow rules decide what gets through; its logging
/// settings decide whether you can ever SEE what it dropped or allowed. A host
/// with a perfectly hardened rule set but logging turned off is a host where an
/// incident responder has no packet-level evidence of a scan, a lateral-movement
/// attempt, or an exfiltration path being probed. CIS Windows L1 explicitly
/// requires, for every profile:
///
///   * LogDroppedPackets = 1        - record blocked inbound/outbound packets so
///                                    recon and blocked C2 attempts leave a trail.
///   * LogSuccessfulConnections = 1 - record allowed connections so you can spot
///                                    unexpected allowed egress / lateral moves.
///   * A log file MaxFileSize of at least 16384 KB (16 MB) so the log does not
///                                    wrap and lose evidence within minutes.
///   * A LogFilePath configured so the log actually lands somewhere on disk.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// firewall-profile registry state only. Nothing multi-machine, nothing
/// license-gated. All rules operate on a synthetic
/// <see cref="FirewallLoggingState"/> so they can be unit tested directly,
/// mirroring the established collector-owns-I/O / analyzer-owns-decisions split
/// used by <see cref="LsaHardeningAnalyzer"/>.
/// </summary>
public static class FirewallLoggingAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Firewall";

    /// <summary>
    /// The CIS-recommended minimum firewall log size in kilobytes (16 MB). A log
    /// smaller than this wraps quickly on a busy host and loses evidence.
    /// </summary>
    public const int MinLogFileSizeKb = 16384;

    /// <summary>The three Windows Firewall profiles, in stable report order.</summary>
    public static readonly IReadOnlyList<string> Profiles = new[] { "Domain", "Private", "Public" };

    /// <summary>
    /// Evaluate every collected per-profile logging state and return findings in a
    /// stable, deterministic order (all checks for Domain, then Private, then
    /// Public) so reports diff cleanly between runs.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(FirewallLoggingState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>();
        foreach (var profile in Profiles)
        {
            var p = state.GetProfile(profile);
            findings.Add(AnalyzeLogDropped(profile, p));
            findings.Add(AnalyzeLogAllowed(profile, p));
            findings.Add(AnalyzeLogSize(profile, p));
            findings.Add(AnalyzeLogPath(profile, p));
        }
        return findings;
    }

    /// <summary>LogDroppedPackets must be 1 for the profile.</summary>
    public static Finding AnalyzeLogDropped(string profile, FirewallProfileLogging p)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (p.LogDroppedPackets == 1)
        {
            return Finding.Pass(
                $"{profile} firewall logs dropped packets",
                $"LogDroppedPackets is enabled for the {profile} profile, so blocked inbound/outbound " +
                "packets are recorded - the evidence trail for scans and blocked C2 attempts.",
                Category);
        }

        return Finding.Warning(
            $"{profile} firewall does not log dropped packets",
            $"LogDroppedPackets is disabled (or unset) for the {profile} profile. Blocked packets leave " +
            "no record, so port scans and blocked malicious connections are invisible to incident response.",
            Category,
            remediation: $"Enable dropped-packet logging for the {profile} profile " +
                         "(gpedit / netsh advfirewall).",
            fixCommand: $"netsh advfirewall set {profile.ToLowerInvariant()}profile logging droppedconnections enable");
    }

    /// <summary>LogSuccessfulConnections must be 1 for the profile.</summary>
    public static Finding AnalyzeLogAllowed(string profile, FirewallProfileLogging p)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (p.LogSuccessfulConnections == 1)
        {
            return Finding.Pass(
                $"{profile} firewall logs successful connections",
                $"LogSuccessfulConnections is enabled for the {profile} profile, so allowed connections " +
                "are recorded - letting you spot unexpected allowed egress or lateral movement.",
                Category);
        }

        return Finding.Warning(
            $"{profile} firewall does not log successful connections",
            $"LogSuccessfulConnections is disabled (or unset) for the {profile} profile. Allowed " +
            "connections leave no record, so unexpected outbound egress and lateral movement over " +
            "permitted ports go unseen.",
            Category,
            remediation: $"Enable allowed-connection logging for the {profile} profile.",
            fixCommand: $"netsh advfirewall set {profile.ToLowerInvariant()}profile logging allowedconnections enable");
    }

    /// <summary>The log file must be at least <see cref="MinLogFileSizeKb"/> KB.</summary>
    public static Finding AnalyzeLogSize(string profile, FirewallProfileLogging p)
    {
        ArgumentNullException.ThrowIfNull(p);
        int size = p.LogFileSizeKb ?? 0;
        if (size >= MinLogFileSizeKb)
        {
            return Finding.Pass(
                $"{profile} firewall log size is adequate",
                $"The {profile} profile firewall log is {size} KB, at or above the recommended {MinLogFileSizeKb} KB, " +
                "so it does not wrap and discard evidence within minutes on a busy host.",
                Category);
        }

        return Finding.Warning(
            $"{profile} firewall log is too small",
            $"The {profile} profile firewall log is {size} KB, below the recommended minimum of {MinLogFileSizeKb} KB " +
            "(16 MB). A small log wraps quickly and loses the very events you would need after an incident.",
            Category,
            remediation: $"Raise the {profile} profile firewall log MaxFileSize to at least {MinLogFileSizeKb} KB.",
            fixCommand: $"netsh advfirewall set {profile.ToLowerInvariant()}profile logging maxfilesize {MinLogFileSizeKb}");
    }

    /// <summary>A LogFilePath must be configured for the profile.</summary>
    public static Finding AnalyzeLogPath(string profile, FirewallProfileLogging p)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (!string.IsNullOrWhiteSpace(p.LogFilePath))
        {
            return Finding.Pass(
                $"{profile} firewall log path is configured",
                $"The {profile} profile firewall log writes to '{p.LogFilePath}', so records land on disk.",
                Category);
        }

        return Finding.Warning(
            $"{profile} firewall log path is not configured",
            $"No LogFilePath is set for the {profile} profile, so even if logging is enabled the events " +
            "may not be written to a known location for review.",
            Category,
            remediation: $"Set the {profile} profile firewall log file path (default " +
                         "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log).",
            fixCommand: $"netsh advfirewall set {profile.ToLowerInvariant()}profile logging filename " +
                        "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log");
    }
}

/// <summary>
/// Raw, collector-supplied Windows Firewall logging state for all three profiles.
/// Populated by the audit module's I/O layer and handed to
/// <see cref="FirewallLoggingAnalyzer"/> for a pure decision. A missing profile
/// resolves to an empty <see cref="FirewallProfileLogging"/> (all-null), which the
/// analyzer treats as "logging not configured" - the conservative default.
/// </summary>
public class FirewallLoggingState
{
    /// <summary>Domain profile logging state.</summary>
    public FirewallProfileLogging Domain { get; set; } = new();

    /// <summary>Private (standard) profile logging state.</summary>
    public FirewallProfileLogging Private { get; set; } = new();

    /// <summary>Public profile logging state.</summary>
    public FirewallProfileLogging Public { get; set; } = new();

    /// <summary>Resolve the logging state for a profile name; never null.</summary>
    public FirewallProfileLogging GetProfile(string profile) => profile switch
    {
        "Domain" => Domain,
        "Private" => Private,
        "Public" => Public,
        _ => new FirewallProfileLogging(),
    };
}

/// <summary>
/// Logging settings for a single Windows Firewall profile. Null numeric fields
/// mean "value absent / not readable"; the analyzer treats absence as the
/// unconfigured/default state (logging off, size 0, no path).
/// </summary>
public class FirewallProfileLogging
{
    /// <summary>REG_DWORD LogDroppedPackets (1 = log dropped packets).</summary>
    public int? LogDroppedPackets { get; set; }

    /// <summary>REG_DWORD LogSuccessfulConnections (1 = log allowed connections).</summary>
    public int? LogSuccessfulConnections { get; set; }

    /// <summary>REG_DWORD LogFileSize in kilobytes.</summary>
    public int? LogFileSizeKb { get; set; }

    /// <summary>REG_SZ/REG_EXPAND_SZ LogFilePath, or null when unset.</summary>
    public string? LogFilePath { get; set; }
}
