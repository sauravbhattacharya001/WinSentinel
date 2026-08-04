using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing single-machine Windows time-synchronization security. Accurate
/// system time is a security control, not just a convenience: Kerberos rejects tickets whose clock
/// skew exceeds ~5 minutes (so a drifting clock silently breaks domain auth), TLS/code-signing
/// certificate validity windows depend on the clock, and log correlation / incident timelines are
/// worthless if the clock is wrong. An attacker who can shift the local clock (or point W32Time at a
/// rogue NTP peer) can revive expired certificates, replay Kerberos tickets, or scramble forensic
/// timelines. All of the checks here read local Windows Time service (W32Time) configuration and
/// state, so this module is single-machine and therefore FREE / OSS: nothing multi-machine, nothing
/// license-gated.
///
/// <para>Every rule operates on a synthetic <see cref="TimeSyncState"/> so it can be unit tested
/// directly, mirroring the established <see cref="ExploitMitigationAnalyzer"/> /
/// <see cref="WerExposureAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
///
///   * W32Time service running - if the Windows Time service is stopped, the clock is not being
///     disciplined at all and will drift freely. Stopped is the risky state.
///   * Sync type (Type value) - "NTP" (standalone) or "NT5DS" (domain hierarchy) are healthy;
///     "NoSync" means time sync is explicitly turned off (risky); "AllSync" is legacy/acceptable.
///   * NTP peer configured - a NoSync/empty peer, or an insecure plain-HTTP-looking peer, is
///     surfaced. An unauthenticated public NTP peer on a domain-joined machine is called out as Info
///     because domain members should sync up the domain hierarchy (NT5DS), not an arbitrary peer.
///   * Unbounded phase correction - MaxPosPhaseCorrection / MaxNegPhaseCorrection cap how far a
///     single correction may move the clock. 0xFFFFFFFF (or a huge value) means "accept any jump",
///     which lets a rogue/spoofed time source shift the clock arbitrarily. A bounded correction is
///     the safe posture.
/// </summary>
public static class TimeSyncSecurityAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Time Synchronization";

    /// <summary>The sentinel meaning "no maximum" for phase-correction values (0xFFFFFFFF).</summary>
    public const long UnlimitedPhaseCorrection = 0xFFFFFFFFL;

    /// <summary>
    /// A phase-correction cap at or above this many seconds is treated as effectively unbounded even
    /// when it is not the literal 0xFFFFFFFF sentinel (a year is far larger than any legitimate drift
    /// correction and would let a spoofed source shift the clock arbitrarily).
    /// </summary>
    public const long EffectivelyUnlimitedSeconds = 31_536_000L;

    /// <summary>
    /// Evaluate the collected time-sync state and return one finding per check (a Pass when the
    /// setting is already safe, otherwise Info/Warning). Ordering is stable and deterministic for
    /// diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(TimeSyncState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeServiceRunning(state),
            AnalyzeSyncType(state),
            AnalyzeNtpPeer(state),
            AnalyzePhaseCorrection(state),
        };
    }

    /// <summary>
    /// The Windows Time service (W32Time) disciplines the system clock. If it is stopped, the clock
    /// drifts uncorrected - eventually breaking Kerberos auth and invalidating log timestamps.
    /// </summary>
    public static Finding AnalyzeServiceRunning(TimeSyncState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.ServiceRunning)
        {
            return Finding.Warning(
                "Windows Time service is not running",
                "The Windows Time service (W32Time) is not running, so the system clock is not being disciplined against a " +
                "trusted time source and will drift freely. Once skew exceeds ~5 minutes, Kerberos rejects authentication " +
                "(silently breaking domain logons and Kerberos-authenticated services), certificate validity checks become " +
                "unreliable, and security-log timestamps can no longer be correlated across machines.",
                Category,
                remediation: "Start and enable the Windows Time service so the clock stays disciplined.",
                fixCommand: "Set-Service -Name W32Time -StartupType Automatic; Start-Service -Name W32Time");
        }

        return Finding.Pass(
            "Windows Time service is running",
            "The Windows Time service (W32Time) is running, so the system clock is being disciplined against a configured " +
            "time source and stays within the tolerance Kerberos, certificate validation, and log correlation depend on.",
            Category);
    }

    /// <summary>
    /// The W32Time <c>Type</c> value selects how time is sourced. "NoSync" disables synchronization
    /// entirely (risky); "NTP" and "NT5DS" are healthy; anything unrecognized is surfaced as Info.
    /// </summary>
    public static Finding AnalyzeSyncType(TimeSyncState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var type = (state.SyncType ?? string.Empty).Trim();

        if (string.Equals(type, "NoSync", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Warning(
                "Time synchronization is disabled (Type = NoSync)",
                "The Windows Time service is configured with Type = NoSync, which turns off external time synchronization " +
                "entirely - the clock free-runs on the hardware oscillator. This is the same end result as a stopped " +
                "service: the clock drifts uncorrected and eventually breaks Kerberos, certificate validation, and log " +
                "correlation.",
                Category,
                remediation: "Set the sync type to NT5DS on domain-joined machines (sync up the domain hierarchy) or NTP on " +
                    "standalone machines, then resync.",
                fixCommand: "w32tm /config /syncfromflags:domhier /update  # or /manualpeerlist for standalone NTP");
        }

        if (string.Equals(type, "NTP", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "NT5DS", StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "AllSync", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Pass(
                $"Time source type is '{type}'",
                $"The Windows Time service sync type is '{type}', a supported configuration that keeps the clock " +
                "disciplined against a real time source rather than letting it free-run.",
                Category);
        }

        return Finding.Info(
            "Time source type is unrecognized or unset",
            $"The Windows Time service sync type is '{(string.IsNullOrEmpty(type) ? "(unset)" : type)}', which is not one of " +
            "the standard values (NTP, NT5DS, AllSync, NoSync). Verify the clock is actually being synchronized with " +
            "'w32tm /query /status' and set an explicit type appropriate for this machine.",
            Category,
            remediation: "Confirm sync status with 'w32tm /query /status' and set Type to NT5DS (domain) or NTP (standalone).");
    }

    /// <summary>
    /// The configured NTP peer list. A domain-joined machine should sync up the domain hierarchy
    /// (NT5DS) rather than an arbitrary public peer; a standalone machine syncing to an
    /// unauthenticated public peer is normal but worth noting.
    /// </summary>
    public static Finding AnalyzeNtpPeer(TimeSyncState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var peer = (state.NtpPeer ?? string.Empty).Trim();

        // Only meaningful when the machine actually uses NTP-style peers.
        var usesManualPeer = string.Equals((state.SyncType ?? string.Empty).Trim(), "NTP", StringComparison.OrdinalIgnoreCase);

        if (usesManualPeer && peer.Length == 0)
        {
            return Finding.Warning(
                "NTP sync selected but no peer is configured",
                "The Windows Time service is set to NTP mode but has no manual peer list configured, so it has no trusted " +
                "source to synchronize against and the clock will drift. An empty peer list under NTP mode is a " +
                "misconfiguration.",
                Category,
                remediation: "Configure a trusted NTP peer, e.g. 'w32tm /config /manualpeerlist:\"time.windows.com,0x9\" /syncfromflags:manual /update'.",
                fixCommand: "w32tm /config /manualpeerlist:\"time.windows.com,0x9\" /syncfromflags:manual /update");
        }

        if (state.DomainJoined && usesManualPeer && peer.Length > 0)
        {
            return Finding.Info(
                "Domain-joined machine syncs to a manual NTP peer",
                $"This machine is domain-joined but is configured to synchronize time from a manual NTP peer ('{peer}') " +
                "rather than the domain hierarchy (NT5DS). Domain members normally inherit time from the domain controllers, " +
                "which are themselves disciplined and authenticated; a manual external peer bypasses that chain of trust and " +
                "makes the clock depend on an unauthenticated source. Confirm this override is intentional.",
                Category,
                remediation: "Unless this override is deliberate, sync from the domain hierarchy: 'w32tm /config /syncfromflags:domhier /update'.");
        }

        return Finding.Pass(
            "Time peer configuration looks consistent",
            "The configured time source is consistent with the machine's role (domain members sync the domain hierarchy; " +
            "standalone machines use a configured NTP peer), so the clock is disciplined against an appropriate source.",
            Category);
    }

    /// <summary>
    /// MaxPosPhaseCorrection / MaxNegPhaseCorrection cap how far a single correction may move the
    /// clock. An unbounded cap (0xFFFFFFFF or an enormous value) lets a rogue/spoofed time source
    /// shift the clock arbitrarily in one step - reviving expired certificates or breaking Kerberos.
    /// </summary>
    public static Finding AnalyzePhaseCorrection(TimeSyncState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        bool posUnbounded = IsUnbounded(state.MaxPosPhaseCorrectionSeconds);
        bool negUnbounded = IsUnbounded(state.MaxNegPhaseCorrectionSeconds);

        if (posUnbounded || negUnbounded)
        {
            var which = (posUnbounded, negUnbounded) switch
            {
                (true, true) => "both the positive and negative",
                (true, false) => "the positive",
                _ => "the negative",
            };

            return Finding.Warning(
                "Clock phase correction is unbounded",
                $"The Windows Time service allows an unbounded {which} phase correction (MaxPosPhaseCorrection / " +
                "MaxNegPhaseCorrection is set to accept any jump). With no cap on how far a single update may move the clock, " +
                "a spoofed or compromised time source can shift the system clock arbitrarily in one step - reviving expired " +
                "certificates, defeating Kerberos ticket-lifetime checks, or scrambling forensic timelines. A bounded " +
                "correction rejects implausible time jumps.",
                Category,
                remediation: "Set a sane cap (e.g. 172800 seconds / 48h) on both MaxPosPhaseCorrection and MaxNegPhaseCorrection " +
                    "so implausible clock jumps are rejected.",
                fixCommand: "w32tm /config /update  # after setting MaxPosPhaseCorrection/MaxNegPhaseCorrection to a bounded value (e.g. 0x2A300)");
        }

        return Finding.Pass(
            "Clock phase correction is bounded",
            "The Windows Time service caps how far a single correction may move the clock (MaxPosPhaseCorrection / " +
            "MaxNegPhaseCorrection are bounded), so an implausible time jump from a spoofed or compromised source is " +
            "rejected instead of silently applied.",
            Category);
    }

    /// <summary>
    /// True when a phase-correction cap should be treated as "no maximum": the literal 0xFFFFFFFF
    /// sentinel, or any value at/above <see cref="EffectivelyUnlimitedSeconds"/>. A negative value
    /// (shouldn't occur) is treated as unbounded defensively.
    /// </summary>
    private static bool IsUnbounded(long seconds)
        => seconds < 0 || seconds == UnlimitedPhaseCorrection || seconds >= EffectivelyUnlimitedSeconds;
}

/// <summary>
/// Raw, collector-supplied Windows time-synchronization state. Populated by the audit module's I/O
/// layer (reading the W32Time service state and the
/// <c>SYSTEM\CurrentControlSet\Services\W32Time</c> configuration registry values) and handed to
/// <see cref="TimeSyncSecurityAnalyzer"/> for a pure decision. Defaults are chosen so an unreadable
/// value never false-positives the dangerous posture: the service is assumed running, the sync type
/// is treated as healthy NT5DS, and phase corrections default to a bounded value.
/// </summary>
public sealed record TimeSyncState
{
    /// <summary>Whether the W32Time service is currently running. Secure default <c>true</c>.</summary>
    public bool ServiceRunning { get; init; } = true;

    /// <summary>The W32Time <c>Type</c> value (NTP / NT5DS / AllSync / NoSync). Defaults to NT5DS (healthy).</summary>
    public string? SyncType { get; init; } = "NT5DS";

    /// <summary>The configured manual NTP peer list (may be empty). Only meaningful under NTP mode.</summary>
    public string? NtpPeer { get; init; }

    /// <summary>Whether this machine is domain-joined (affects whether a manual peer is expected).</summary>
    public bool DomainJoined { get; init; }

    /// <summary>MaxPosPhaseCorrection in seconds. 0xFFFFFFFF or a huge value means unbounded. Defaults to a bounded 48h.</summary>
    public long MaxPosPhaseCorrectionSeconds { get; init; } = 172_800L;

    /// <summary>MaxNegPhaseCorrection in seconds. 0xFFFFFFFF or a huge value means unbounded. Defaults to a bounded 48h.</summary>
    public long MaxNegPhaseCorrectionSeconds { get; init; } = 172_800L;
}
