using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing single-machine Microsoft Defender <b>Network Protection</b>
/// posture. Network Protection (part of Defender Exploit Guard / attack-surface reduction) extends
/// SmartScreen-style reputation blocking to the whole machine: it inspects outbound connections and
/// blocks processes - not just browsers - from reaching low-reputation domains and IPs (phishing,
/// malware C2, exploit-hosting, scam sites). Without it, a compromised process, a non-browser app,
/// or a script can freely reach an attacker's callback host even when the user's browser would have
/// warned them. It is the single most effective free control against commodity C2 and drive-by
/// payload retrieval, and it is entirely local machine state, so this module is single-machine and
/// therefore FREE / OSS: nothing multi-machine, nothing license-gated.
///
/// <para>Every rule operates on a synthetic <see cref="NetworkProtectionState"/> so it can be unit
/// tested directly, mirroring the established <see cref="TimeSyncSecurityAnalyzer"/> /
/// <see cref="ExploitMitigationAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
///
///   * Defender real-time protection running - Network Protection is a Defender component, so if
///     Defender's real-time engine is off the feature cannot function regardless of its setting.
///   * Network Protection mode - Disabled (0) leaves the machine with no reputation blocking of
///     outbound connections (Warning); Audit (2) only logs would-be blocks without enforcing
///     (Info - it is a tuning stage, not a protective one); Block (1) is the secure posture.
///   * Reputation-based cloud lookups - Network Protection relies on Defender's cloud (MAPS) for
///     up-to-date reputation. With cloud-delivered protection off, block decisions fall back to
///     stale local intel, materially weakening the feature (Info).
/// </summary>
public static class NetworkProtectionAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Network Protection";

    /// <summary>Network Protection is turned off entirely - no outbound reputation blocking.</summary>
    public const int ModeDisabled = 0;

    /// <summary>Network Protection actively blocks connections to low-reputation hosts (secure).</summary>
    public const int ModeBlock = 1;

    /// <summary>Network Protection only logs would-be blocks (audit/tuning) without enforcing.</summary>
    public const int ModeAudit = 2;

    /// <summary>
    /// Evaluate the collected Network Protection state and return one finding per check (a Pass when
    /// the setting is already safe, otherwise Info/Warning). Ordering is stable and deterministic for
    /// diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(NetworkProtectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeRealTimeProtection(state),
            AnalyzeMode(state),
            AnalyzeCloudReputation(state),
        };
    }

    /// <summary>
    /// Network Protection is a Microsoft Defender component. If Defender's real-time protection is
    /// disabled (a third-party AV took over, or it was turned off), Network Protection cannot inspect
    /// or block outbound connections no matter how its own toggle is set.
    /// </summary>
    public static Finding AnalyzeRealTimeProtection(NetworkProtectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.DefenderRealTimeProtectionEnabled)
        {
            return Finding.Warning(
                "Microsoft Defender real-time protection is off, so Network Protection is inert",
                "Network Protection is delivered by the Microsoft Defender real-time engine, which is currently disabled. " +
                "With real-time protection off, Defender is not inspecting outbound connections at all, so processes on this " +
                "machine can reach malware command-and-control, phishing, and exploit-hosting domains with no reputation " +
                "check - even if the Network Protection setting itself is enabled. This is common when a third-party AV has " +
                "taken over; confirm that replacement provides equivalent outbound reputation blocking.",
                Category,
                remediation: "Re-enable Microsoft Defender real-time protection (or verify the third-party AV enforces outbound " +
                    "reputation blocking), then confirm Network Protection is in Block mode.",
                fixCommand: "Set-MpPreference -DisableRealtimeMonitoring $false");
        }

        return Finding.Pass(
            "Microsoft Defender real-time protection is enabled",
            "Microsoft Defender's real-time engine is running, so the Network Protection component is able to inspect " +
            "outbound connections and enforce reputation-based blocking.",
            Category);
    }

    /// <summary>
    /// The Network Protection mode: Disabled (no protection - Warning), Audit (logs but does not
    /// enforce - Info), or Block (the secure enforcing posture - Pass).
    /// </summary>
    public static Finding AnalyzeMode(NetworkProtectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        switch (state.Mode)
        {
            case ModeBlock:
                return Finding.Pass(
                    "Network Protection is enabled in Block mode",
                    "Microsoft Defender Network Protection is set to Block, so any process on this machine that tries to " +
                    "connect to a domain or IP with a known-bad reputation (malware C2, phishing, exploit hosting, scam " +
                    "sites) is stopped - not just in the browser but for every process, including scripts and non-browser " +
                    "apps. This is the secure posture.",
                    Category);

            case ModeAudit:
                return Finding.Info(
                    "Network Protection is in Audit mode (logging only, not blocking)",
                    "Microsoft Defender Network Protection is set to Audit: it records events for connections it would have " +
                    "blocked but does not actually stop them. Audit mode is a tuning stage - useful for measuring impact - " +
                    "but it provides no protection. A process reaching an attacker's callback host is logged and allowed. " +
                    "Move to Block mode once you have confirmed there are no false positives.",
                    Category,
                    remediation: "Switch Network Protection from Audit to Block once impact is validated: " +
                        "'Set-MpPreference -EnableNetworkProtection Enabled'.",
                    fixCommand: "Set-MpPreference -EnableNetworkProtection Enabled");

            case ModeDisabled:
                return Finding.Warning(
                    "Network Protection is disabled",
                    "Microsoft Defender Network Protection is turned off, so no process on this machine has its outbound " +
                    "connections checked against domain/IP reputation. A compromised or malicious process - or a script or " +
                    "non-browser application - can freely reach malware command-and-control, phishing, and exploit-hosting " +
                    "hosts even though the browser might have warned about the same site. Network Protection is the most " +
                    "effective free control against commodity C2 callbacks and drive-by payload retrieval.",
                    Category,
                    remediation: "Enable Network Protection in Block mode: 'Set-MpPreference -EnableNetworkProtection Enabled'.",
                    fixCommand: "Set-MpPreference -EnableNetworkProtection Enabled");

            default:
                return Finding.Info(
                    "Network Protection mode is unrecognized",
                    $"Microsoft Defender Network Protection reports an unrecognized mode value ({state.Mode}). Expected 0 " +
                    "(Disabled), 1 (Block), or 2 (Audit). Verify the current setting with 'Get-MpPreference | Select " +
                    "EnableNetworkProtection' and set it explicitly to Block.",
                    Category,
                    remediation: "Confirm and set Network Protection to Block: 'Set-MpPreference -EnableNetworkProtection Enabled'.");
        }
    }

    /// <summary>
    /// Network Protection block decisions lean on Defender's cloud (MAPS/cloud-delivered protection)
    /// for fresh reputation data. With cloud protection off, the feature falls back to whatever local
    /// intel shipped with the last signature update, materially weakening its coverage of newly
    /// registered attacker infrastructure.
    /// </summary>
    public static Finding AnalyzeCloudReputation(NetworkProtectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // Only relevant when Network Protection is actually doing something (Block or Audit).
        var active = state.Mode == ModeBlock || state.Mode == ModeAudit;
        if (active && !state.CloudProtectionEnabled)
        {
            return Finding.Info(
                "Network Protection is active but cloud-delivered protection is off",
                "Network Protection is enabled, but Microsoft Defender's cloud-delivered protection (MAPS) is disabled. " +
                "Reputation lookups for outbound connections then fall back to the intel bundled with the last signature " +
                "update rather than the live cloud, so freshly registered malware C2 and phishing domains - the ones that " +
                "matter most for a live intrusion - are far more likely to be missed. Cloud-delivered protection sharply " +
                "improves Network Protection's coverage of new attacker infrastructure.",
                Category,
                remediation: "Enable cloud-delivered protection so Network Protection gets live reputation data: " +
                    "'Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples'.",
                fixCommand: "Set-MpPreference -MAPSReporting Advanced");
        }

        return Finding.Pass(
            "Reputation source for Network Protection is healthy",
            "Either Network Protection is not currently enforcing, or Microsoft Defender's cloud-delivered protection is " +
            "enabled - so when Network Protection blocks a connection it is doing so against live reputation data covering " +
            "newly registered attacker infrastructure, not stale local intel.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied Microsoft Defender Network Protection state. Populated by the audit
/// module's I/O layer (reading Defender's <c>Get-MpPreference</c>-equivalent state and the Exploit
/// Guard policy registry) and handed to <see cref="NetworkProtectionAnalyzer"/> for a pure decision.
/// Defaults are chosen so an unreadable value never false-positives the dangerous posture: real-time
/// protection is assumed enabled, the mode defaults to Block, and cloud protection is assumed on.
/// </summary>
public sealed record NetworkProtectionState
{
    /// <summary>Whether Microsoft Defender real-time protection is enabled. Secure default <c>true</c>.</summary>
    public bool DefenderRealTimeProtectionEnabled { get; init; } = true;

    /// <summary>Network Protection mode: 0 Disabled, 1 Block, 2 Audit. Defaults to Block (secure).</summary>
    public int Mode { get; init; } = NetworkProtectionAnalyzer.ModeBlock;

    /// <summary>Whether cloud-delivered protection (MAPS) is enabled. Secure default <c>true</c>.</summary>
    public bool CloudProtectionEnabled { get; init; } = true;
}
