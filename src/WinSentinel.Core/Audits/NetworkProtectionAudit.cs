using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Microsoft Defender <b>Network Protection</b> posture in
/// a live <c>--audit</c> run: whether Defender real-time protection is active, whether Network
/// Protection is Disabled / Audit / Block, and whether cloud-delivered protection is feeding it live
/// reputation data.
///
/// <para>This is the thin I/O layer for <see cref="NetworkProtectionAnalyzer"/>: it owns the reading
/// of local Defender state via <c>Get-MpPreference</c> / <c>Get-MpComputerStatus</c> and delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O, analyzer owns
/// decisions - the same split as <see cref="TimeSyncSecurityAudit"/> /
/// <see cref="TimeSyncSecurityAnalyzer"/>). It reads only local machine state, so it is
/// single-machine and therefore FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class NetworkProtectionAudit : AuditModuleBase
{
    public override string Name => "Network Protection Audit";
    public override string Category => NetworkProtectionAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Microsoft Defender Network Protection - whether outbound connections from any process are " +
        "blocked when they target low-reputation (malware C2, phishing, exploit-hosting) domains and IPs, whether the " +
        "feature is enforcing (Block) or only logging (Audit), and whether Defender real-time and cloud-delivered " +
        "protection are active to back it - the most effective free control against commodity C2 callbacks.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectStateAsync(cancellationToken).ConfigureAwait(false);
        foreach (var finding in NetworkProtectionAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Defender Network Protection state into the pure
    /// <see cref="NetworkProtectionState"/>. Each value is a best-effort <c>Get-MpPreference</c> /
    /// <c>Get-MpComputerStatus</c> read whose absence/unreadability maps to the safer default (see
    /// <see cref="NetworkProtectionState"/>) so a missing value never false-positives the dangerous
    /// posture (e.g. on a machine where a third-party AV replaced Defender).
    /// </summary>
    internal static async Task<NetworkProtectionState> CollectStateAsync(CancellationToken ct)
    {
        // DisableRealtimeMonitoring: True => real-time protection OFF.
        var rtpOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).DisableRealtimeMonitoring", ct).ConfigureAwait(false);
        bool realTimeEnabled = ParseRealTimeEnabled(rtpOutput);

        // EnableNetworkProtection: 0 Disabled, 1 Block, 2 Audit.
        var npOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).EnableNetworkProtection", ct).ConfigureAwait(false);
        int mode = ParseMode(npOutput);

        // MAPSReporting: 0 Disabled, 1 Basic, 2 Advanced => cloud protection on when > 0.
        var mapsOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).MAPSReporting", ct).ConfigureAwait(false);
        bool cloudEnabled = ParseCloudEnabled(mapsOutput);

        return new NetworkProtectionState
        {
            DefenderRealTimeProtectionEnabled = realTimeEnabled,
            Mode = mode,
            CloudProtectionEnabled = cloudEnabled,
        };
    }

    /// <summary>
    /// Map <c>(Get-MpPreference).DisableRealtimeMonitoring</c> to whether real-time protection is on.
    /// Only a literal "True" means disabled; anything else (including an empty/unreadable result on a
    /// non-Defender machine) is treated as enabled so a read failure never false-positives.
    /// </summary>
    internal static bool ParseRealTimeEnabled(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        return !string.Equals(t, "True", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Map <c>(Get-MpPreference).EnableNetworkProtection</c> to a mode value. A parseable 0/1/2 is
    /// used directly; an empty/unparseable result defaults to Block so an unreadable value never
    /// false-positives the "disabled" warning.
    /// </summary>
    internal static int ParseMode(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        if (int.TryParse(t, out var v) && v >= 0 && v <= 2)
        {
            return v;
        }

        return NetworkProtectionAnalyzer.ModeBlock;
    }

    /// <summary>
    /// Map <c>(Get-MpPreference).MAPSReporting</c> to whether cloud-delivered protection is on
    /// (reporting level &gt; 0). An empty/unparseable result defaults to enabled so a read failure
    /// never false-positives.
    /// </summary>
    internal static bool ParseCloudEnabled(string? output)
    {
        var t = (output ?? string.Empty).Trim();
        if (int.TryParse(t, out var v))
        {
            return v > 0;
        }

        return true;
    }
}
