using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Delivery Optimization (DO)
/// download-source posture in a live <c>--audit</c> run: whether the machine is
/// configured to exchange update / Store content with peers, and in particular
/// whether it peers across the public Internet (DODownloadMode=3). Internet peering
/// turns the machine into a content peer on the open Internet - an inbound peer
/// surface and data-egress path most standalone machines do not want - so this is
/// meaningful single-machine hardening.
///
/// <para>This is the thin I/O layer for <see cref="DeliveryOptimizationAnalyzer"/>:
/// it reads the HKLM policy and unmanaged config registry values and delegates every
/// pass/fail decision to the pure, unit-tested analyzer (collector owns I/O, analyzer
/// owns decisions - the same split as <see cref="SmartScreenAudit"/> /
/// <see cref="SmartScreenAnalyzer"/>). It reads only local machine state, so it is
/// single-machine and therefore FREE / OSS - nothing multi-machine, nothing
/// license-gated.</para>
/// </summary>
public class DeliveryOptimizationAudit : AuditModuleBase
{
    public override string Name => "Delivery Optimization Audit";
    public override string Category => DeliveryOptimizationAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Delivery Optimization download-source posture - whether the machine " +
        "peers update/Store content with other machines and, critically, whether it peers across the public " +
        "Internet (DODownloadMode=3) - to avoid turning the machine into an Internet-facing content peer.";

    private const string PolicySubKey = @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
    private const string ConfigSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in DeliveryOptimizationAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Delivery Optimization state into the pure
    /// <see cref="DeliveryOptimizationState"/>. Both values are best-effort registry
    /// reads whose absence maps to null so the analyzer treats them as the Windows
    /// default (LAN peering) rather than a false full-pass. The policy value (HKLM
    /// Policies) takes precedence over the unmanaged config value in the analyzer.
    /// </summary>
    internal static DeliveryOptimizationState CollectState()
    {
        return new DeliveryOptimizationState
        {
            PolicyDownloadMode = ReadDword(RegistryHive.LocalMachine, PolicySubKey, "DODownloadMode"),
            ConfigDownloadMode = ReadDword(RegistryHive.LocalMachine, ConfigSubKey, "DODownloadMode"),
        };
    }

    /// <summary>
    /// Best-effort read of a DWORD; null when missing/unreadable. Tolerates REG_SZ
    /// numeric values (DODownloadMode is occasionally written as a string).
    /// </summary>
    private static int? ReadDword(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }
}
