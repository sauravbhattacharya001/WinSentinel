using System.ServiceProcess;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows time-synchronization security in a live
/// <c>--audit</c> run: whether the Windows Time service (W32Time) is running, how time is sourced
/// (Type = NTP / NT5DS / NoSync), the configured NTP peer relative to the machine's domain role, and
/// whether the clock's phase-correction caps are bounded.
///
/// <para>This is the thin I/O layer for <see cref="TimeSyncSecurityAnalyzer"/>: it owns the reading
/// of the local W32Time service state and the W32Time configuration registry, and delegates every
/// pass/fail decision to the pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions
/// - the same split as <see cref="ExploitMitigationAudit"/> / <see cref="ExploitMitigationAnalyzer"/>).
/// It reads only local machine state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class TimeSyncSecurityAudit : AuditModuleBase
{
    public override string Name => "Time Synchronization Audit";
    public override string Category => TimeSyncSecurityAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows time-synchronization security - the Windows Time service (W32Time) state, the sync " +
        "source type (NTP / NT5DS / NoSync), the NTP peer relative to the machine's domain role, and whether clock " +
        "phase-correction caps are bounded - because accurate time underpins Kerberos auth, certificate validity, and log correlation.";

    private const string ConfigSubKey = @"SYSTEM\CurrentControlSet\Services\W32Time\Config";
    private const string ParametersSubKey = @"SYSTEM\CurrentControlSet\Services\W32Time\Parameters";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in TimeSyncSecurityAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local W32Time service/config state into the pure <see cref="TimeSyncState"/>. The
    /// running-state comes from the "W32Time" service; each config value is a best-effort registry
    /// read whose absence maps to the safer default (see <see cref="TimeSyncState"/>) so a missing
    /// key never false-positives the dangerous posture.
    /// </summary>
    internal static TimeSyncState CollectState()
    {
        bool serviceRunning = IsServiceRunning("W32Time");

        // Type lives under Parameters; the manual peer (NtpServer) also lives under Parameters.
        string? syncType = ReadString(ParametersSubKey, "Type") ?? "NT5DS";
        string? ntpPeer = ReadString(ParametersSubKey, "NtpServer");

        // MaxPos/MaxNegPhaseCorrection are DWORDs under Config; 0xFFFFFFFF => unbounded.
        long maxPos = ReadDwordAsUnsigned(ConfigSubKey, "MaxPosPhaseCorrection", defaultValue: 172_800L);
        long maxNeg = ReadDwordAsUnsigned(ConfigSubKey, "MaxNegPhaseCorrection", defaultValue: 172_800L);

        bool domainJoined = IsDomainJoined();

        return new TimeSyncState
        {
            ServiceRunning = serviceRunning,
            SyncType = syncType,
            NtpPeer = ntpPeer,
            DomainJoined = domainJoined,
            MaxPosPhaseCorrectionSeconds = maxPos,
            MaxNegPhaseCorrectionSeconds = maxNeg,
        };
    }

    /// <summary>Best-effort check of whether a Windows service is currently running.</summary>
    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            // If we cannot read the service (non-Windows / access denied), assume the safe posture
            // (running) so a read failure never false-positives the "stopped" warning.
            return true;
        }
    }

    /// <summary>Best-effort read of whether this machine is joined to an AD domain.</summary>
    private static bool IsDomainJoined()
    {
        try
        {
            var domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            return !string.IsNullOrWhiteSpace(domain);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Best-effort read of a REG_SZ from HKLM, returning <c>null</c> when missing/unreadable.</summary>
    private static string? ReadString(string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(RegistryHive.LocalMachine, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD interpreted as an unsigned 32-bit value (so 0xFFFFFFFF becomes
    /// 4294967295, the "unbounded" sentinel, rather than -1). Returns <paramref name="defaultValue"/>
    /// when the key/value is missing or unreadable.
    /// </summary>
    private static long ReadDwordAsUnsigned(string subKey, string valueName, long defaultValue)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            var raw = key?.GetValue(valueName);
            if (raw is null)
            {
                return defaultValue;
            }

            return raw switch
            {
                int i => unchecked((uint)i),
                long l => l,
                _ => Convert.ToInt64(raw),
            };
        }
        catch
        {
            return defaultValue;
        }
    }
}
