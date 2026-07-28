using System.ServiceProcess;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Remote Management
/// (WinRM / WS-Management) hardening in a live <c>--audit</c> run.
///
/// <para>This is the thin I/O layer for <see cref="WinRmSecurityAnalyzer"/>: it owns
/// the reading of the local WinRM service state and the GPO-managed WinRM policy
/// registry, and delegates every pass/fail decision to the pure, unit-tested
/// analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="SmbSecurityAudit"/> / <see cref="SmbSecurityAnalyzer"/>). It reads only
/// local service/registry state, so it is single-machine and therefore FREE / OSS -
/// nothing multi-machine, nothing license-gated.</para>
///
/// <para>The service running-state is read via <see cref="ServiceController"/> ("WinRM").
/// The auth/transport knobs are read from the WinRM policy keys under
/// <c>SOFTWARE\Policies\Microsoft\Windows\WinRM\{Service,Client}</c>, which is where
/// Group-Policy-managed WinRM configuration is enforced. Unreadable values fall back
/// to the safer default (see <see cref="WinRmState"/>) so a missing key never
/// false-positives a dangerous posture.</para>
/// </summary>
public class WinRmSecurityAudit : AuditModuleBase
{
    public override string Name => "WinRM Remote Management Hardening Audit";
    public override string Category => WinRmSecurityAnalyzer.Category;
    public override string Description =>
        "Checks Windows Remote Management (WS-Man) service and client hardening - " +
        "unencrypted traffic, Basic/Digest auth, channel-binding-token enforcement, " +
        "and wildcard TrustedHosts - against CIS Windows L1.";

    private const string ServicePolicy =
        @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
    private const string ClientPolicy =
        @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in WinRmSecurityAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local WinRM service/client hardening state into the pure
    /// <see cref="WinRmState"/>. The running-state comes from the "WinRM" service;
    /// each policy value is a best-effort registry read whose absence maps to the
    /// safer default so a missing key never false-positives the insecure posture.
    /// </summary>
    internal static WinRmState CollectState()
    {
        bool serviceRunning = IsServiceRunning("WinRM");

        // Policy DWORDs: 1 = allowed/enabled. Absent -> treat as not enabled (safe default).
        bool serviceAllowUnencrypted = ReadDword(ServicePolicy, "AllowUnencryptedTraffic") == 1;
        bool serviceAllowBasic = ReadDword(ServicePolicy, "AllowBasic") == 1;
        bool serviceAllowDigest = ReadDword(ServicePolicy, "AllowDigest") == 1;
        // CbtHardeningLevel policy is stored as a string ("None"/"Relaxed"/"Strict"); null = unset.
        string? serviceCbt = ReadString(ServicePolicy, "CBTHardeningLevelStatus")
                             ?? ReadString(ServicePolicy, "CbtHardeningLevel");

        bool clientAllowUnencrypted = ReadDword(ClientPolicy, "AllowUnencryptedTraffic") == 1;
        bool clientAllowBasic = ReadDword(ClientPolicy, "AllowBasic") == 1;
        bool clientAllowDigest = ReadDword(ClientPolicy, "AllowDigest") == 1;
        string? clientTrustedHosts = ReadString(ClientPolicy, "TrustedHosts");

        return new WinRmState
        {
            ServiceRunning = serviceRunning,
            ServiceAllowUnencrypted = serviceAllowUnencrypted,
            ServiceAllowBasic = serviceAllowBasic,
            ServiceAllowDigest = serviceAllowDigest,
            ServiceCbtHardeningLevel = serviceCbt,
            ClientAllowUnencrypted = clientAllowUnencrypted,
            ClientAllowBasic = clientAllowBasic,
            ClientAllowDigest = clientAllowDigest,
            ClientTrustedHosts = clientTrustedHosts,
        };
    }

    /// <summary>
    /// Best-effort check of whether a Windows service is currently running. A missing
    /// service, or any query error, is treated as "not running" (no inbound listener).
    /// </summary>
    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKLM, returning <paramref name="defaultValue"/>
    /// when the key/value is missing or unreadable.
    /// </summary>
    private static int ReadDword(string subKey, string valueName, int defaultValue = 0)
    {
        try
        {
            return RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine, subKey, valueName, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Best-effort read of a REG_SZ from HKLM, returning <c>null</c> when the key/value
    /// is missing or unreadable (so the analyzer sees an "unset" value).
    /// </summary>
    private static string? ReadString(string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(
                RegistryHive.LocalMachine, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
